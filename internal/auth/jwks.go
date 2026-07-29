package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/upstream"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const maxJWKSBytes = 1 << 20

// JWKSOptions controls refresh and failure windows.
type JWKSOptions struct {
	RefreshInterval time.Duration
	PreviousOverlap time.Duration
	StaleIfError    time.Duration
}

type keySnapshot struct {
	current       jwk.Set
	withPrevious  jwk.Set
	previousUntil time.Time
	fetchedAt     time.Time
}

// JWKSManager owns a cache-aware, refreshable remote key set.
type JWKSManager struct {
	url             string
	client          *http.Client
	refreshInterval time.Duration
	previousOverlap time.Duration
	staleIfError    time.Duration

	current         atomic.Pointer[keySnapshot]
	mu              sync.Mutex
	etag            string
	modified        string
	lastAttempt     time.Time
	missingAttempts map[string]time.Time
}

// NewJWKSManager constructs a manager without performing network I/O.
func NewJWKSManager(url string, allowLocal bool, options JWKSOptions) (*JWKSManager, error) {
	return NewJWKSManagerWithTLS(url, allowLocal, options, model.TLSConfig{})
}

// NewJWKSManagerWithTLS constructs a manager with private-CA or mTLS trust.
func NewJWKSManagerWithTLS(url string, allowLocal bool, options JWKSOptions, tlsConfig model.TLSConfig) (*JWKSManager, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("JWKS URL is required")
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = 5 * time.Minute
	}
	if options.PreviousOverlap <= 0 {
		options.PreviousOverlap = 15 * time.Minute
	}
	if options.StaleIfError <= 0 {
		options.StaleIfError = 24 * time.Hour
	}
	client, err := upstream.NewClientWithTLS(10*time.Second, allowLocal, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize JWKS transport: %w", err)
	}
	return &JWKSManager{
		url: url, client: client,
		refreshInterval: options.RefreshInterval, previousOverlap: options.PreviousOverlap,
		staleIfError: options.StaleIfError, missingAttempts: make(map[string]time.Time),
	}, nil
}

// Current returns the current keys and, during rotation overlap, the previous
// keys. A set older than stale-if-error is not returned.
func (m *JWKSManager) Current() jwk.Set {
	snapshot := m.current.Load()
	if snapshot == nil || time.Since(snapshot.fetchedAt) > m.staleIfError {
		return nil
	}
	if time.Now().Before(snapshot.previousUntil) {
		return snapshot.withPrevious
	}
	return snapshot.current
}

// Refresh fetches and atomically publishes a complete JWKS. Calls within one
// second are coalesced to bound unknown-kid refresh amplification.
func (m *JWKSManager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastAttempt.IsZero() && time.Since(m.lastAttempt) < time.Second {
		if m.Current() != nil {
			return nil
		}
	}
	return m.refreshLocked(ctx)
}

// RefreshUnknownKey performs a double-check under the refresh lock and
// throttles repeated misses for the same attacker-controlled kid.
func (m *JWKSManager) RefreshUnknownKey(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if containsKeyID(m.Current(), keyID) {
		return nil
	}
	if attempted := m.missingAttempts[keyID]; !attempted.IsZero() && time.Since(attempted) < time.Minute {
		return nil
	}
	if len(m.missingAttempts) > 1024 {
		m.missingAttempts = make(map[string]time.Time)
	}
	m.missingAttempts[keyID] = time.Now()
	return m.refreshLocked(ctx)
}

func (m *JWKSManager) refreshLocked(ctx context.Context) error {
	m.lastAttempt = time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if m.etag != "" {
		request.Header.Set("If-None-Match", m.etag)
	}
	if m.modified != "" {
		request.Header.Set("If-Modified-Since", m.modified)
	}
	response, err := m.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		previous := m.current.Load()
		if previous == nil {
			return errors.New("JWKS returned 304 without a cached key set")
		}
		copySnapshot := *previous
		copySnapshot.fetchedAt = time.Now()
		m.current.Store(&copySnapshot)
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("JWKS endpoint returned status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxJWKSBytes {
		return errors.New("JWKS response exceeds 1 MiB")
	}
	keys, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	if keys.Len() == 0 {
		return errors.New("trusted JWKS contains no keys")
	}
	if err := validateKeyIDs(keys); err != nil {
		return err
	}

	now := time.Now()
	combined := copyKeySet(keys)
	previous := m.current.Load()
	if previous != nil {
		for index := 0; index < previous.current.Len(); index++ {
			key, ok := previous.current.Key(index)
			if ok && !containsKeyID(combined, key.KeyID()) {
				_ = combined.AddKey(key)
			}
		}
	}
	m.current.Store(&keySnapshot{
		current: keys, withPrevious: combined, previousUntil: now.Add(m.previousOverlap), fetchedAt: now,
	})
	m.etag = response.Header.Get("ETag")
	m.modified = response.Header.Get("Last-Modified")
	if maxAge := cacheMaxAge(response.Header.Get("Cache-Control")); maxAge > 0 {
		m.refreshInterval = maxAge
	}
	return nil
}

// Start refreshes in the background until ctx is cancelled.
func (m *JWKSManager) Start(ctx context.Context) {
	go func() {
		for {
			interval := m.refreshInterval
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				refreshContext, cancel := context.WithTimeout(ctx, 10*time.Second)
				_ = m.Refresh(refreshContext)
				cancel()
			}
		}
	}()
}

func validateKeyIDs(keys jwk.Set) error {
	seen := make(map[string]struct{}, keys.Len())
	for index := 0; index < keys.Len(); index++ {
		key, ok := keys.Key(index)
		if !ok || key.KeyID() == "" {
			return errors.New("every JWKS key must have a kid")
		}
		if _, exists := seen[key.KeyID()]; exists {
			return fmt.Errorf("JWKS contains duplicate kid %q", key.KeyID())
		}
		seen[key.KeyID()] = struct{}{}
	}
	return nil
}

func copyKeySet(source jwk.Set) jwk.Set {
	result := jwk.NewSet()
	for index := 0; index < source.Len(); index++ {
		key, ok := source.Key(index)
		if ok {
			_ = result.AddKey(key)
		}
	}
	return result
}

func cacheMaxAge(value string) time.Duration {
	for _, directive := range strings.Split(value, ",") {
		name, raw, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found || !strings.EqualFold(name, "max-age") {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
		if err == nil && seconds > 0 && seconds <= int64((24*time.Hour)/time.Second) {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}
