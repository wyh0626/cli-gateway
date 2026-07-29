// Package cache contains bounded, security-aware runtime caches.
package cache

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// Result describes how a token was obtained without exposing its value.
type Result string

const (
	ResultHit      Result = "hit"
	ResultMiss     Result = "miss"
	ResultWaiter   Result = "waiter"
	ResultStale    Result = "stale"
	ResultNegative Result = "negative"
)

// Token is a cached bearer token and its hard expiry.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

type entry struct {
	key           string
	token         Token
	serveUntil    time.Time
	negativeUntil time.Time
	negativeErr   error
	element       *list.Element
}

type call struct {
	done      chan struct{}
	token     Token
	result    Result
	err       error
	transient bool
}

// Loader fetches one token. transient must be true only for sanitized timeout,
// 429, or 5xx failures that are safe to negative-cache briefly.
type Loader func(context.Context) (token Token, transient bool, err error)

// TokenCache is a bounded LRU cache with per-key request coalescing.
type TokenCache struct {
	mu          sync.Mutex
	key         []byte
	capacity    int
	refreshSkew time.Duration
	negativeTTL time.Duration
	now         func() time.Time
	entries     map[string]*entry
	lru         *list.List
	flights     map[string]*call
}

// NewTokenCache constructs an in-process credential cache.
func NewTokenCache(key []byte, capacity int, refreshSkew, negativeTTL time.Duration) (*TokenCache, error) {
	if len(key) < 32 {
		return nil, errors.New("token cache HMAC key must be at least 32 bytes")
	}
	if capacity <= 0 {
		return nil, errors.New("token cache capacity must be positive")
	}
	if refreshSkew < 0 || negativeTTL < 0 {
		return nil, errors.New("token cache durations must not be negative")
	}
	return &TokenCache{
		key: append([]byte(nil), key...), capacity: capacity, refreshSkew: refreshSkew,
		negativeTTL: negativeTTL, now: time.Now, entries: make(map[string]*entry),
		lru: list.New(), flights: make(map[string]*call),
	}, nil
}

// Key returns an opaque HMAC identifier. Empty and ambiguous parts are
// length-separated before hashing.
func (c *TokenCache) Key(parts ...string) string {
	mac := hmac.New(sha256.New, c.key)
	for _, part := range parts {
		_, _ = mac.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
		_, _ = mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// GetOrLoad returns a valid token or invokes loader once for all concurrent
// callers of the same opaque key.
func (c *TokenCache) GetOrLoad(ctx context.Context, key string, loader Loader) (Token, Result, error) {
	if strings.TrimSpace(key) == "" || loader == nil {
		return Token{}, ResultMiss, errors.New("cache key and loader are required")
	}
	now := c.now()
	c.mu.Lock()
	stale, found, result, err := c.lookupLocked(key, now)
	if found && result == ResultHit {
		c.mu.Unlock()
		return stale, result, err
	}
	if found && result == ResultNegative {
		c.mu.Unlock()
		return Token{}, result, err
	}
	if active := c.flights[key]; active != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return Token{}, ResultWaiter, ctx.Err()
		case <-active.done:
			return active.token, ResultWaiter, active.err
		}
	}
	active := &call{done: make(chan struct{})}
	c.flights[key] = active
	c.mu.Unlock()

	token, transient, loadErr := loader(ctx)
	if loadErr == nil {
		if token.AccessToken == "" || !token.ExpiresAt.After(c.now()) {
			loadErr = errors.New("credential provider returned an empty or expired token")
			transient = false
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.flights, key)
	active.transient = transient
	if loadErr == nil {
		c.storeTokenLocked(key, token)
		active.token = token
		active.result = ResultMiss
	} else if transient && stale.AccessToken != "" && stale.ExpiresAt.After(c.now()) {
		active.token = stale
		active.result = ResultStale
	} else {
		active.err = loadErr
		if transient && c.negativeTTL > 0 {
			c.storeNegativeLocked(key, loadErr)
		}
	}
	close(active.done)
	return active.token, active.result, active.err
}

func (c *TokenCache) lookupLocked(key string, now time.Time) (Token, bool, Result, error) {
	current := c.entries[key]
	if current == nil {
		return Token{}, false, ResultMiss, nil
	}
	c.lru.MoveToFront(current.element)
	if current.negativeErr != nil {
		if now.Before(current.negativeUntil) {
			return Token{}, true, ResultNegative, current.negativeErr
		}
		c.removeLocked(current)
		return Token{}, false, ResultMiss, nil
	}
	if !now.Before(current.token.ExpiresAt) {
		c.removeLocked(current)
		return Token{}, false, ResultMiss, nil
	}
	if now.Before(current.serveUntil) {
		return current.token, true, ResultHit, nil
	}
	return current.token, true, ResultStale, nil
}

func (c *TokenCache) storeTokenLocked(key string, token Token) {
	c.removeKeyLocked(key)
	serveUntil := token.ExpiresAt.Add(-c.refreshSkew)
	now := c.now()
	if serveUntil.Before(now) {
		serveUntil = now
	}
	current := &entry{key: key, token: token, serveUntil: serveUntil}
	current.element = c.lru.PushFront(current)
	c.entries[key] = current
	c.evictLocked()
}

func (c *TokenCache) storeNegativeLocked(key string, err error) {
	c.removeKeyLocked(key)
	current := &entry{key: key, negativeErr: err, negativeUntil: c.now().Add(c.negativeTTL)}
	current.element = c.lru.PushFront(current)
	c.entries[key] = current
	c.evictLocked()
}

func (c *TokenCache) evictLocked() {
	for len(c.entries) > c.capacity {
		element := c.lru.Back()
		if element == nil {
			return
		}
		c.removeLocked(element.Value.(*entry))
	}
}

func (c *TokenCache) removeKeyLocked(key string) {
	if current := c.entries[key]; current != nil {
		c.removeLocked(current)
	}
}

func (c *TokenCache) removeLocked(current *entry) {
	delete(c.entries, current.key)
	c.lru.Remove(current.element)
}

// Invalidate removes one opaque cache key.
func (c *TokenCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeKeyLocked(key)
}

// Flush drops all cached values. In-flight loads complete for their callers but
// are not retained if a new generation owns a different cache.
func (c *TokenCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*entry)
	c.lru.Init()
}
