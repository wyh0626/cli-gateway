// Package limiter provides generation-scoped admission control.
package limiter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

const maxRateBuckets = 10_000

type domainLimit struct {
	slots chan struct{}
	rate  float64
	burst float64
}

type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// Manager separates concurrency admission from request-rate budgeting.
type Manager struct {
	global       chan struct{}
	domains      map[string]domainLimit
	queueTimeout time.Duration
	mu           sync.Mutex
	buckets      map[string]*bucket
	now          func() time.Time
}

// NewManager builds bounded admission state for one runtime generation.
func NewManager(snapshot *manifest.Snapshot) (*Manager, error) {
	manager := &Manager{
		global: make(chan struct{}, snapshot.GlobalConcurrency), domains: make(map[string]domainLimit),
		queueTimeout: snapshot.QueueTimeout, buckets: make(map[string]*bucket), now: time.Now,
	}
	for _, key := range snapshot.CommandKeys {
		command := snapshot.Commands[key]
		if _, exists := manager.domains[command.Domain]; exists {
			continue
		}
		manager.domains[command.Domain] = domainLimit{
			slots: make(chan struct{}, command.DomainConcurrency),
			rate:  command.RequestsPerSecond, burst: float64(command.RateBurst),
		}
	}
	return manager, nil
}

// Acquire returns a release function that must remain held until the execution
// body closes.
func (m *Manager) Acquire(ctx context.Context, invocation model.Invocation) (func(), error) {
	domain := m.domains[invocation.Command.Domain]
	if domain.slots == nil {
		return nil, &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "domain admission policy is unavailable"}
	}
	if domain.rate > 0 && !m.takeRate(invocation, domain) {
		return nil, &httpx.APIError{Status: http.StatusTooManyRequests, Code: "E_RATE_LIMITED", Message: "request rate limit exceeded", RetryAfter: time.Second}
	}
	queueContext, cancel := context.WithTimeout(ctx, m.queueTimeout)
	defer cancel()
	select {
	case m.global <- struct{}{}:
	case <-queueContext.Done():
		return nil, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_OVERLOADED", Message: "gateway concurrency limit exceeded", RetryAfter: time.Second}
	}
	select {
	case domain.slots <- struct{}{}:
	case <-queueContext.Done():
		<-m.global
		return nil, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_OVERLOADED", Message: "domain concurrency limit exceeded", RetryAfter: time.Second}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-domain.slots
			<-m.global
		})
	}, nil
}

func (m *Manager) takeRate(invocation model.Invocation, limit domainLimit) bool {
	digest := sha256.Sum256([]byte(
		invocation.Principal.Issuer + "\x00" + invocation.Principal.Tenant + "\x00" +
			invocation.Principal.Subject + "\x00" + invocation.Principal.ClientID + "\x00" +
			invocation.Command.Domain,
	))
	key := hex.EncodeToString(digest[:])
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.buckets[key]
	if current == nil {
		if len(m.buckets) >= maxRateBuckets {
			for candidate, existing := range m.buckets {
				if now.Sub(existing.lastSeen) > 10*time.Minute {
					delete(m.buckets, candidate)
				}
			}
			if len(m.buckets) >= maxRateBuckets {
				return false
			}
		}
		current = &bucket{tokens: limit.burst, last: now}
		m.buckets[key] = current
	}
	elapsed := now.Sub(current.last).Seconds()
	current.tokens += elapsed * limit.rate
	if current.tokens > limit.burst {
		current.tokens = limit.burst
	}
	current.last = now
	current.lastSeen = now
	if current.tokens < 1 {
		return false
	}
	current.tokens--
	return true
}
