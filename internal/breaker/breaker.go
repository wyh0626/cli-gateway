// Package breaker provides a small, dependency-local circuit breaker. A
// breaker instance must be scoped to exactly one upstream dependency.
package breaker

import (
	"sync"
	"time"
)

// Breaker opens after a consecutive failure threshold, rejects calls for a
// cooldown, and then permits one half-open probe.
type Breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
	probing   bool
	now       func() time.Time
}

// New constructs a circuit breaker.
func New(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

// Allow admits a normal request or exactly one half-open probe.
func (b *Breaker) Allow() (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.openUntil.IsZero() {
		return true, 0
	}
	if now.Before(b.openUntil) {
		return false, b.openUntil.Sub(now)
	}
	if b.probing {
		return false, b.cooldown
	}
	b.probing = true
	return true, 0
}

// Success closes the breaker and clears the consecutive failure count.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
	b.probing = false
}

// Ignore releases a half-open probe when no dependency request was made.
func (b *Breaker) Ignore() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
}

// Failure records a dependency failure and opens or re-opens when required.
func (b *Breaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = b.now().Add(b.cooldown)
	}
}

// Open reports whether calls are currently rejected.
func (b *Breaker) Open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.openUntil.IsZero() && b.now().Before(b.openUntil)
}
