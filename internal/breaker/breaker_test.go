package breaker

import (
	"testing"
	"time"
)

func TestBreakerOpenAndHalfOpen(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	breaker := New(2, time.Minute)
	breaker.now = func() time.Time { return now }
	if allowed, _ := breaker.Allow(); !allowed {
		t.Fatal("initial request was rejected")
	}
	breaker.Failure()
	if allowed, _ := breaker.Allow(); !allowed {
		t.Fatal("request before threshold was rejected")
	}
	breaker.Failure()
	if allowed, retry := breaker.Allow(); allowed || retry != time.Minute {
		t.Fatalf("open breaker result = %v, %s", allowed, retry)
	}
	now = now.Add(time.Minute)
	if allowed, _ := breaker.Allow(); !allowed {
		t.Fatal("half-open probe was rejected")
	}
	if allowed, _ := breaker.Allow(); allowed {
		t.Fatal("second half-open probe was admitted")
	}
	breaker.Success()
	if allowed, _ := breaker.Allow(); !allowed || breaker.Open() {
		t.Fatal("successful probe did not close breaker")
	}
}
