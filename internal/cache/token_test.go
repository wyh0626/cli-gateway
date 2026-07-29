package cache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenCacheCoalescesConcurrentLoads(t *testing.T) {
	t.Parallel()
	cache, err := NewTokenCache([]byte(strings.Repeat("k", 32)), 10, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := cache.Key("issuer", "alice", "inventory-api", "read")
	var loads atomic.Int32
	start := make(chan struct{})
	loader := func(context.Context) (Token, bool, error) {
		loads.Add(1)
		<-start
		return Token{AccessToken: "downstream", ExpiresAt: time.Now().Add(time.Hour)}, false, nil
	}

	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	errorsFound := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			token, _, loadErr := cache.GetOrLoad(context.Background(), key, loader)
			if loadErr != nil {
				errorsFound <- loadErr
				return
			}
			if token.AccessToken != "downstream" {
				errorsFound <- errors.New("unexpected token")
			}
		}()
	}
	for loads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for found := range errorsFound {
		t.Error(found)
	}
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", loads.Load())
	}
	if strings.Contains(key, "alice") || strings.Contains(key, "inventory") {
		t.Fatalf("cache key exposes source material: %q", key)
	}
}

func TestTokenCacheNegativeAndStaleFallback(t *testing.T) {
	t.Parallel()
	cache, err := NewTokenCache([]byte(strings.Repeat("n", 32)), 2, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cache.now = func() time.Time { return now }
	key := cache.Key("a")
	token, result, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (Token, bool, error) {
		return Token{AccessToken: "valid", ExpiresAt: now.Add(2 * time.Hour)}, false, nil
	})
	if err != nil || result != ResultMiss || token.AccessToken != "valid" {
		t.Fatalf("initial = %#v, %s, %v", token, result, err)
	}
	now = now.Add(70 * time.Minute)
	token, result, err = cache.GetOrLoad(context.Background(), key, func(context.Context) (Token, bool, error) {
		return Token{}, true, errors.New("temporarily unavailable")
	})
	if err != nil || result != ResultStale || token.AccessToken != "valid" {
		t.Fatalf("stale = %#v, %s, %v", token, result, err)
	}

	emptyKey := cache.Key("b")
	_, result, err = cache.GetOrLoad(context.Background(), emptyKey, func(context.Context) (Token, bool, error) {
		return Token{}, true, errors.New("temporarily unavailable")
	})
	if err == nil {
		t.Fatal("transient error was hidden without stale token")
	}
	_, result, err = cache.GetOrLoad(context.Background(), emptyKey, func(context.Context) (Token, bool, error) {
		t.Fatal("negative cache invoked loader")
		return Token{}, false, nil
	})
	if err == nil || result != ResultNegative {
		t.Fatalf("negative = %s, %v", result, err)
	}
}
