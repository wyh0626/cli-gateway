package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestManagerConcurrencyAndRate(t *testing.T) {
	t.Parallel()
	command := &model.CompiledCommand{
		Domain: "demo", DomainConcurrency: 1, RequestsPerSecond: 1, RateBurst: 3,
	}
	snapshot := &manifest.Snapshot{
		GlobalConcurrency: 1, QueueTimeout: 10 * time.Millisecond,
		CommandKeys: []string{"demo.get"}, Commands: map[string]*model.CompiledCommand{"demo.get": command},
	}
	manager, err := NewManager(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	invocation := model.Invocation{
		Principal: model.Principal{Subject: "alice"}, Command: command,
	}
	release, err := manager.Acquire(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Acquire(context.Background(), invocation)
	var apiErr *httpx.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "E_OVERLOADED" {
		t.Fatalf("concurrency error = %v", err)
	}
	release()
	secondRelease, err := manager.Acquire(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	secondRelease()
	_, err = manager.Acquire(context.Background(), invocation)
	if !errors.As(err, &apiErr) || apiErr.Code != "E_RATE_LIMITED" {
		t.Fatalf("rate error = %v", err)
	}
}
