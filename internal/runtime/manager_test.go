package runtime

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

type noopInvoker struct{}

func (noopInvoker) Invoke(context.Context, model.Invocation) (*model.Execution, error) {
	return &model.Execution{Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestReloadDrainsPreviousGeneration(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(runtimeManifest("read")), 0o600); err != nil {
		t.Fatal(err)
	}
	closed := make(chan model.Risk, 2)
	manager, err := NewManager(path, time.Second, func(snapshot *manifest.Snapshot) (Components, error) {
		risk := snapshot.AIMaxRisk
		return Components{Invoker: noopInvoker{}, Close: func() error {
			closed <- risk
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	lease, ok := manager.Acquire()
	if !ok {
		t.Fatal("Acquire() failed")
	}
	if lease.Generation.ID != 1 {
		t.Fatalf("generation ID = %d", lease.Generation.ID)
	}
	if err := os.WriteFile(path, []byte(runtimeManifest("write")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if current := manager.Current(); current == nil || current.ID != 2 {
		t.Fatalf("current generation = %#v", current)
	}
	select {
	case risk := <-closed:
		t.Fatalf("old generation closed while leased: %s", risk)
	case <-time.After(25 * time.Millisecond):
	}
	_ = lease.Close()
	select {
	case risk := <-closed:
		if risk != model.RiskRead {
			t.Fatalf("closed risk = %s", risk)
		}
	case <-time.After(time.Second):
		t.Fatal("old generation did not close after release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, ok := manager.Acquire(); ok {
		t.Fatal("Acquire() succeeded after Close")
	}
}

func runtimeManifest(maxRisk string) string {
	return `version: 1
server:
  listen: ":8080"
  public_url: https://tools.example.com
  environment: development
auth:
  mode: trusted-header
  issuer: https://auth.example.com
  trusted_jwks: https://auth.example.com/jwks.json
  audience: cli-gateway
cli:
  name: cg
policy:
  ai_max_risk: ` + maxRisk + `
audit: {}
domains:
  - name: demo
    upstream: https://api.example.com
    downstream_auth:
      mode: signed-identity
      identity_audience: demo-api
    commands:
      - path: [list]
        method: GET
        endpoint: /v1/items
        risk: read
`
}
