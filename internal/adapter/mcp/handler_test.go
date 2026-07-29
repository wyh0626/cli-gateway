package mcpadapter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
	runtimecfg "github.com/wyh0626/cli-gateway/internal/runtime"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type staticVerifier struct{}

func (staticVerifier) Verify(context.Context, string) (model.Principal, error) {
	return model.Principal{
		Subject: "alice", Issuer: "https://issuer.example", ExpiresAt: time.Now().Add(time.Hour),
		Scopes: map[string]struct{}{"demo:read": {}, "demo:write": {}}, Invoker: model.InvokerHuman,
	}, nil
}

type resultInvoker struct{}

func (resultInvoker) Invoke(_ context.Context, invocation model.Invocation) (*model.Execution, error) {
	return &model.Execution{
		Status: http.StatusOK, ContentType: "application/json",
		Body: io.NopCloser(strings.NewReader(`{"command":"` + invocation.Command.Key + `"}`)),
	}, nil
}

type bearerTransport struct {
	base http.RoundTripper
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.Header = request.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer test-token")
	return t.base.RoundTrip(cloned)
}

func TestHandlerListsFilteredToolsAndCallsSharedInvoker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(mcpManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeManager, err := runtimecfg.NewManager(path, time.Second, func(_ *manifest.Snapshot) (runtimecfg.Components, error) {
		return runtimecfg.Components{Invoker: resultInvoker{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(runtimeManager, staticVerifier{}, "https://tools.example.com/.well-known/oauth-protected-resource/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := &http.Client{Transport: bearerTransport{base: http.DefaultTransport}}
	changed := make(chan struct{}, 4)
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "v1"}, &sdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *sdk.ToolListChangedRequest) {
			changed <- struct{}{}
		},
	})
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint: server.URL, HTTPClient: httpClient, MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "demo_get" {
		t.Fatalf("tools = %#v", tools.Tools)
	}
	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "demo_get", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError || len(result.Content) != 1 {
		t.Fatalf("result = %#v", result)
	}
	text, ok := result.Content[0].(*sdk.TextContent)
	if !ok || !strings.Contains(text.Text, "demo.get") {
		t.Fatalf("content = %#v", result.Content)
	}

	updated := strings.Replace(mcpManifest, "path: [get]", "path: [list]", 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtimeManager.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	select {
	case <-changed:
	case <-time.After(3 * time.Second):
		t.Fatal("tools/list_changed notification was not received")
	}
	tools, err = session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() after reload error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "demo_list" {
		t.Fatalf("tools after reload = %#v", tools.Tools)
	}
}

const mcpManifest = `version: 1
server:
  listen: ":8080"
  public_url: https://tools.example.com
  environment: development
auth:
  mode: trusted-header
  issuer: https://issuer.example
  trusted_jwks: https://issuer.example/jwks
  audience: cli-gateway
cli:
  name: cg
policy:
  ai_max_risk: read
audit: {}
domains:
  - name: demo
    upstream: https://api.example.com
    downstream_auth:
      mode: signed-identity
      identity_audience: demo-api
    commands:
      - path: [get]
        method: GET
        endpoint: /v1/items
        risk: read
      - path: [put]
        method: POST
        endpoint: /v1/items
        risk: write
`
