package mcpadapter

import (
	"bytes"
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
	assertStatelessLifecycle(t, httpClient, server.URL)
	assertLegacySessionLifecycle(t, httpClient, server.URL)

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
	if got := session.InitializeResult().ProtocolVersion; got != statelessProtocol {
		t.Fatalf("negotiated protocol = %q, want %q", got, statelessProtocol)
	}

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "demo_get" {
		t.Fatalf("tools = %#v", tools.Tools)
	}
	if tools.CacheScope != "private" {
		t.Fatalf("tools cache scope = %q, want private", tools.CacheScope)
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

func assertStatelessLifecycle(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"stateless-client","version":"v1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(discover))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(protocolVersionHeader, statelessProtocol)
	request.Header.Set("Mcp-Method", "server/discover")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(sessionHeader) != "" {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("stateless discover status = %d, session = %q, body = %s", response.StatusCode, response.Header.Get(sessionHeader), body)
	}
	response.Body.Close()

	request, err = http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(protocolVersionHeader, statelessProtocol)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != http.MethodPost {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("stateless delete status = %d, allow = %q, body = %s", response.StatusCode, response.Header.Get("Allow"), body)
	}
	response.Body.Close()
}

func assertLegacySessionLifecycle(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy-client","version":"v1"}}}`
	response := legacyRequest(t, client, endpoint, http.MethodPost, "", initialize)
	sessionID := response.Header.Get(sessionHeader)
	if response.StatusCode != http.StatusOK || sessionID == "" {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("legacy initialize status = %d, session = %q, body = %s", response.StatusCode, sessionID, body)
	}
	response.Body.Close()

	response = legacyRequest(t, client, endpoint, http.MethodPost, sessionID, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("legacy initialized status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()

	response = legacyRequest(t, client, endpoint, http.MethodPost, sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("legacy tools/list status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()

	response = legacyRequest(t, client, endpoint, http.MethodDelete, sessionID, "")
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("legacy delete status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()
}

func legacyRequest(t *testing.T, client *http.Client, endpoint, method, sessionID, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(protocolVersionHeader, "2025-11-25")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
	}
	if sessionID != "" {
		request.Header.Set(sessionHeader, sessionID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
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
