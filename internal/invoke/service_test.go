package invoke

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

type staticSigner struct{}

func (staticSigner) Sign(model.Invocation) (string, error) { return "signed-identity", nil }

func TestServiceInvoke(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/items/a%2Fb" && request.URL.EscapedPath() != "/v1/items/a%2Fb" {
			t.Errorf("upstream path = %q escaped=%q", request.URL.Path, request.URL.EscapedPath())
		}
		if request.URL.Query().Get("verbose") != "true" {
			t.Errorf("verbose query = %q", request.URL.Query().Get("verbose"))
		}
		if request.Header.Get("X-Cli-Gateway-Identity") != "signed-identity" {
			t.Errorf("identity header = %q", request.Header.Get("X-Cli-Gateway-Identity"))
		}
		if request.Header.Get("User-Agent") != "cli-gateway/upstream" {
			t.Errorf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	upstreamURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	command := &model.CompiledCommand{
		Key: "demo.item.get", Method: http.MethodGet, Upstream: upstreamURL,
		EndpointSegments: []string{"v1", "items", "{id}"}, Risk: model.RiskRead,
		Timeout: time.Second, DownstreamAuth: model.DownstreamSignedIdentity, IdentityAudience: "demo-api", AllowLocal: true,
		Flags: []model.CompiledFlag{
			{Name: "id", Type: model.FlagString, Location: model.FlagInPath, Required: true},
			{Name: "verbose", Type: model.FlagBool, Location: model.FlagInQuery, QueryName: "verbose"},
		},
	}
	service := NewService(staticSigner{})
	result, err := service.Invoke(context.Background(), model.Invocation{
		Principal: model.Principal{Subject: "alice", Scopes: map[string]struct{}{"demo:read": {}}},
		Command:   command, Args: map[string]any{"id": "a/b", "verbose": true}, Invoker: model.InvokerHuman,
		AIMaxRisk: model.RiskWrite, TraceID: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if result.Status != http.StatusOK {
		t.Fatalf("result = %#v", result)
	}
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read execution: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
}
