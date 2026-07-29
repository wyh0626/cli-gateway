package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManifestAndExecute(t *testing.T) {
	t.Parallel()
	var executeCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("X-Cli-Gateway-Invoker"); got != "ai" {
			t.Errorf("X-Cli-Gateway-Invoker = %q", got)
		}
		if len(request.Header.Get("X-Cli-Gateway-Trace-Id")) != 32 {
			t.Errorf("trace ID = %q", request.Header.Get("X-Cli-Gateway-Trace-Id"))
		}
		switch request.URL.Path {
		case "/manifest":
			if request.Header.Get("If-None-Match") == `"abc"` {
				writer.Header().Set("ETag", `"abc"`)
				writer.WriteHeader(http.StatusNotModified)
				return
			}
			writer.Header().Set("ETag", `"abc"`)
			_, _ = io.WriteString(writer, `{"cli":{"name":"cg"},"domains":[],"etag":"abc"}`)
		case "/exec/demo/item.get":
			executeCalled = true
			if got := request.Header.Get("X-Cli-Gateway-Confirm"); got != "true" {
				t.Errorf("X-Cli-Gateway-Confirm = %q", got)
			}
			var body struct {
				Args map[string]any `json:"args"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if body.Args["id"] != "42" {
				t.Errorf("args = %#v", body.Args)
			}
			_, _ = io.WriteString(writer, `{"ok":true,"status":200,"data":{"id":"42"}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := New(Options{Server: server.URL, Token: "token-1", Invoker: "ai", HTTP: server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body, etag, unchanged, err := client.Manifest(context.Background(), "")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if unchanged || etag != `"abc"` || len(body) == 0 {
		t.Fatalf("body=%s etag=%q unchanged=%v", body, etag, unchanged)
	}
	_, _, unchanged, err = client.Manifest(context.Background(), etag)
	if err != nil || !unchanged {
		t.Fatalf("conditional Manifest: unchanged=%v err=%v", unchanged, err)
	}
	if _, err := client.Execute(context.Background(), "demo", "item.get", map[string]any{"id": "42"}, true); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !executeCalled {
		t.Fatal("execute endpoint was not called")
	}
}

func TestAPIError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"ok":false,"error":"E_AUTH_INVALID","message":"bad token","trace_id":"0123456789abcdef0123456789abcdef"}`)
	}))
	defer server.Close()
	client, err := New(Options{Server: server.URL, HTTP: server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, _, err = client.Manifest(context.Background(), "")
	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("error = %T %v", err, err)
	}
	if apiErr.Status != http.StatusUnauthorized || apiErr.Code != "E_AUTH_INVALID" {
		t.Fatalf("error = %#v", apiErr)
	}
}
