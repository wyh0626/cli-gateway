package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/credential"
	"github.com/wyh0626/cli-gateway/internal/invoke"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(testManifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manager, err := manifest.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	NewHandler(manager).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	if body := response.Body.String(); body != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestHealthzRejectsOtherMethods(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	response := httptest.NewRecorder()
	NewHandler(nil).ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestProtectedResourceMetadataDistinguishesHTTPAndMCP(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(testManifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manager, err := manifest.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	handler := NewHandler(manager)
	for _, test := range []struct {
		path     string
		resource string
	}{
		{path: "/.well-known/oauth-protected-resource", resource: "https://tools.example.com"},
		{path: "/.well-known/oauth-protected-resource/mcp", resource: "https://tools.example.com/mcp"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", test.path, response.Code)
		}
		var document struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			ClientID             string   `json:"client_id"`
			Audience             string   `json:"audience"`
			ResourceParameter    string   `json:"resource_parameter"`
			Scopes               []string `json:"scopes_supported"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		if document.Resource != test.resource || document.ClientID != "cg-cli" ||
			document.Audience != "cli-gateway" || document.ResourceParameter != "both" {
			t.Fatalf("%s metadata = %#v", test.path, document)
		}
		if len(document.AuthorizationServers) != 1 || document.AuthorizationServers[0] != "https://auth.example.com" {
			t.Fatalf("%s authorization servers = %#v", test.path, document.AuthorizationServers)
		}
		if strings.Join(document.Scopes, ",") != "email,profile" {
			t.Fatalf("%s scopes = %#v", test.path, document.Scopes)
		}
	}
}

func TestFlushWriterFlushesEveryChunk(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	writer := flushWriter{writer: recorder, flusher: recorder}
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if !recorder.Flushed || !bytes.Equal(recorder.Body.Bytes(), []byte("first\n")) {
		t.Fatalf("flush writer state = flushed:%v body:%q", recorder.Flushed, recorder.Body.Bytes())
	}
}

func TestAuthorizationCodeEndToEnd(t *testing.T) {
	var tokenRequests int
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/token" {
			http.NotFound(writer, request)
			return
		}
		tokenRequests++
		username, password, ok := request.BasicAuth()
		if !ok || username != "cli-gateway" || password != "oauth-secret" {
			t.Errorf("token endpoint basic auth = %q, %q, %t", username, password, ok)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if request.Form.Get("grant_type") != "authorization_code" ||
			request.Form.Get("code") != "provider-code" ||
			request.Form.Get("code_verifier") == "" {
			t.Errorf("token form = %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"access_token":"downstream-access","refresh_token":"downstream-refresh","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	var upstreamRequests int
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamRequests++
		if got := request.Header.Get("Authorization"); got != "Bearer downstream-access" {
			t.Errorf("upstream Authorization = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"items":["one"]}`)
	}))
	defer upstreamServer.Close()

	input := fmt.Sprintf(`version: 1
server:
  listen: ":0"
  public_url: https://cli-gateway.example
  environment: development
auth:
  mode: trusted-header
  issuer: https://issuer.example
  trusted_jwks: https://issuer.example/jwks.json
  audience: cli-gateway
cli:
  name: cg
policy:
  ai_max_risk: read
audit: {}
domains:
  - name: inventory
    upstream: %s
    network:
      allow_local: true
    downstream_auth:
      mode: authorization-code
      authorization_code:
        authorization_url: %s/authorize
        token_url: %s/token
        client_id: cli-gateway
        client_secret_ref: env:OAUTH_SECRET
        audience: inventory-api
        scopes: [items.read, offline_access]
    commands:
      - path: [list]
        method: GET
        endpoint: /v1/items
        risk: read
`, upstreamServer.URL, tokenServer.URL, tokenServer.URL)
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := manifest.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.NewMemoryAuthorizationTokenStore([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	secrets := serverTestSecrets("oauth-secret")
	broker, err := credential.NewAuthorizationCodeBroker(store, secrets, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	credentialManager, err := credential.NewManagerWithAuthorizationCode(
		manager.Current(), nil, []byte(strings.Repeat("c", 32)), secrets, broker,
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager, Dependencies{
		Verifier: serverTestVerifier{principal: model.Principal{
			Issuer: "https://issuer.example", Tenant: "acme", Subject: "alice",
			Scopes: map[string]struct{}{}, Invoker: model.InvokerHuman,
		}},
		Invoker: invoke.NewServiceWithAuthorizer(credentialManager), DownstreamOAuth: broker,
	})

	execute := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/exec/inventory/list", strings.NewReader(`{"args":{}}`))
		request.Header.Set("Authorization", "Bearer cli-access")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := execute(); response.Code != http.StatusPreconditionRequired ||
		!strings.Contains(response.Body.String(), "E_DOWNSTREAM_AUTH_REQUIRED") {
		t.Fatalf("first execute status=%d body=%q", response.Code, response.Body.String())
	}

	startRequest := httptest.NewRequest(http.MethodPost, "/oauth/downstream/inventory/authorize", nil)
	startRequest.Header.Set("Authorization", "Bearer cli-access")
	startResponse := httptest.NewRecorder()
	handler.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%q", startResponse.Code, startResponse.Body.String())
	}
	var start credential.AuthorizationStart
	if err := json.Unmarshal(startResponse.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := http.NewRequest(http.MethodGet, start.AuthorizationURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.URL.Query().Get("state")
	if state == "" || authorizationURL.URL.Query().Get("code_challenge") == "" {
		t.Fatalf("authorization URL = %q", start.AuthorizationURL)
	}

	callback := httptest.NewRequest(http.MethodGet, "/oauth/downstream/callback?state="+state+"&code=provider-code", nil)
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, callback)
	if callbackResponse.Code != http.StatusOK || !strings.Contains(callbackResponse.Body.String(), "Authorization for") {
		t.Fatalf("callback status=%d body=%q", callbackResponse.Code, callbackResponse.Body.String())
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/oauth/downstream/inventory/status", nil)
	statusRequest.Header.Set("Authorization", "Bearer cli-access")
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"authorized":true`) {
		t.Fatalf("status=%d body=%q", statusResponse.Code, statusResponse.Body.String())
	}

	if response := execute(); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"items"`) {
		t.Fatalf("authorized execute status=%d body=%q", response.Code, response.Body.String())
	}
	if tokenRequests != 1 || upstreamRequests != 1 {
		t.Fatalf("token requests=%d upstream requests=%d", tokenRequests, upstreamRequests)
	}

	disconnectRequest := httptest.NewRequest(http.MethodDelete, "/oauth/downstream/inventory", nil)
	disconnectRequest.Header.Set("Authorization", "Bearer cli-access")
	disconnectResponse := httptest.NewRecorder()
	handler.ServeHTTP(disconnectResponse, disconnectRequest)
	if disconnectResponse.Code != http.StatusOK {
		t.Fatalf("disconnect status=%d body=%q", disconnectResponse.Code, disconnectResponse.Body.String())
	}
	if response := execute(); response.Code != http.StatusPreconditionRequired {
		t.Fatalf("execute after disconnect status=%d body=%q", response.Code, response.Body.String())
	}
}

type serverTestSecrets string

func (s serverTestSecrets) Resolve(string) (string, error) { return string(s), nil }

type serverTestVerifier struct {
	principal model.Principal
}

func (v serverTestVerifier) Verify(_ context.Context, token string) (model.Principal, error) {
	if token != "cli-access" {
		return model.Principal{}, fmt.Errorf("unexpected token")
	}
	return v.principal, nil
}

const testManifest = `version: 1
server:
  listen: ":8080"
  public_url: https://tools.example.com
  environment: development
auth:
  mode: trusted-header
  issuer: https://auth.example.com
  client_id: cg-cli
  trusted_jwks: https://auth.example.com/jwks.json
  audience: cli-gateway
  identity_claims:
    email: email
    name: name
cli:
  name: cg
policy:
  ai_max_risk: read
audit: {}
domains:
  - name: inventory
    upstream: https://api.example.com
    downstream_auth:
      mode: signed-identity
      identity_audience: inventory-api
    commands:
      - path: [list]
        method: GET
        endpoint: /v1/resources
        risk: read
`
