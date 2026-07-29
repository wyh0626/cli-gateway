package credential

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestAuthorizationCodeFlowUsesPKCEAndIsolatesUsers(t *testing.T) {
	t.Parallel()

	var expectedChallenge string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/token" {
			http.NotFound(writer, request)
			return
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "cli-gateway" || password != "secret" {
			t.Errorf("basic auth = %q, %q, %t", username, password, ok)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != "one-time-code" {
			t.Errorf("form = %#v", request.Form)
		}
		challenge := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
		if got := base64.RawURLEncoding.EncodeToString(challenge[:]); got != expectedChallenge {
			t.Errorf("PKCE challenge = %q, want %q", got, expectedChallenge)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "alice-access", "refresh_token": "alice-refresh",
			"token_type": "Bearer", "expires_in": 3600, "scope": "items.read offline_access",
		})
	}))
	defer tokenServer.Close()

	command := authorizationTestCommand(t, tokenServer.URL)
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	alice := model.Principal{Issuer: "https://issuer.example", Tenant: "acme", Subject: "alice"}
	start, err := broker.Begin(context.Background(), command, alice, "https://cli-gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizationURL.Query()
	expectedChallenge = query.Get("code_challenge")
	if authorizationURL.Path != "/authorize" || query.Get("response_type") != "code" ||
		query.Get("client_id") != "cli-gateway" || query.Get("code_challenge_method") != "S256" ||
		query.Get("scope") != "items.read offline_access" ||
		query.Get("redirect_uri") != "https://cli-gateway.example/oauth/downstream/callback" ||
		query.Get("state") == "" || expectedChallenge == "" {
		t.Fatalf("authorization URL = %s", start.AuthorizationURL)
	}
	if _, err := broker.Complete(context.Background(), query.Get("state"), "one-time-code", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Complete(context.Background(), query.Get("state"), "one-time-code", ""); err == nil {
		t.Fatal("replayed state was accepted")
	}

	provider, err := newAuthorizationCodeProvider(command, broker, staticSecrets("secret"), "acme")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
	if err := provider.Authorize(context.Background(), request, model.Invocation{Command: command, Principal: alice}); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer alice-access" {
		t.Fatalf("Authorization = %q", got)
	}

	bobRequest := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
	err = provider.Authorize(context.Background(), bobRequest, model.Invocation{
		Command:   command,
		Principal: model.Principal{Issuer: alice.Issuer, Tenant: alice.Tenant, Subject: "bob"},
	})
	var apiErr *httpx.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "E_DOWNSTREAM_AUTH_REQUIRED" {
		t.Fatalf("bob authorization error = %#v", err)
	}
	if apiErr.Hint != "run acme authorize inventory" {
		t.Fatalf("bob authorization hint = %q", apiErr.Hint)
	}
}

func TestAuthorizationCodeUsesClientSecretPost(t *testing.T) {
	t.Parallel()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, _, ok := request.BasicAuth(); ok {
			t.Error("client_secret_post request unexpectedly used HTTP Basic authentication")
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if request.Form.Get("client_id") != "github-app-client" ||
			request.Form.Get("client_secret") != "github-app-secret" ||
			request.Form.Get("code_verifier") != "verifier" {
			t.Errorf("form = %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "github-user-token", "refresh_token": "github-refresh-token",
			"token_type": "bearer", "expires_in": 28800,
		})
	}))
	defer tokenServer.Close()

	tokenURL, err := url.Parse(tokenServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	token, err := requestAuthorizationCodeToken(
		context.Background(),
		tokenServer.Client(),
		model.OAuthCredentialConfig{
			TokenURL: tokenURL, ClientID: "github-app-client",
			TokenEndpointAuth: clientSecretPostAuthMethod,
		},
		"github-app-secret",
		url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"one-time-code"},
			"client_id":     {"github-app-client"},
			"code_verifier": {"verifier"},
		},
		AuthorizationToken{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "github-user-token" || token.RefreshToken != "github-refresh-token" {
		t.Fatalf("token = %#v", token)
	}
}

func TestAuthorizationCodeRefreshIsCoalesced(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	release := make(chan struct{})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		<-release
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "refresh-1" {
			t.Errorf("form = %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"access_token":"refreshed-access","refresh_token":"refresh-2","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	command := authorizationTestCommand(t, tokenServer.URL)
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := model.Principal{Issuer: "issuer", Tenant: "acme", Subject: "alice"}
	key := broker.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	if err := store.Save(key, AuthorizationToken{
		AccessToken: "expired", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	provider, err := newAuthorizationCodeProvider(command, broker, staticSecrets("secret"), "cg")
	if err != nil {
		t.Fatal(err)
	}

	const callers = 24
	var wait sync.WaitGroup
	wait.Add(callers)
	failures := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			request := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
			if err := provider.Authorize(context.Background(), request, model.Invocation{Command: command, Principal: principal}); err != nil {
				failures <- err
				return
			}
			if got := request.Header.Get("Authorization"); got != "Bearer refreshed-access" {
				failures <- fmt.Errorf("Authorization = %q", got)
			}
		}()
	}
	for requests.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("refresh requests = %d, want 1", got)
	}
}

func TestAuthorizationCodePermanentRefreshFailureRequiresReauthorization(t *testing.T) {
	t.Parallel()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(writer, `{"error":"invalid_grant"}`)
	}))
	defer tokenServer.Close()

	command := authorizationTestCommand(t, tokenServer.URL)
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := model.Principal{Issuer: "issuer", Subject: "alice"}
	key := broker.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	if err := store.Save(key, AuthorizationToken{AccessToken: "expired", RefreshToken: "revoked", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	provider, err := newAuthorizationCodeProvider(command, broker, staticSecrets("secret"), "cg")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
	err = provider.Authorize(context.Background(), request, model.Invocation{Command: command, Principal: principal})
	var apiErr *httpx.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "E_DOWNSTREAM_AUTH_REQUIRED" {
		t.Fatalf("Authorize() error = %#v", err)
	}
	if _, found, err := store.Load(key); err != nil || found {
		t.Fatalf("revoked token found=%t err=%v", found, err)
	}
}

func TestAuthorizationCodeClientFailureKeepsRefreshGrant(t *testing.T) {
	t.Parallel()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(writer, `{"error":"invalid_client"}`)
	}))
	defer tokenServer.Close()

	command := authorizationTestCommand(t, tokenServer.URL)
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := model.Principal{Issuer: "issuer", Subject: "alice"}
	key := broker.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	if err := store.Save(key, AuthorizationToken{AccessToken: "expired", RefreshToken: "still-valid", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	provider, err := newAuthorizationCodeProvider(command, broker, staticSecrets("secret"), "cg")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
	err = provider.Authorize(context.Background(), request, model.Invocation{Command: command, Principal: principal})
	var apiErr *httpx.APIError
	if errors.As(err, &apiErr) && apiErr.Code == "E_DOWNSTREAM_AUTH_REQUIRED" {
		t.Fatalf("invalid_client incorrectly required user reauthorization: %v", err)
	}
	token, found, loadErr := store.Load(key)
	if loadErr != nil || !found || token.RefreshToken != "still-valid" {
		t.Fatalf("grant after invalid_client = %#v, found=%t err=%v", token, found, loadErr)
	}
}

func TestAuthorizationStateExpiresAndDenialConsumesIt(t *testing.T) {
	t.Parallel()

	command := authorizationTestCommand(t, "http://127.0.0.1:1")
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	broker.now = func() time.Time { return now }
	principal := model.Principal{Issuer: "issuer", Subject: "alice"}

	start, err := broker.Begin(context.Background(), command, principal, "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(start.AuthorizationURL)
	state := parsed.Query().Get("state")
	now = now.Add(2 * time.Minute)
	if _, err := broker.Complete(context.Background(), state, "code", ""); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired state error = %v", err)
	}

	now = time.Now()
	start, err = broker.Begin(context.Background(), command, principal, "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = url.Parse(start.AuthorizationURL)
	state = parsed.Query().Get("state")
	if _, err := broker.Complete(context.Background(), state, "", "access_denied"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denial error = %v", err)
	}
	if _, err := broker.Complete(context.Background(), state, "code", ""); err == nil {
		t.Fatal("denied state was reusable")
	}
}

func TestAuthorizationDisconnectRevokesRefreshTokenAndDeletesGrant(t *testing.T) {
	t.Parallel()

	var revoked string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/revoke" {
			http.NotFound(writer, request)
			return
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "cli-gateway" || password != "secret" {
			t.Errorf("basic auth = %q, %q, %t", username, password, ok)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		revoked = request.Form.Get("token")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	command := authorizationTestCommand(t, server.URL)
	revocationURL, err := url.Parse(server.URL + "/revoke")
	if err != nil {
		t.Fatal(err)
	}
	command.OAuthCredential.RevocationURL = revocationURL
	store := authorizationTestStore(t)
	broker, err := NewAuthorizationCodeBroker(store, staticSecrets("secret"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := model.Principal{Issuer: "issuer", Subject: "alice"}
	key := broker.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	if err := store.Save(key, AuthorizationToken{AccessToken: "access", RefreshToken: "refresh-to-revoke", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := broker.Disconnect(context.Background(), command, principal); err != nil {
		t.Fatal(err)
	}
	if revoked != "refresh-to-revoke" {
		t.Fatalf("revoked token = %q", revoked)
	}
	if _, found, err := store.Load(key); err != nil || found {
		t.Fatalf("grant after disconnect found=%t err=%v", found, err)
	}
}

func authorizationTestCommand(t *testing.T, serverURL string) *model.CompiledCommand {
	t.Helper()
	authorizationURL, err := url.Parse(serverURL + "/authorize")
	if err != nil {
		t.Fatal(err)
	}
	tokenURL, err := url.Parse(serverURL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	return &model.CompiledCommand{
		Domain: "inventory", DownstreamAuth: model.DownstreamAuthorizationCode,
		OAuthCredential: &model.OAuthCredentialConfig{
			AuthorizationURL: authorizationURL, TokenURL: tokenURL,
			ClientID: "cli-gateway", ClientSecretRef: "env:OAUTH_SECRET",
			Audience: "inventory-api", Scopes: []string{"items.read", "offline_access"}, AllowLocal: true,
		},
		CredentialCache: model.CredentialCacheConfig{Capacity: 100, RefreshSkew: 30 * time.Second, NegativeTTL: time.Second},
	}
}

func authorizationTestStore(t *testing.T) *MemoryAuthorizationTokenStore {
	t.Helper()
	store, err := NewMemoryAuthorizationTokenStore([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
