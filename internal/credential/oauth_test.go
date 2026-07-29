package credential

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

type staticSecrets string

func (s staticSecrets) Resolve(string) (string, error) { return string(s), nil }

func TestTokenExchangeIsCachedAndCoalesced(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	release := make(chan struct{})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		<-release
		username, password, ok := request.BasicAuth()
		if !ok || username != "cli-gateway" || password != "secret" {
			t.Errorf("basic auth = %q, %q, %t", username, password, ok)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if request.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			request.Form.Get("subject_token") != "inbound-user-token" ||
			request.Form.Get("audience") != "inventory-api" ||
			request.Form.Get("scope") != "inventory.read" {
			t.Errorf("form = %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "downstream-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	tokenURL, err := url.Parse(tokenServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	command := &model.CompiledCommand{
		Domain: "inventory", DownstreamAuth: model.DownstreamTokenExchange,
		OAuthCredential: &model.OAuthCredentialConfig{
			TokenURL: tokenURL, ClientID: "cli-gateway", ClientSecretRef: "env:SECRET",
			Audience: "inventory-api", Scopes: []string{"inventory.read"},
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
			RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			AllowLocal:         true,
		},
		CredentialCache: model.CredentialCacheConfig{Capacity: 100, RefreshSkew: time.Minute, NegativeTTL: time.Second},
	}
	provider, err := newOAuthProvider(command, []byte(strings.Repeat("c", 32)), staticSecrets("secret"))
	if err != nil {
		t.Fatal(err)
	}
	invocation := model.Invocation{
		Principal: model.Principal{Issuer: "issuer", Subject: "alice", SessionID: "session-1", ClientID: "cg"},
		Command:   command, BearerToken: "inbound-user-token",
	}

	const callers = 24
	var wait sync.WaitGroup
	wait.Add(callers)
	failures := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			request := httptest.NewRequest(http.MethodGet, "https://inventory.example/items", nil)
			if err := provider.Authorize(context.Background(), request, invocation); err != nil {
				failures <- err
				return
			}
			if authorization := request.Header.Get("Authorization"); authorization != "Bearer downstream-token" {
				failures <- fmt.Errorf("Authorization = %q", authorization)
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
	if requests.Load() != 1 {
		t.Fatalf("token requests = %d, want 1", requests.Load())
	}
	provider.cache.Invalidate(provider.cacheKey(invocation))
	retryRequest := httptest.NewRequest(http.MethodGet, "https://inventory.example/items", nil)
	if err := provider.Authorize(context.Background(), retryRequest, invocation); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("token requests after invalidation = %d, want 2", requests.Load())
	}
}

func TestParseTokenResponseUsesEarlierJWTExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, now.Add(5*time.Minute).Unix())))
	accessToken := header + "." + payload + ".signature"
	body, err := json.Marshal(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   "3600",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := parseTokenResponse(body, now)
	if err != nil {
		t.Fatal(err)
	}
	if !token.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("ExpiresAt = %v", token.ExpiresAt)
	}
}
