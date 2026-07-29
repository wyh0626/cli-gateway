package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestAccessTokenSingleFlightAndRefreshRotation(t *testing.T) {
	keyring.MockInit()
	var tokenRequests atomic.Int32
	var issuerURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(writer).Encode(ResourceMetadata{
				Resource: issuerURL, AuthorizationServers: []string{issuerURL}, ClientID: "cg-cli", Audience: "cli-gateway",
			})
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(IssuerMetadata{
				Issuer: issuerURL, TokenEndpoint: issuerURL + "/oauth2/token",
				RevocationEndpoint: issuerURL + "/oauth2/revoke",
			})
		case "/oauth2/token":
			requestNumber := tokenRequests.Add(1)
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			expectedRefresh := "refresh-1"
			if requestNumber == 2 {
				expectedRefresh = "refresh-2"
			}
			if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != expectedRefresh {
				t.Errorf("form = %#v", request.Form)
			}
			if request.Form.Get("resource") != issuerURL || request.Form.Get("audience") != "cli-gateway" {
				t.Errorf("resource parameters = %#v", request.Form)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"access_token": fmt.Sprintf("access-%d", requestNumber), "refresh_token": fmt.Sprintf("refresh-%d", requestNumber+1),
				"token_type": "Bearer", "expires_in": 3600,
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	issuerURL = server.URL
	manager, err := New(server.URL, "", server.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(manager.keyringService, manager.account(), "refresh-1"); err != nil {
		t.Fatal(err)
	}

	const callers = 20
	var wait sync.WaitGroup
	wait.Add(callers)
	failures := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			token, tokenErr := manager.AccessToken(context.Background())
			if tokenErr != nil {
				failures <- tokenErr
			} else if token != "access-1" {
				failures <- &unexpectedToken{token}
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests.Load())
	}
	rotated, err := keyring.Get(manager.keyringService, manager.account())
	if err != nil || rotated != "refresh-2" {
		t.Fatalf("rotated refresh = %q, %v", rotated, err)
	}
	forced, err := manager.RefreshAccessToken(context.Background())
	if err != nil || forced != "access-2" {
		t.Fatalf("forced refresh = %q, %v", forced, err)
	}
	if tokenRequests.Load() != 2 {
		t.Fatalf("token requests after forced refresh = %d, want 2", tokenRequests.Load())
	}
}

type unexpectedToken struct{ value string }

func (e *unexpectedToken) Error() string { return "unexpected token: " + e.value }

func TestEffectiveScopesUseIdentityScopesByDefault(t *testing.T) {
	t.Parallel()
	defaults := effectiveScopes(nil, []string{"demo:destroy", "demo:write", "demo:read", "email", "profile", "profile.read"})
	if strings.Join(defaults, " ") != "openid offline_access email profile" {
		t.Fatalf("default scopes = %#v", defaults)
	}
	explicit := effectiveScopes([]string{"demo:write"}, nil)
	if strings.Join(explicit, " ") != "openid offline_access demo:write" {
		t.Fatalf("explicit scopes = %#v", explicit)
	}
}

func TestSetResourceParametersIncludesHydraAudience(t *testing.T) {
	t.Parallel()
	values := make(url.Values)
	setResourceParameters(values, ResourceMetadata{Resource: "https://cli.example", Audience: "cli-gateway"})
	if values.Get("resource") != "https://cli.example" || values.Get("audience") != "cli-gateway" {
		t.Fatalf("resource parameters = %#v", values)
	}
}

func TestSetResourceParametersSupportsProviderModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		mode         string
		wantResource string
		wantAudience string
	}{
		{name: "both", mode: "both", wantResource: "https://cli.example", wantAudience: "cli-gateway"},
		{name: "audience", mode: "audience", wantAudience: "cli-gateway"},
		{name: "resource", mode: "resource", wantResource: "https://cli.example"},
		{name: "none", mode: "none"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			values := make(url.Values)
			setResourceParameters(values, ResourceMetadata{
				Resource: "https://cli.example", Audience: "cli-gateway", ResourceParameter: test.mode,
			})
			if values.Get("resource") != test.wantResource || values.Get("audience") != test.wantAudience {
				t.Fatalf("resource parameters = %#v", values)
			}
		})
	}
}
