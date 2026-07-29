// Package credential builds trusted downstream authentication headers.
package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/breaker"
	"github.com/wyh0626/cli-gateway/internal/cache"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

// IdentitySigner creates request-bound downstream identity assertions.
type IdentitySigner interface {
	Sign(model.Invocation) (string, error)
}

type provider interface {
	Authorize(context.Context, *http.Request, model.Invocation) error
}

// Observer receives bounded-cardinality credential telemetry.
type Observer interface {
	RecordTokenCache(string)
	RecordTokenExchange(time.Duration, bool)
	RecordCircuitRejection()
}

// Manager is a generation-scoped downstream credential broker.
type Manager struct {
	providers map[string]provider
}

// NewManager constructs and preflights one provider per domain.
func NewManager(snapshot *manifest.Snapshot, signer IdentitySigner, cacheKey []byte, secrets SecretResolver, observers ...Observer) (*Manager, error) {
	return newManager(snapshot, signer, cacheKey, secrets, nil, observers...)
}

// NewManagerWithAuthorizationCode constructs a manager with process-scoped
// per-user downstream OAuth support.
func NewManagerWithAuthorizationCode(
	snapshot *manifest.Snapshot,
	signer IdentitySigner,
	cacheKey []byte,
	secrets SecretResolver,
	authorizationBroker *AuthorizationCodeBroker,
	observers ...Observer,
) (*Manager, error) {
	return newManager(snapshot, signer, cacheKey, secrets, authorizationBroker, observers...)
}

func newManager(snapshot *manifest.Snapshot, signer IdentitySigner, cacheKey []byte, secrets SecretResolver, authorizationBroker *AuthorizationCodeBroker, observers ...Observer) (*Manager, error) {
	if snapshot == nil {
		return nil, errors.New("credential manager snapshot is required")
	}
	if secrets == nil {
		secrets = EnvironmentSecrets{}
	}
	manager := &Manager{providers: make(map[string]provider)}
	var observer Observer
	if len(observers) != 0 {
		observer = observers[0]
	}
	for _, key := range snapshot.CommandKeys {
		command := snapshot.Commands[key]
		if _, exists := manager.providers[command.Domain]; exists {
			continue
		}
		var selected provider
		switch command.DownstreamAuth {
		case model.DownstreamSignedIdentity:
			if signer == nil {
				return nil, fmt.Errorf("domain %s: identity signer is unavailable", command.Domain)
			}
			selected = signedIdentityProvider{signer: signer}
		case model.DownstreamBearerPassthrough:
			selected = bearerPassthroughProvider{}
		case model.DownstreamTokenExchange, model.DownstreamClientCredentials:
			created, err := newOAuthProvider(command, cacheKey, secrets, observer)
			if err != nil {
				return nil, fmt.Errorf("domain %s: %w", command.Domain, err)
			}
			selected = created
		case model.DownstreamAuthorizationCode:
			created, err := newAuthorizationCodeProvider(command, authorizationBroker, secrets, snapshot.CLIName)
			if err != nil {
				return nil, fmt.Errorf("domain %s: %w", command.Domain, err)
			}
			selected = created
		default:
			return nil, fmt.Errorf("domain %s: unsupported downstream credential mode %q", command.Domain, command.DownstreamAuth)
		}
		manager.providers[command.Domain] = selected
	}
	return manager, nil
}

// Authorize implements model.OutboundAuthorizer.
func (m *Manager) Authorize(ctx context.Context, request *http.Request, invocation model.Invocation) error {
	if m == nil || invocation.Command == nil {
		return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream credential manager is unavailable"}
	}
	selected := m.providers[invocation.Command.Domain]
	if selected == nil {
		return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream credential provider is unavailable"}
	}
	return selected.Authorize(ctx, request, invocation)
}

// Invalidate drops a cached downstream bearer after an upstream 401.
func (m *Manager) Invalidate(invocation model.Invocation) {
	if m == nil || invocation.Command == nil {
		return
	}
	if selected, ok := m.providers[invocation.Command.Domain].(*oauthProvider); ok {
		selected.cache.Invalidate(selected.cacheKey(invocation))
	}
	if selected, ok := m.providers[invocation.Command.Domain].(*authorizationCodeProvider); ok {
		selected.broker.invalidate(selected.command, invocation.Principal)
	}
}

type signedIdentityProvider struct {
	signer IdentitySigner
}

func (p signedIdentityProvider) Authorize(_ context.Context, request *http.Request, invocation model.Invocation) error {
	token, err := p.signer.Sign(invocation)
	if err != nil {
		return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "identity signing failed", Cause: err}
	}
	request.Header.Set("X-Cli-Gateway-Identity", token)
	return nil
}

type bearerPassthroughProvider struct{}

func (bearerPassthroughProvider) Authorize(_ context.Context, request *http.Request, invocation model.Invocation) error {
	if invocation.BearerToken == "" {
		return &httpx.APIError{Status: http.StatusBadGateway, Code: "E_DOWNSTREAM_AUTH", Message: "inbound bearer is unavailable"}
	}
	request.Header.Set("Authorization", "Bearer "+invocation.BearerToken)
	return nil
}

type oauthProvider struct {
	mode         model.DownstreamAuthMode
	domain       string
	config       *model.OAuthCredentialConfig
	clientSecret string
	configDigest string
	cache        *cache.TokenCache
	http         *http.Client
	breaker      *breaker.Breaker
	observer     Observer
}

func newOAuthProvider(command *model.CompiledCommand, cacheKey []byte, secrets SecretResolver, observers ...Observer) (*oauthProvider, error) {
	config := command.OAuthCredential
	if config == nil || config.TokenURL == nil {
		return nil, errors.New("OAuth credential configuration is missing")
	}
	secret, err := secrets.Resolve(config.ClientSecretRef)
	if err != nil {
		return nil, fmt.Errorf("resolve client secret: %w", err)
	}
	tokenCache, err := cache.NewTokenCache(cacheKey, command.CredentialCache.Capacity, command.CredentialCache.RefreshSkew, command.CredentialCache.NegativeTTL)
	if err != nil {
		return nil, err
	}
	httpClient, err := tokenHTTPClient(config.AllowLocal, config.TLS)
	if err != nil {
		return nil, fmt.Errorf("initialize token endpoint transport: %w", err)
	}
	var observer Observer
	if len(observers) != 0 {
		observer = observers[0]
	}
	return &oauthProvider{
		mode: command.DownstreamAuth, domain: command.Domain, config: config, clientSecret: secret,
		configDigest: credentialDigest(command.DownstreamAuth, config),
		cache:        tokenCache, http: httpClient, breaker: breaker.New(5, 30*time.Second), observer: observer,
	}, nil
}

func (p *oauthProvider) Authorize(ctx context.Context, request *http.Request, invocation model.Invocation) error {
	if p.mode == model.DownstreamTokenExchange && invocation.BearerToken == "" {
		return &httpx.APIError{Status: http.StatusBadGateway, Code: "E_DOWNSTREAM_AUTH", Message: "subject token is unavailable for downstream delegation"}
	}
	key := p.cacheKey(invocation)
	token, result, err := p.cache.GetOrLoad(ctx, key, func(loadContext context.Context) (cache.Token, bool, error) {
		return p.requestToken(loadContext, invocation.BearerToken, invocation.TraceID, invocation.TraceState)
	})
	if p.observer != nil {
		p.observer.RecordTokenCache(string(result))
	}
	if err != nil {
		var apiErr *httpx.APIError
		if errors.As(err, &apiErr) {
			return apiErr
		}
		return &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream authorization server is unavailable", Cause: err}
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return nil
}

func (p *oauthProvider) cacheKey(invocation model.Invocation) string {
	binding := invocation.Principal.SessionID
	if binding == "" {
		binding = invocation.Principal.Subject
	}
	if p.mode == model.DownstreamClientCredentials {
		binding = "service"
	}
	return p.cache.Key(
		invocation.Principal.Issuer,
		invocation.Principal.Tenant,
		binding,
		invocation.Principal.ClientID,
		p.domain,
		string(p.mode),
		p.configDigest,
		p.config.Audience,
		p.config.Resource,
		strings.Join(p.config.Scopes, "\x1f"),
		p.config.RequestedTokenType,
	)
}

func credentialDigest(mode model.DownstreamAuthMode, config *model.OAuthCredentialConfig) string {
	scopes := append([]string(nil), config.Scopes...)
	sort.Strings(scopes)
	value := strings.Join([]string{
		string(mode), optionalURL(config.AuthorizationURL), optionalURL(config.TokenURL), optionalURL(config.RevocationURL), config.ClientID, config.ClientSecretRef,
		config.TokenEndpointAuth, config.Audience, config.Resource, strings.Join(scopes, "\x1f"),
		config.SubjectTokenType, config.RequestedTokenType, config.TLS.CAFile,
		config.TLS.ClientCertFile, config.TLS.ClientKeyFile, fmt.Sprint(config.TLS.InsecureSkipVerify),
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func optionalURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	return value.String()
}
