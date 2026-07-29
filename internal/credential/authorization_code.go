package credential

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
)

const maxPendingAuthorizations = 10_000

// AuthorizationStart is returned to an authenticated client that must open a
// downstream provider's browser authorization page.
type AuthorizationStart struct {
	Domain           string    `json:"domain"`
	AuthorizationURL string    `json:"authorization_url"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// AuthorizationStatus reports whether a user has completed authorization.
type AuthorizationStatus struct {
	Domain     string    `json:"domain"`
	Authorized bool      `json:"authorized"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// AuthorizationCompletion is safe to render in the public callback response.
type AuthorizationCompletion struct {
	Domain string
}

type pendingAuthorization struct {
	domain       string
	recordKey    string
	configDigest string
	redirectURI  string
	codeVerifier string
	expiresAt    time.Time
	config       model.OAuthCredentialConfig
	clientSecret string
	http         *http.Client
}

type authorizationRefreshCall struct {
	done  chan struct{}
	token string
	err   error
}

// AuthorizationCodeBroker owns short-lived OAuth state and a persistent,
// encrypted per-user token store. It is process-scoped so tokens survive
// manifest generation reloads.
type AuthorizationCodeBroker struct {
	store    AuthorizationTokenStore
	secrets  SecretResolver
	stateTTL time.Duration
	now      func() time.Time

	mu          sync.Mutex
	pending     map[string]pendingAuthorization
	pendingByID map[string]string
	refreshes   map[string]*authorizationRefreshCall
	clients     map[string]*http.Client
}

// NewAuthorizationCodeBroker creates the process-wide downstream user grant
// broker.
func NewAuthorizationCodeBroker(store AuthorizationTokenStore, secrets SecretResolver, stateTTL time.Duration) (*AuthorizationCodeBroker, error) {
	if store == nil {
		return nil, errors.New("authorization token store is required")
	}
	if secrets == nil {
		secrets = EnvironmentSecrets{}
	}
	if stateTTL <= 0 || stateTTL > 15*time.Minute {
		return nil, errors.New("authorization state TTL must be between zero and 15 minutes")
	}
	return &AuthorizationCodeBroker{
		store: store, secrets: secrets, stateTTL: stateTTL, now: time.Now,
		pending: make(map[string]pendingAuthorization), pendingByID: make(map[string]string),
		refreshes: make(map[string]*authorizationRefreshCall), clients: make(map[string]*http.Client),
	}, nil
}

// Begin starts one PKCE-protected downstream authorization for an already
// authenticated cli-gateway principal.
func (b *AuthorizationCodeBroker) Begin(_ context.Context, command *model.CompiledCommand, principal model.Principal, publicURL string) (AuthorizationStart, error) {
	if err := validateAuthorizationCommand(command); err != nil {
		return AuthorizationStart{}, err
	}
	if principal.Subject == "" || principal.Issuer == "" {
		return AuthorizationStart{}, &httpx.APIError{Status: http.StatusUnauthorized, Code: "E_AUTH_INVALID", Message: "authenticated user identity is incomplete"}
	}
	config := command.OAuthCredential
	clientSecret, err := b.secrets.Resolve(config.ClientSecretRef)
	if err != nil {
		return AuthorizationStart{}, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream OAuth client is unavailable", Cause: err}
	}
	httpClient, err := b.clientFor(command)
	if err != nil {
		return AuthorizationStart{}, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream OAuth transport is unavailable", Cause: err}
	}
	state, err := secureRandomURLValue(32)
	if err != nil {
		return AuthorizationStart{}, err
	}
	verifier, err := secureRandomURLValue(48)
	if err != nil {
		return AuthorizationStart{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	redirectURI := strings.TrimSuffix(publicURL, "/") + "/oauth/downstream/callback"
	digest := credentialDigest(command.DownstreamAuth, config)
	recordKey := b.recordKey(command.Domain, digest, principal)
	expiresAt := b.now().UTC().Add(b.stateTTL)

	authorizationURL := *config.AuthorizationURL
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", config.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	if len(config.Scopes) != 0 {
		query.Set("scope", strings.Join(config.Scopes, " "))
	}
	if config.Audience != "" {
		query.Set("audience", config.Audience)
	}
	if config.Resource != "" {
		query.Set("resource", config.Resource)
	}
	authorizationURL.RawQuery = query.Encode()

	pending := pendingAuthorization{
		domain: command.Domain, recordKey: recordKey, configDigest: digest,
		redirectURI: redirectURI, codeVerifier: verifier, expiresAt: expiresAt,
		config: cloneOAuthCredential(*config), clientSecret: clientSecret, http: httpClient,
	}
	b.mu.Lock()
	b.purgePendingLocked(b.now())
	if previousState := b.pendingByID[recordKey]; previousState != "" {
		delete(b.pending, previousState)
	}
	if len(b.pending) >= maxPendingAuthorizations {
		b.mu.Unlock()
		return AuthorizationStart{}, &httpx.APIError{Status: http.StatusTooManyRequests, Code: "E_RATE_LIMITED", Message: "too many downstream authorizations are pending"}
	}
	b.pending[state] = pending
	b.pendingByID[recordKey] = state
	b.mu.Unlock()

	return AuthorizationStart{Domain: command.Domain, AuthorizationURL: authorizationURL.String(), ExpiresAt: expiresAt}, nil
}

// Complete consumes a one-time state, exchanges the code, and persists the
// resulting user token.
func (b *AuthorizationCodeBroker) Complete(ctx context.Context, state, code, providerError string) (AuthorizationCompletion, error) {
	if strings.TrimSpace(state) == "" {
		return AuthorizationCompletion{}, errors.New("authorization state is missing")
	}
	b.mu.Lock()
	b.purgePendingLocked(b.now())
	pending, ok := b.pending[state]
	if ok {
		delete(b.pending, state)
		if b.pendingByID[pending.recordKey] == state {
			delete(b.pendingByID, pending.recordKey)
		}
	}
	b.mu.Unlock()
	if !ok {
		return AuthorizationCompletion{}, errors.New("authorization state is invalid or expired")
	}
	if providerError != "" {
		return AuthorizationCompletion{}, errors.New("downstream authorization was denied")
	}
	if strings.TrimSpace(code) == "" {
		return AuthorizationCompletion{}, errors.New("authorization code is missing")
	}

	token, err := requestAuthorizationCodeToken(ctx, pending.http, pending.config, pending.clientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pending.redirectURI},
		"client_id":     {pending.config.ClientID},
		"code_verifier": {pending.codeVerifier},
	}, AuthorizationToken{})
	if err != nil {
		return AuthorizationCompletion{}, err
	}
	if token.RefreshToken == "" {
		return AuthorizationCompletion{}, errors.New("downstream authorization server did not issue a refresh token")
	}
	if err := b.store.Save(pending.recordKey, token); err != nil {
		return AuthorizationCompletion{}, fmt.Errorf("persist downstream OAuth token: %w", err)
	}
	return AuthorizationCompletion{Domain: pending.domain}, nil
}

// Status checks whether a per-user grant exists without exposing its tokens.
func (b *AuthorizationCodeBroker) Status(command *model.CompiledCommand, principal model.Principal) (AuthorizationStatus, error) {
	if err := validateAuthorizationCommand(command); err != nil {
		return AuthorizationStatus{}, err
	}
	key := b.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	token, found, err := b.store.Load(key)
	if err != nil {
		return AuthorizationStatus{}, err
	}
	return AuthorizationStatus{
		Domain: command.Domain, Authorized: found && (token.AccessToken != "" || token.RefreshToken != ""),
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// Disconnect best-effort revokes and always forgets one user's downstream
// grant, matching the CLI logout safety contract.
func (b *AuthorizationCodeBroker) Disconnect(ctx context.Context, command *model.CompiledCommand, principal model.Principal) error {
	if err := validateAuthorizationCommand(command); err != nil {
		return err
	}
	key := b.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	token, found, loadErr := b.store.Load(key)
	if loadErr != nil {
		return loadErr
	}
	var revokeErr error
	if found && command.OAuthCredential.RevocationURL != nil && token.RefreshToken != "" {
		clientSecret, err := b.secrets.Resolve(command.OAuthCredential.ClientSecretRef)
		if err != nil {
			revokeErr = fmt.Errorf("resolve downstream OAuth client for revocation: %w", err)
		} else {
			httpClient, clientErr := b.clientFor(command)
			if clientErr != nil {
				revokeErr = clientErr
			} else {
				revokeErr = requestAuthorizationRevocation(ctx, httpClient, *command.OAuthCredential, clientSecret, token.RefreshToken)
			}
		}
	}
	deleteErr := b.store.Delete(key)
	return errors.Join(revokeErr, deleteErr)
}

func (b *AuthorizationCodeBroker) accessToken(ctx context.Context, command *model.CompiledCommand, principal model.Principal, clientSecret string, httpClient *http.Client, cliName string) (string, error) {
	key := b.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	token, found, err := b.store.Load(key)
	if err != nil {
		return "", &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream token store is unavailable", Cause: err}
	}
	now := b.now()
	if found && token.AccessToken != "" && token.ExpiresAt.After(now.Add(command.CredentialCache.RefreshSkew)) {
		return token.AccessToken, nil
	}
	if !found || token.RefreshToken == "" {
		return "", downstreamAuthorizationRequired(cliName, command.Domain)
	}

	b.mu.Lock()
	if active := b.refreshes[key]; active != nil {
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-active.done:
			return active.token, active.err
		}
	}
	active := &authorizationRefreshCall{done: make(chan struct{})}
	b.refreshes[key] = active
	b.mu.Unlock()

	refreshed, refreshErr := requestAuthorizationCodeToken(ctx, httpClient, *command.OAuthCredential, clientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {command.OAuthCredential.ClientID},
	}, token)
	if refreshErr == nil {
		if saveErr := b.store.Save(key, refreshed); saveErr != nil {
			refreshErr = &httpx.APIError{
				Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH",
				Message: "refreshed downstream token could not be persisted", Cause: saveErr,
			}
		}
	}
	if refreshErr != nil {
		if token.AccessToken != "" && token.ExpiresAt.After(b.now()) && isTransientAuthorizationError(refreshErr) {
			active.token = token.AccessToken
			refreshErr = nil
		} else if isInvalidAuthorizationGrant(refreshErr) {
			_ = b.store.Delete(key)
			refreshErr = downstreamAuthorizationRequired(cliName, command.Domain)
		}
	}
	if refreshErr == nil && active.token == "" {
		active.token = refreshed.AccessToken
	}
	active.err = refreshErr

	b.mu.Lock()
	delete(b.refreshes, key)
	close(active.done)
	b.mu.Unlock()
	return active.token, active.err
}

func (b *AuthorizationCodeBroker) invalidate(command *model.CompiledCommand, principal model.Principal) {
	key := b.recordKey(command.Domain, credentialDigest(command.DownstreamAuth, command.OAuthCredential), principal)
	token, found, err := b.store.Load(key)
	if err != nil || !found {
		return
	}
	token.AccessToken = ""
	token.ExpiresAt = time.Time{}
	token.UpdatedAt = b.now().UTC()
	_ = b.store.Save(key, token)
}

func (b *AuthorizationCodeBroker) recordKey(domain, digest string, principal model.Principal) string {
	return b.store.Key(principal.Issuer, principal.Tenant, principal.Subject, domain, digest)
}

func (b *AuthorizationCodeBroker) purgePendingLocked(now time.Time) {
	for state, pending := range b.pending {
		if !pending.expiresAt.After(now) {
			delete(b.pending, state)
			if b.pendingByID[pending.recordKey] == state {
				delete(b.pendingByID, pending.recordKey)
			}
		}
	}
}

func (b *AuthorizationCodeBroker) clientFor(command *model.CompiledCommand) (*http.Client, error) {
	digest := credentialDigest(command.DownstreamAuth, command.OAuthCredential)
	b.mu.Lock()
	defer b.mu.Unlock()
	if client := b.clients[digest]; client != nil {
		return client, nil
	}
	client, err := tokenHTTPClient(command.OAuthCredential.AllowLocal, command.OAuthCredential.TLS)
	if err != nil {
		return nil, err
	}
	b.clients[digest] = client
	return client, nil
}

type authorizationCodeProvider struct {
	command      *model.CompiledCommand
	clientSecret string
	broker       *AuthorizationCodeBroker
	http         *http.Client
	cliName      string
}

func newAuthorizationCodeProvider(command *model.CompiledCommand, broker *AuthorizationCodeBroker, secrets SecretResolver, cliName string) (*authorizationCodeProvider, error) {
	if broker == nil {
		return nil, errors.New("authorization-code broker is unavailable")
	}
	if err := validateAuthorizationCommand(command); err != nil {
		return nil, err
	}
	secret, err := secrets.Resolve(command.OAuthCredential.ClientSecretRef)
	if err != nil {
		return nil, fmt.Errorf("resolve client secret: %w", err)
	}
	httpClient, err := broker.clientFor(command)
	if err != nil {
		return nil, fmt.Errorf("initialize downstream OAuth transport: %w", err)
	}
	if strings.TrimSpace(cliName) == "" {
		return nil, errors.New("CLI name is required")
	}
	return &authorizationCodeProvider{command: command, clientSecret: secret, broker: broker, http: httpClient, cliName: cliName}, nil
}

func (p *authorizationCodeProvider) Authorize(ctx context.Context, request *http.Request, invocation model.Invocation) error {
	token, err := p.broker.accessToken(ctx, p.command, invocation.Principal, p.clientSecret, p.http, p.cliName)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func validateAuthorizationCommand(command *model.CompiledCommand) error {
	if command == nil || command.DownstreamAuth != model.DownstreamAuthorizationCode || command.OAuthCredential == nil ||
		command.OAuthCredential.AuthorizationURL == nil || command.OAuthCredential.TokenURL == nil {
		return &httpx.APIError{Status: http.StatusBadRequest, Code: "E_DOWNSTREAM_AUTH_MODE", Message: "domain does not use per-user OAuth authorization"}
	}
	return nil
}

func requestAuthorizationCodeToken(ctx context.Context, client *http.Client, config model.OAuthCredentialConfig, clientSecret string, form url.Values, previous AuthorizationToken) (AuthorizationToken, error) {
	if config.Audience != "" {
		form.Set("audience", config.Audience)
	}
	if config.Resource != "" {
		form.Set("resource", config.Resource)
	}
	if form.Get("grant_type") == "refresh_token" && len(config.Scopes) != 0 {
		form.Set("scope", strings.Join(config.Scopes, " "))
	}
	useBasicAuth, err := applyOAuthClientAuthentication(form, config, clientSecret)
	if err != nil {
		return AuthorizationToken{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return AuthorizationToken{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cli-gateway/downstream-oauth")
	if useBasicAuth {
		request.SetBasicAuth(config.ClientID, clientSecret)
	}
	response, err := client.Do(request)
	if err != nil {
		return AuthorizationToken{}, &authorizationEndpointError{transient: true}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponse+1))
	if err != nil {
		return AuthorizationToken{}, &authorizationEndpointError{transient: true}
	}
	if len(body) > maxTokenResponse {
		return AuthorizationToken{}, errors.New("downstream token response is too large")
	}
	var decoded struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		TokenType    string          `json:"token_type"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		Scope        string          `json:"scope"`
		Error        string          `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&decoded); err != nil {
		return AuthorizationToken{}, errors.New("downstream token response is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AuthorizationToken{}, errors.New("downstream token response contains trailing data")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || decoded.Error != "" {
		transient := response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		grantInvalid := decoded.Error == "invalid_grant" || decoded.Error == "invalid_token"
		return AuthorizationToken{}, &authorizationEndpointError{transient: transient, grantInvalid: grantInvalid}
	}
	if decoded.AccessToken == "" || !strings.EqualFold(decoded.TokenType, "Bearer") {
		return AuthorizationToken{}, errors.New("downstream token response is missing a Bearer access token")
	}
	parsed, err := parseTokenResponse(body, time.Now())
	if err != nil {
		return AuthorizationToken{}, err
	}
	refreshToken := decoded.RefreshToken
	if refreshToken == "" {
		refreshToken = previous.RefreshToken
	}
	scopes := append([]string(nil), config.Scopes...)
	if decoded.Scope != "" {
		scopes = strings.Fields(decoded.Scope)
	}
	return AuthorizationToken{
		AccessToken: decoded.AccessToken, RefreshToken: refreshToken,
		ExpiresAt: parsed.ExpiresAt, Scopes: scopes, UpdatedAt: time.Now().UTC(),
	}, nil
}

func requestAuthorizationRevocation(ctx context.Context, client *http.Client, config model.OAuthCredentialConfig, clientSecret, refreshToken string) error {
	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {config.ClientID},
	}
	useBasicAuth, err := applyOAuthClientAuthentication(form, config, clientSecret)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.RevocationURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cli-gateway/downstream-oauth")
	if useBasicAuth {
		request.SetBasicAuth(config.ClientID, clientSecret)
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("downstream token revocation failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxTokenResponse))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("downstream token revocation failed")
	}
	return nil
}

type authorizationEndpointError struct {
	transient    bool
	grantInvalid bool
}

func (e *authorizationEndpointError) Error() string {
	return "downstream authorization server rejected the token request"
}

func isTransientAuthorizationError(err error) bool {
	var endpointErr *authorizationEndpointError
	return errors.As(err, &endpointErr) && endpointErr.transient
}

func isInvalidAuthorizationGrant(err error) bool {
	var endpointErr *authorizationEndpointError
	return errors.As(err, &endpointErr) && endpointErr.grantInvalid
}

func downstreamAuthorizationRequired(cliName, domain string) *httpx.APIError {
	return &httpx.APIError{
		Status: http.StatusPreconditionRequired, Code: "E_DOWNSTREAM_AUTH_REQUIRED",
		Message: "downstream user authorization is required", Hint: "run " + cliName + " authorize " + domain,
	}
}

func secureRandomURLValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate OAuth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func cloneOAuthCredential(config model.OAuthCredentialConfig) model.OAuthCredentialConfig {
	cloned := config
	if config.AuthorizationURL != nil {
		value := *config.AuthorizationURL
		cloned.AuthorizationURL = &value
	}
	if config.TokenURL != nil {
		value := *config.TokenURL
		cloned.TokenURL = &value
	}
	if config.RevocationURL != nil {
		value := *config.RevocationURL
		cloned.RevocationURL = &value
	}
	cloned.Scopes = append([]string(nil), config.Scopes...)
	return cloned
}
