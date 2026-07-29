// Package oauth implements CLI-side OAuth public-client flows and keyring
// refresh-token storage.
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wyh0626/cli-gateway/client/internal/branding"

	"github.com/zalando/go-keyring"
)

const maxOAuthPayload = 1 << 20

// ResourceMetadata is the cli-gateway protected-resource discovery document.
type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ClientID             string   `json:"client_id"`
	Audience             string   `json:"audience"`
	ResourceParameter    string   `json:"resource_parameter"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// IssuerMetadata is the OAuth/OIDC metadata used by the public CLI.
type IssuerMetadata struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
}

// Token is a process-scoped access token.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Error        string          `json:"error"`
	Description  string          `json:"error_description"`
}

// Manager performs one single-flight refresh per process and stores only the
// refresh token in the OS keyring.
type Manager struct {
	server         string
	http           *http.Client
	out            io.Writer
	cliName        string
	keyringService string
	mu             sync.Mutex
	token          Token
}

// New creates a manager for one validated cli-gateway origin.
func New(server, caFile string, httpClient *http.Client, out io.Writer) (*Manager, error) {
	brand, err := branding.Resolve(branding.Config{})
	if err != nil {
		return nil, err
	}
	return NewWithBrand(server, caFile, httpClient, out, brand)
}

// NewWithBrand creates a manager whose refresh-token namespace is isolated
// from other white-label clients on the same workstation.
func NewWithBrand(server, caFile string, httpClient *http.Client, out io.Writer, brand branding.Config) (*Manager, error) {
	brand, err := branding.Resolve(brand)
	if err != nil {
		return nil, err
	}
	server, err = validateServerOrigin(server)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = io.Discard
	}
	if httpClient == nil {
		created, err := secureHTTPClient(caFile)
		if err != nil {
			return nil, err
		}
		httpClient = created
	} else {
		copied := *httpClient
		copied.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		if copied.Timeout == 0 {
			copied.Timeout = 15 * time.Second
		}
		httpClient = &copied
	}
	return &Manager{
		server: server, http: httpClient, out: out,
		cliName: brand.Name, keyringService: brand.KeyringService,
	}, nil
}

// AccessToken returns an environment-independent process token, refreshing
// once through the keyring when needed.
func (m *Manager) AccessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token.AccessToken != "" && time.Until(m.token.ExpiresAt) > 30*time.Second {
		return m.token.AccessToken, nil
	}
	refreshToken, err := keyring.Get(m.keyringService, m.account())
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", fmt.Errorf("not logged in; run %s login", m.cliName)
		}
		return "", fmt.Errorf("read refresh token from OS keyring: %w", err)
	}
	resource, issuer, err := m.metadata(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {resource.ClientID},
	}
	setResourceParameters(form, resource)
	response, err := m.tokenRequest(ctx, issuer.TokenEndpoint, form)
	if err != nil {
		return "", err
	}
	if response.RefreshToken != "" && response.RefreshToken != refreshToken {
		if err := keyring.Set(m.keyringService, m.account(), response.RefreshToken); err != nil {
			return "", fmt.Errorf("rotate refresh token in OS keyring: %w", err)
		}
	}
	m.token = tokenFromResponse(response)
	return m.token.AccessToken, nil
}

// RefreshAccessToken forces one refresh-token exchange. Callers use this only
// after cli-gateway rejects a request as expired and before any upstream dispatch.
func (m *Manager) RefreshAccessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	m.token = Token{}
	m.mu.Unlock()
	return m.AccessToken(ctx)
}

// LoginDevice completes the OAuth Device Authorization Grant.
func (m *Manager) LoginDevice(ctx context.Context, scopes []string) (Token, error) {
	resource, issuer, err := m.metadata(ctx)
	if err != nil {
		return Token{}, err
	}
	if issuer.DeviceAuthorizationEndpoint == "" {
		return Token{}, errors.New("authorization server does not advertise a device authorization endpoint")
	}
	scopes = effectiveScopes(scopes, resource.ScopesSupported)
	form := url.Values{"client_id": {resource.ClientID}}
	setResourceParameters(form, resource)
	if len(scopes) != 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	body, status, err := m.postForm(ctx, issuer.DeviceAuthorizationEndpoint, form)
	if err != nil {
		return Token{}, err
	}
	if status < 200 || status >= 300 {
		return Token{}, errors.New("device authorization request was rejected")
	}
	var device struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &device); err != nil || device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" {
		return Token{}, errors.New("authorization server returned an invalid device response")
	}
	verification := device.VerificationURIComplete
	if verification == "" {
		verification = device.VerificationURI
	}
	fmt.Fprintf(m.out, "Open %s and enter code %s\n", verification, device.UserCode)
	interval := time.Duration(device.Interval) * time.Second
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	expires := time.Duration(device.ExpiresIn) * time.Second
	if expires <= 0 || expires > 15*time.Minute {
		expires = 10 * time.Minute
	}
	pollContext, cancel := context.WithTimeout(ctx, expires)
	defer cancel()
	for {
		timer := time.NewTimer(interval)
		select {
		case <-pollContext.Done():
			timer.Stop()
			return Token{}, errors.New("device authorization expired or was cancelled")
		case <-timer.C:
		}
		tokenForm := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {device.DeviceCode},
			"client_id":   {resource.ClientID},
		}
		setResourceParameters(tokenForm, resource)
		response, tokenErr := m.tokenRequest(pollContext, issuer.TokenEndpoint, tokenForm)
		if tokenErr == nil {
			return m.persistLogin(response)
		}
		var oauthErr *protocolError
		if !errors.As(tokenErr, &oauthErr) {
			return Token{}, tokenErr
		}
		switch oauthErr.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return Token{}, errors.New("device authorization was denied or expired")
		}
	}
}

// LoginPKCE completes Authorization Code with PKCE using a loopback redirect.
func (m *Manager) LoginPKCE(ctx context.Context, scopes []string) (Token, error) {
	resource, issuer, err := m.metadata(ctx)
	if err != nil {
		return Token{}, err
	}
	if issuer.AuthorizationEndpoint == "" {
		return Token{}, errors.New("authorization endpoint is unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Token{}, fmt.Errorf("open OAuth loopback listener: %w", err)
	}
	defer listener.Close()
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	verifier := randomURLValue(48)
	challengeDigest := sha256.Sum256([]byte(verifier))
	state := randomURLValue(24)
	authorizationURL, err := url.Parse(issuer.AuthorizationEndpoint)
	if err != nil {
		return Token{}, err
	}
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", resource.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challengeDigest[:]))
	query.Set("code_challenge_method", "S256")
	query.Set("state", state)
	setResourceParameters(query, resource)
	scopes = effectiveScopes(scopes, resource.ScopesSupported)
	if len(scopes) != 0 {
		query.Set("scope", strings.Join(scopes, " "))
	}
	authorizationURL.RawQuery = query.Encode()

	type callback struct {
		code string
		err  error
	}
	result := make(chan callback, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/callback" || request.URL.Query().Get("state") != state {
			http.Error(writer, "invalid OAuth callback", http.StatusBadRequest)
			return
		}
		if protocolFailure := request.URL.Query().Get("error"); protocolFailure != "" {
			result <- callback{err: errors.New("authorization was denied")}
			http.Error(writer, "authorization failed; return to the terminal", http.StatusBadRequest)
			return
		}
		code := request.URL.Query().Get("code")
		if code == "" {
			http.Error(writer, "authorization code is missing", http.StatusBadRequest)
			return
		}
		result <- callback{code: code}
		_, _ = io.WriteString(writer, "Login complete. You can close this window.")
	})
	go func() { _ = server.Serve(listener) }()
	fmt.Fprintf(m.out, "Open this URL to log in:\n%s\n", authorizationURL.String())
	_ = openBrowser(authorizationURL.String())

	waitContext, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var completed callback
	select {
	case completed = <-result:
	case <-waitContext.Done():
		_ = server.Shutdown(context.Background())
		return Token{}, errors.New("OAuth login timed out or was cancelled")
	}
	_ = server.Shutdown(context.Background())
	if completed.err != nil {
		return Token{}, completed.err
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {completed.code},
		"redirect_uri":  {redirectURI},
		"client_id":     {resource.ClientID},
		"code_verifier": {verifier},
	}
	setResourceParameters(tokenForm, resource)
	response, err := m.tokenRequest(ctx, issuer.TokenEndpoint, tokenForm)
	if err != nil {
		return Token{}, err
	}
	return m.persistLogin(response)
}

// Logout best-effort revokes the refresh token and always removes it locally.
func (m *Manager) Logout(ctx context.Context) error {
	refreshToken, err := keyring.Get(m.keyringService, m.account())
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("read refresh token from OS keyring: %w", err)
	}
	var revokeErr error
	if refreshToken != "" {
		resource, issuer, metadataErr := m.metadata(ctx)
		if metadataErr == nil && issuer.RevocationEndpoint != "" {
			_, status, postErr := m.postForm(ctx, issuer.RevocationEndpoint, url.Values{
				"token": {refreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {resource.ClientID},
			})
			if postErr != nil || status < 200 || status >= 300 {
				revokeErr = errors.New("remote token revocation failed")
			}
		}
	}
	deleteErr := keyring.Delete(m.keyringService, m.account())
	if errors.Is(deleteErr, keyring.ErrNotFound) {
		deleteErr = nil
	}
	m.mu.Lock()
	m.token = Token{}
	m.mu.Unlock()
	return errors.Join(revokeErr, deleteErr)
}

func (m *Manager) persistLogin(response tokenResponse) (Token, error) {
	if response.RefreshToken == "" {
		return Token{}, errors.New("authorization server did not issue a refresh token")
	}
	if err := keyring.Set(m.keyringService, m.account(), response.RefreshToken); err != nil {
		return Token{}, fmt.Errorf("store refresh token in OS keyring: %w", err)
	}
	token := tokenFromResponse(response)
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()
	return token, nil
}

func (m *Manager) metadata(ctx context.Context) (ResourceMetadata, IssuerMetadata, error) {
	var resource ResourceMetadata
	if err := m.getJSON(ctx, m.server+"/.well-known/oauth-protected-resource", &resource); err != nil {
		return resource, IssuerMetadata{}, err
	}
	if len(resource.AuthorizationServers) != 1 || resource.ClientID == "" || strings.TrimSuffix(resource.Resource, "/") != m.server {
		return resource, IssuerMetadata{}, errors.New("protected-resource metadata is incomplete")
	}
	issuerURL := strings.TrimSuffix(resource.AuthorizationServers[0], "/")
	if err := validateOAuthEndpoint(issuerURL); err != nil {
		return resource, IssuerMetadata{}, fmt.Errorf("authorization server metadata: %w", err)
	}
	var issuer IssuerMetadata
	if err := m.getJSON(ctx, issuerURL+"/.well-known/openid-configuration", &issuer); err != nil {
		return resource, issuer, err
	}
	if strings.TrimSuffix(issuer.Issuer, "/") != issuerURL || issuer.TokenEndpoint == "" {
		return resource, issuer, errors.New("authorization-server metadata is inconsistent")
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": issuer.AuthorizationEndpoint,
		"token_endpoint":         issuer.TokenEndpoint,
		"device_endpoint":        issuer.DeviceAuthorizationEndpoint,
		"revocation_endpoint":    issuer.RevocationEndpoint,
	} {
		if endpoint == "" && name != "token_endpoint" {
			continue
		}
		if err := validateOAuthEndpoint(endpoint); err != nil {
			return resource, issuer, fmt.Errorf("%s: %w", name, err)
		}
	}
	return resource, issuer, nil
}

func (m *Manager) getJSON(ctx context.Context, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := m.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("metadata endpoint returned status %d", response.StatusCode)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return errors.New("metadata endpoint returned invalid JSON")
	}
	return nil
}

type protocolError struct {
	Code string
}

func (e *protocolError) Error() string { return e.Code }

func (m *Manager) tokenRequest(ctx context.Context, endpoint string, form url.Values) (tokenResponse, error) {
	body, status, err := m.postForm(ctx, endpoint, form)
	if err != nil {
		return tokenResponse{}, err
	}
	var response tokenResponse
	if json.Unmarshal(body, &response) != nil {
		return tokenResponse{}, errors.New("authorization server returned invalid JSON")
	}
	if status < 200 || status >= 300 || response.Error != "" {
		code := response.Error
		if code == "" {
			code = "token_request_failed"
		}
		return tokenResponse{}, &protocolError{Code: code}
	}
	if response.AccessToken == "" || !strings.EqualFold(response.TokenType, "Bearer") {
		return tokenResponse{}, errors.New("authorization server returned an invalid token")
	}
	if _, err := expiresIn(response.ExpiresIn); err != nil {
		return tokenResponse{}, err
	}
	return response, nil
}

func (m *Manager) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := m.http.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	return body, response.StatusCode, err
}

func readLimited(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxOAuthPayload+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxOAuthPayload {
		return nil, errors.New("OAuth response exceeds 1 MiB")
	}
	return body, nil
}

func tokenFromResponse(response tokenResponse) Token {
	seconds, _ := expiresIn(response.ExpiresIn)
	return Token{AccessToken: response.AccessToken, ExpiresAt: time.Now().Add(time.Duration(seconds) * time.Second)}
}

func expiresIn(raw json.RawMessage) (int64, error) {
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		value, parseErr := strconv.ParseInt(number.String(), 10, 64)
		if parseErr == nil && value > 0 && value <= 24*60*60 {
			return value, nil
		}
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		value, parseErr := strconv.ParseInt(text, 10, 64)
		if parseErr == nil && value > 0 && value <= 24*60*60 {
			return value, nil
		}
	}
	return 0, errors.New("authorization server returned invalid expires_in")
}

func (m *Manager) account() string {
	digest := sha256.Sum256([]byte(m.server))
	return hex.EncodeToString(digest[:16])
}

func randomURLValue(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func effectiveScopes(requested, supported []string) []string {
	if len(requested) != 0 {
		return normalizeScopes(append([]string{"openid", "offline_access"}, requested...))
	}
	defaults := []string{"openid", "offline_access"}
	for _, scope := range supported {
		if scope == "email" || scope == "profile" {
			defaults = append(defaults, scope)
		}
	}
	return normalizeScopes(defaults)
}

// setResourceParameters emits the provider-compatible audience/resource
// parameters advertised by cli-gateway protected-resource metadata.
func setResourceParameters(values url.Values, resource ResourceMetadata) {
	switch resource.ResourceParameter {
	case "", "both":
		values.Set("resource", resource.Resource)
		if resource.Audience != "" {
			values.Set("audience", resource.Audience)
		}
	case "audience":
		values.Set("audience", resource.Audience)
	case "resource":
		values.Set("resource", resource.Resource)
	case "none":
	}
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		for _, item := range strings.Fields(scope) {
			if _, exists := seen[item]; exists {
				continue
			}
			seen[item] = struct{}{}
			normalized = append(normalized, item)
		}
	}
	return normalized
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	return command.Start()
}

// OpenBrowser opens one validated authorization URL using the operating system.
func OpenBrowser(target string) error {
	if err := validateOAuthEndpoint(target); err != nil {
		return err
	}
	return openBrowser(target)
}

func validateServerOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("OAuth server must be an absolute origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("OAuth server must not contain userinfo, path, query, or fragment")
	}
	if err := validateOAuthEndpoint(parsed.String()); err != nil {
		return "", err
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func validateOAuthEndpoint(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("OAuth endpoint must be an absolute URL without userinfo or fragment")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("OAuth endpoint must use HTTPS except on loopback")
}

func secureHTTPClient(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
