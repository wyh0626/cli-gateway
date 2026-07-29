// devissuer is a local-only ES256 OAuth/OIDC issuer for cli-gateway integration
// testing. It intentionally has no user authentication and must never be used
// outside a developer workstation or isolated test environment.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const maxFormBytes = 64 << 10

type authorizationCode struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Scopes      []string
	ExpiresAt   time.Time
}

type deviceAuthorization struct {
	ClientID   string
	UserCode   string
	Scopes     []string
	ExpiresAt  time.Time
	Authorized bool
}

type refreshGrant struct {
	ClientID  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
}

type issuerServer struct {
	issuer           string
	audience         string
	clientID         string
	gatewayResource  string
	signingKey       jwk.Key
	keySet           jwk.Set
	kid              string
	mu               sync.Mutex
	authorization    map[string]authorizationCode
	devices          map[string]*deviceAuthorization
	refreshTokens    map[string]refreshGrant
	userCodeToDevice map[string]string
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:18080", "token issuer")
	audience := flag.String("audience", "cli-gateway", "access-token audience")
	clientID := flag.String("client-id", "cg-cli", "OAuth public client ID")
	gatewayResource := flag.String("resource", "http://127.0.0.1:18082", "cli-gateway protected resource")
	flag.Parse()

	server, err := newIssuerServer(*issuer, *audience, *clientID, *gatewayResource)
	if err != nil {
		log.Fatal(err)
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("development issuer listening on %s (issuer=%s, client_id=%s, kid=%s)", *listen, *issuer, *clientID, server.kid)
	log.Fatal(httpServer.ListenAndServe())
}

func newIssuerServer(issuer, audience, clientID, gatewayResource string) (*issuerServer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	encodedPublic, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encodedPublic)
	kid := hex.EncodeToString(digest[:8])
	privateJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, err
	}
	if err := privateJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := privateJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, err
	}
	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		return nil, err
	}
	_ = publicJWK.Set(jwk.KeyIDKey, kid)
	_ = publicJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = publicJWK.Set(jwk.KeyUsageKey, "sig")
	set := jwk.NewSet()
	if err := set.AddKey(publicJWK); err != nil {
		return nil, err
	}
	return &issuerServer{
		issuer:           strings.TrimSuffix(issuer, "/"),
		audience:         audience,
		clientID:         clientID,
		gatewayResource:  strings.TrimSuffix(gatewayResource, "/"),
		signingKey:       privateJWK,
		keySet:           set,
		kid:              kid,
		authorization:    make(map[string]authorizationCode),
		devices:          make(map[string]*deviceAuthorization),
		refreshTokens:    make(map[string]refreshGrant),
		userCodeToDevice: make(map[string]string),
	}, nil
}

func (s *issuerServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "kid": s.kid})
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks.json", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, s.keySet)
	})
	mux.HandleFunc("GET /oauth2/auth", s.authorize)
	mux.HandleFunc("POST /oauth2/device/auth", s.startDeviceAuthorization)
	mux.HandleFunc("GET /device", s.devicePage)
	mux.HandleFunc("POST /device", s.activateDevice)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("POST /oauth2/revoke", s.revoke)
	mux.HandleFunc("GET /token", s.developmentToken)
	return http.MaxBytesHandler(mux, maxFormBytes)
}

func (s *issuerServer) discovery(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth2/auth",
		"token_endpoint":                        s.issuer + "/oauth2/token",
		"device_authorization_endpoint":         s.issuer + "/oauth2/device/auth",
		"revocation_endpoint":                   s.issuer + "/oauth2/revoke",
		"jwks_uri":                              s.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "offline_access", "demo:read", "demo:write", "demo:destroy"},
	})
}

func (s *issuerServer) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	if query.Get("response_type") != "code" || query.Get("client_id") != s.clientID ||
		query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" ||
		!validLoopbackRedirect(redirectURI) || !s.validResource(query.Get("resource")) {
		s.redirectOAuthError(writer, request, redirectURI, state, "invalid_request")
		return
	}
	scopes, ok := validScopes(query.Get("scope"))
	if !ok {
		s.redirectOAuthError(writer, request, redirectURI, state, "invalid_scope")
		return
	}
	code := randomValue(32)
	s.mu.Lock()
	s.authorization[code] = authorizationCode{
		ClientID: query.Get("client_id"), RedirectURI: redirectURI,
		Challenge: query.Get("code_challenge"), Scopes: scopes, ExpiresAt: time.Now().Add(2 * time.Minute),
	}
	s.cleanupLocked(time.Now())
	s.mu.Unlock()
	redirect, _ := url.Parse(redirectURI)
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", state)
	redirect.RawQuery = values.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

func (s *issuerServer) startDeviceAuthorization(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil || request.Form.Get("client_id") != s.clientID || !s.validResource(request.Form.Get("resource")) {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	scopes, ok := validScopes(request.Form.Get("scope"))
	if !ok {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_scope")
		return
	}
	deviceCode := randomValue(32)
	userCode := strings.ToUpper(hex.EncodeToString(randomBytes(4)))
	s.mu.Lock()
	s.devices[deviceCode] = &deviceAuthorization{
		ClientID: s.clientID, UserCode: userCode, Scopes: scopes, ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	s.userCodeToDevice[userCode] = deviceCode
	s.cleanupLocked(time.Now())
	s.mu.Unlock()
	verification := s.issuer + "/device"
	writeJSON(writer, http.StatusOK, map[string]any{
		"device_code": deviceCode, "user_code": userCode, "verification_uri": verification,
		"verification_uri_complete": verification + "?user_code=" + url.QueryEscape(userCode),
		"expires_in":                600, "interval": 2,
	})
}

func (s *issuerServer) devicePage(writer http.ResponseWriter, request *http.Request) {
	userCode := html.EscapeString(request.URL.Query().Get("user_code"))
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	_, _ = fmt.Fprintf(writer, `<!doctype html><meta charset="utf-8"><title>cli-gateway development login</title>
<style>body{font:16px system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem}input,button{font:inherit;padding:.6rem}</style>
<h1>Development device login</h1><p>This issuer is local-only and performs no user authentication.</p>
<form method="post"><label>Code <input name="user_code" required value="%s"></label> <button>Approve</button></form>`, userCode)
}

func (s *issuerServer) activateDevice(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	userCode := strings.ToUpper(strings.TrimSpace(request.Form.Get("user_code")))
	s.mu.Lock()
	deviceCode, exists := s.userCodeToDevice[userCode]
	grant := s.devices[deviceCode]
	if exists && grant != nil && time.Now().Before(grant.ExpiresAt) {
		grant.Authorized = true
	}
	s.mu.Unlock()
	if !exists || grant == nil {
		http.Error(writer, "unknown or expired device code", http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(writer, "Device approved. Return to the CLI.")
}

func (s *issuerServer) token(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil || request.Form.Get("client_id") != s.clientID {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	switch request.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeAuthorizationCode(writer, request)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.exchangeDeviceCode(writer, request)
	case "refresh_token":
		s.exchangeRefreshToken(writer, request)
	default:
		writeOAuthError(writer, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *issuerServer) exchangeAuthorizationCode(writer http.ResponseWriter, request *http.Request) {
	code := request.Form.Get("code")
	s.mu.Lock()
	grant, exists := s.authorization[code]
	delete(s.authorization, code)
	s.mu.Unlock()
	if !exists || time.Now().After(grant.ExpiresAt) || grant.ClientID != request.Form.Get("client_id") ||
		grant.RedirectURI != request.Form.Get("redirect_uri") || !validVerifier(grant.Challenge, request.Form.Get("code_verifier")) ||
		!s.validResource(request.Form.Get("resource")) {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_grant")
		return
	}
	s.issueTokenResponse(writer, grant.ClientID, "developer@example.com", grant.Scopes, true)
}

func (s *issuerServer) exchangeDeviceCode(writer http.ResponseWriter, request *http.Request) {
	deviceCode := request.Form.Get("device_code")
	s.mu.Lock()
	grant := s.devices[deviceCode]
	if grant != nil && grant.Authorized {
		delete(s.devices, deviceCode)
		delete(s.userCodeToDevice, grant.UserCode)
	}
	s.mu.Unlock()
	switch {
	case grant == nil || time.Now().After(grant.ExpiresAt) || grant.ClientID != request.Form.Get("client_id"):
		writeOAuthError(writer, http.StatusBadRequest, "expired_token")
	case !grant.Authorized:
		writeOAuthError(writer, http.StatusBadRequest, "authorization_pending")
	default:
		s.issueTokenResponse(writer, grant.ClientID, "developer@example.com", grant.Scopes, true)
	}
}

func (s *issuerServer) exchangeRefreshToken(writer http.ResponseWriter, request *http.Request) {
	token := request.Form.Get("refresh_token")
	s.mu.Lock()
	grant, exists := s.refreshTokens[token]
	delete(s.refreshTokens, token)
	s.mu.Unlock()
	if !exists || time.Now().After(grant.ExpiresAt) || grant.ClientID != request.Form.Get("client_id") || !s.validResource(request.Form.Get("resource")) {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_grant")
		return
	}
	s.issueTokenResponse(writer, grant.ClientID, grant.Subject, grant.Scopes, true)
}

func (s *issuerServer) revoke(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil || request.Form.Get("client_id") != s.clientID {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	s.mu.Lock()
	delete(s.refreshTokens, request.Form.Get("token"))
	s.mu.Unlock()
	writer.WriteHeader(http.StatusOK)
}

func (s *issuerServer) developmentToken(writer http.ResponseWriter, request *http.Request) {
	subject := request.URL.Query().Get("sub")
	if subject == "" {
		subject = "loadtest-user"
	}
	scopes, ok := validScopes(request.URL.Query().Get("scope"))
	if !ok {
		writeOAuthError(writer, http.StatusBadRequest, "invalid_scope")
		return
	}
	invoker := request.URL.Query().Get("invoker")
	if invoker == "" {
		invoker = "human"
	}
	accessToken, err := s.signAccessToken(subject, "cli-gateway-loadtest", invoker, scopes)
	if err != nil {
		http.Error(writer, "token signing failed", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600})
}

func (s *issuerServer) issueTokenResponse(writer http.ResponseWriter, clientID, subject string, scopes []string, withRefresh bool) {
	accessToken, err := s.signAccessToken(subject, clientID, "human", scopes)
	if err != nil {
		http.Error(writer, "token signing failed", http.StatusInternalServerError)
		return
	}
	response := map[string]any{
		"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600,
		"scope": strings.Join(scopes, " "),
	}
	if withRefresh {
		refreshToken := randomValue(48)
		s.mu.Lock()
		s.refreshTokens[refreshToken] = refreshGrant{
			ClientID: clientID, Subject: subject, Scopes: append([]string(nil), scopes...), ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		s.cleanupLocked(time.Now())
		s.mu.Unlock()
		response["refresh_token"] = refreshToken
	}
	writeJSON(writer, http.StatusOK, response)
}

func (s *issuerServer) signAccessToken(subject, clientID, invoker string, scopes []string) (string, error) {
	now := time.Now().UTC()
	token, err := jwt.NewBuilder().Issuer(s.issuer).Audience([]string{s.audience}).Subject(subject).
		IssuedAt(now).NotBefore(now.Add(-time.Second)).Expiration(now.Add(time.Hour)).
		Claim("scope", scopes).Claim("invoker", invoker).Claim("client_id", clientID).
		Claim("sid", randomValue(18)).Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, s.signingKey))
	return string(signed), err
}

func (s *issuerServer) validResource(resource string) bool {
	resource = strings.TrimSuffix(resource, "/")
	return resource == s.gatewayResource || resource == s.gatewayResource+"/mcp"
}

func (s *issuerServer) redirectOAuthError(writer http.ResponseWriter, request *http.Request, redirectURI, state, code string) {
	if !validLoopbackRedirect(redirectURI) {
		writeOAuthError(writer, http.StatusBadRequest, code)
		return
	}
	redirect, _ := url.Parse(redirectURI)
	values := redirect.Query()
	values.Set("error", code)
	values.Set("state", state)
	redirect.RawQuery = values.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

func (s *issuerServer) cleanupLocked(now time.Time) {
	for code, grant := range s.authorization {
		if now.After(grant.ExpiresAt) {
			delete(s.authorization, code)
		}
	}
	for code, grant := range s.devices {
		if now.After(grant.ExpiresAt) {
			delete(s.devices, code)
			delete(s.userCodeToDevice, grant.UserCode)
		}
	}
	for token, grant := range s.refreshTokens {
		if now.After(grant.ExpiresAt) {
			delete(s.refreshTokens, token)
		}
	}
}

func validScopes(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return []string{"demo:read", "demo:write", "demo:destroy"}, true
	}
	allowed := map[string]struct{}{
		"openid": {}, "offline_access": {}, "demo:read": {}, "demo:write": {}, "demo:destroy": {},
	}
	seen := make(map[string]struct{})
	var scopes []string
	for _, scope := range strings.Fields(raw) {
		if _, exists := allowed[scope]; !exists {
			return nil, false
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes, true
}

func validLoopbackRedirect(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Port() == "" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func validVerifier(challenge, verifier string) bool {
	if verifier == "" {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(actual)) == 1
}

func randomBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return value
}

func randomValue(size int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(size))
}

func writeOAuthError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]string{"error": code})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
