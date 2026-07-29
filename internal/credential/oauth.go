package credential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/cache"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/upstream"
)

const (
	maxTokenResponse            = 64 << 10
	clientSecretBasicAuthMethod = "client_secret_basic"
	clientSecretPostAuthMethod  = "client_secret_post"
)

func tokenHTTPClient(allowLocal bool, tlsConfig model.TLSConfig) (*http.Client, error) {
	return upstream.NewClientWithTLS(10*time.Second, allowLocal, tlsConfig)
}

func (p *oauthProvider) requestToken(ctx context.Context, subjectToken, traceID, traceState string) (cache.Token, bool, error) {
	started := time.Now()
	failed := true
	defer func() {
		if p.observer != nil {
			p.observer.RecordTokenExchange(time.Since(started), failed)
		}
	}()
	if allowed, retryAfter := p.breaker.Allow(); !allowed {
		if p.observer != nil {
			p.observer.RecordCircuitRejection()
		}
		return cache.Token{}, true, &httpx.APIError{
			Status: http.StatusBadGateway, Code: "E_TOKEN_CIRCUIT_OPEN",
			Message: "downstream authorization server is temporarily unavailable", RetryAfter: retryAfter,
		}
	}
	form := make(url.Values)
	switch p.mode {
	case model.DownstreamTokenExchange:
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		form.Set("subject_token", subjectToken)
		form.Set("subject_token_type", p.config.SubjectTokenType)
		form.Set("requested_token_type", p.config.RequestedTokenType)
	case model.DownstreamClientCredentials:
		form.Set("grant_type", "client_credentials")
	default:
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream OAuth mode is invalid"}
	}
	if p.config.Audience != "" {
		form.Set("audience", p.config.Audience)
	}
	if p.config.Resource != "" {
		form.Set("resource", p.config.Resource)
	}
	if len(p.config.Scopes) > 0 {
		form.Set("scope", strings.Join(p.config.Scopes, " "))
	}
	useBasicAuth, err := applyOAuthClientAuthentication(form, *p.config, p.clientSecret)
	if err != nil {
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream OAuth client authentication is invalid", Cause: err}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream token request could not be constructed", Cause: err}
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cli-gateway/token-broker")
	request.Header.Set("X-Cli-Gateway-Trace-Id", traceID)
	request.Header.Set("traceparent", httpx.TraceParent(traceID))
	if traceState != "" {
		request.Header.Set("tracestate", traceState)
	}
	if useBasicAuth {
		request.SetBasicAuth(p.config.ClientID, p.clientSecret)
	}

	response, err := p.http.Do(request)
	if err != nil {
		p.breaker.Failure()
		return cache.Token{}, true, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream authorization server is unavailable", Cause: err}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTokenResponse+1))
	if readErr != nil {
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream token response could not be read", Cause: readErr}
	}
	if len(body) > maxTokenResponse {
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream token response is too large"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		transient := response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		if response.StatusCode >= 500 {
			p.breaker.Failure()
		} else {
			p.breaker.Success()
		}
		return cache.Token{}, transient, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream authorization server rejected the credential request", UpstreamStatus: response.StatusCode}
	}
	p.breaker.Success()
	token, parseErr := parseTokenResponse(body, time.Now())
	if parseErr != nil {
		return cache.Token{}, false, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_TOKEN_EXCHANGE", Message: "downstream authorization server returned an invalid token response", Cause: parseErr}
	}
	failed = false
	return token, false, nil
}

func applyOAuthClientAuthentication(form url.Values, config model.OAuthCredentialConfig, clientSecret string) (bool, error) {
	switch config.TokenEndpointAuth {
	case "", clientSecretBasicAuthMethod:
		return true, nil
	case clientSecretPostAuthMethod:
		form.Set("client_id", config.ClientID)
		form.Set("client_secret", clientSecret)
		return false, nil
	default:
		return false, fmt.Errorf("unsupported token endpoint authentication method %q", config.TokenEndpointAuth)
	}
}

type tokenResponse struct {
	AccessToken string          `json:"access_token"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
}

func parseTokenResponse(body []byte, now time.Time) (cache.Token, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var response tokenResponse
	if err := decoder.Decode(&response); err != nil {
		return cache.Token{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return cache.Token{}, errors.New("token response contains trailing data")
	}
	if response.AccessToken == "" {
		return cache.Token{}, errors.New("access_token is missing")
	}
	if !strings.EqualFold(response.TokenType, "Bearer") {
		return cache.Token{}, errors.New("token_type is not Bearer")
	}

	var expiresAt time.Time
	if len(response.ExpiresIn) > 0 {
		seconds, err := parseExpiresIn(response.ExpiresIn)
		if err != nil {
			return cache.Token{}, err
		}
		if seconds <= 0 || seconds > int64((24*time.Hour)/time.Second) {
			return cache.Token{}, errors.New("expires_in is outside the accepted range")
		}
		expiresAt = now.Add(time.Duration(seconds) * time.Second)
	}
	if jwtExpiry, ok := tokenJWTExpiry(response.AccessToken); ok && (expiresAt.IsZero() || jwtExpiry.Before(expiresAt)) {
		expiresAt = jwtExpiry
	}
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return cache.Token{}, errors.New("token has no valid future expiry")
	}
	return cache.Token{AccessToken: response.AccessToken, ExpiresAt: expiresAt}, nil
}

func parseExpiresIn(raw json.RawMessage) (int64, error) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return strconv.ParseInt(number.String(), 10, 64)
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, errors.New("expires_in must be an integer")
	}
	return strconv.ParseInt(text, 10, 64)
}

func tokenJWTExpiry(raw string) (time.Time, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		ExpiresAt json.Number `json:"exp"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil || claims.ExpiresAt == "" {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(claims.ExpiresAt.String(), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

func (p *oauthProvider) String() string {
	return fmt.Sprintf("%s:%s", p.mode, p.domain)
}
