// Package api is the authenticated HTTP adapter for cli-gateway.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBody = 4 << 20

// Error is a safe error returned by cli-gateway.
type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

func (e *Error) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Client calls one fixed cli-gateway origin and never follows redirects.
type Client struct {
	server    string
	token     string
	invoker   string
	userAgent string
	http      *http.Client
}

// Options configure a Client.
type Options struct {
	Server    string
	Token     string
	Invoker   string
	CAFile    string
	UserAgent string
	HTTP      *http.Client
}

// Stream is a successful response whose body must be closed by the caller.
type Stream struct {
	Status      int
	ContentType string
	Body        io.ReadCloser
}

// DownstreamAuthorizationStart contains the URL a user must open once.
type DownstreamAuthorizationStart struct {
	Domain           string    `json:"domain"`
	AuthorizationURL string    `json:"authorization_url"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// DownstreamAuthorizationStatus reports whether the browser grant completed.
type DownstreamAuthorizationStatus struct {
	Domain     string    `json:"domain"`
	Authorized bool      `json:"authorized"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// New constructs a safe client.
func New(options Options) (*Client, error) {
	httpClient := options.HTTP
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		if options.CAFile != "" {
			pem, err := os.ReadFile(options.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read CA file: %w", err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("load system roots: %w", err)
			}
			if roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("CA file contains no certificates")
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		}
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		copied := *httpClient
		copied.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		if copied.Timeout == 0 {
			copied.Timeout = 60 * time.Second
		}
		httpClient = &copied
	}
	userAgent := options.UserAgent
	if userAgent == "" {
		userAgent = "cli-gateway-cli/dev"
	}
	return &Client{
		server: strings.TrimSuffix(options.Server, "/"), token: options.Token,
		invoker: options.Invoker, userAgent: userAgent, http: httpClient,
	}, nil
}

// Manifest fetches the caller-filtered command tree.
func (c *Client) Manifest(ctx context.Context, etag string) ([]byte, string, bool, error) {
	request, err := c.request(ctx, http.MethodGet, "/manifest", nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, "", false, fmt.Errorf("request manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return nil, response.Header.Get("ETag"), true, nil
	}
	body, err := readLimited(response.Body)
	if err != nil {
		return nil, "", false, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", false, decodeError(response.StatusCode, body)
	}
	return body, response.Header.Get("ETag"), false, nil
}

// Execute invokes one command exactly once.
func (c *Client) Execute(ctx context.Context, domain, command string, args map[string]any, confirmed bool) ([]byte, error) {
	stream, err := c.ExecuteStream(ctx, domain, command, args, confirmed)
	if err != nil {
		return nil, err
	}
	defer stream.Body.Close()
	responseBody, err := readLimited(stream.Body)
	if err != nil {
		return nil, err
	}
	return responseBody, nil
}

// ExecuteStream invokes one command and leaves the successful body open.
func (c *Client) ExecuteStream(ctx context.Context, domain, command string, args map[string]any, confirmed bool) (*Stream, error) {
	body, err := json.Marshal(struct {
		Args map[string]any `json:"args"`
	}{Args: args})
	if err != nil {
		return nil, fmt.Errorf("encode arguments: %w", err)
	}
	path := "/exec/" + url.PathEscape(domain) + "/" + url.PathEscape(command)
	request, err := c.request(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if confirmed {
		request.Header.Set("X-Cli-Gateway-Confirm", "true")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("execute command; outcome may be unknown: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		responseBody, readErr := readLimited(response.Body)
		if readErr != nil {
			return nil, readErr
		}
		return nil, decodeError(response.StatusCode, responseBody)
	}
	return &Stream{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: response.Body}, nil
}

// WhoAmI returns the gateway's non-sensitive authenticated identity document.
func (c *Client) WhoAmI(ctx context.Context) ([]byte, error) {
	request, err := c.request(ctx, http.MethodGet, "/whoami", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request identity: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeError(response.StatusCode, body)
	}
	return body, nil
}

// BeginDownstreamAuthorization creates one user-bound downstream OAuth state.
func (c *Client) BeginDownstreamAuthorization(ctx context.Context, domain string) (DownstreamAuthorizationStart, error) {
	request, err := c.request(ctx, http.MethodPost, "/oauth/downstream/"+url.PathEscape(domain)+"/authorize", nil)
	if err != nil {
		return DownstreamAuthorizationStart{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return DownstreamAuthorizationStart{}, fmt.Errorf("start downstream authorization: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	if err != nil {
		return DownstreamAuthorizationStart{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return DownstreamAuthorizationStart{}, decodeError(response.StatusCode, body)
	}
	var start DownstreamAuthorizationStart
	if err := json.Unmarshal(body, &start); err != nil || start.AuthorizationURL == "" || start.Domain != domain {
		return DownstreamAuthorizationStart{}, errors.New("gateway returned an invalid downstream authorization response")
	}
	return start, nil
}

// DownstreamAuthorizationStatus checks browser-flow completion.
func (c *Client) DownstreamAuthorizationStatus(ctx context.Context, domain string) (DownstreamAuthorizationStatus, error) {
	request, err := c.request(ctx, http.MethodGet, "/oauth/downstream/"+url.PathEscape(domain)+"/status", nil)
	if err != nil {
		return DownstreamAuthorizationStatus{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return DownstreamAuthorizationStatus{}, fmt.Errorf("check downstream authorization: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	if err != nil {
		return DownstreamAuthorizationStatus{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return DownstreamAuthorizationStatus{}, decodeError(response.StatusCode, body)
	}
	var status DownstreamAuthorizationStatus
	if err := json.Unmarshal(body, &status); err != nil || status.Domain != domain {
		return DownstreamAuthorizationStatus{}, errors.New("gateway returned an invalid downstream authorization status")
	}
	return status, nil
}

// DisconnectDownstreamAuthorization removes one stored user grant.
func (c *Client) DisconnectDownstreamAuthorization(ctx context.Context, domain string) error {
	request, err := c.request(ctx, http.MethodDelete, "/oauth/downstream/"+url.PathEscape(domain), nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("disconnect downstream authorization: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeError(response.StatusCode, body)
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.server+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	if strings.EqualFold(c.invoker, "ai") {
		request.Header.Set("X-Cli-Gateway-Invoker", "ai")
	}
	request.Header.Set("X-Cli-Gateway-Trace-Id", traceID())
	request.Header.Set("User-Agent", c.userAgent)
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func traceID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return strings.Repeat("0", 32)
	}
	return hex.EncodeToString(value)
}

func readLimited(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, maxResponseBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseBody {
		return nil, errors.New("response exceeds 4 MiB")
	}
	return body, nil
}

func decodeError(status int, body []byte) error {
	var apiError Error
	if err := json.Unmarshal(body, &apiError); err != nil || apiError.Code == "" {
		return &Error{Status: status, Code: "E_SERVER", Message: http.StatusText(status)}
	}
	apiError.Status = status
	return &apiError
}
