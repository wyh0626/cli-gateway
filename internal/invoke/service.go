// Package invoke contains the transport-neutral command execution pipeline.
package invoke

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/wyh0626/cli-gateway/internal/breaker"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/policy"
	"github.com/wyh0626/cli-gateway/internal/upstream"
)

const (
	maxErrorBytes = 64 << 10
)

// IdentitySigner signs the trusted identity propagated to a downstream API.
type IdentitySigner interface {
	Sign(model.Invocation) (string, error)
}

// AdmissionController bounds rate and in-flight work before downstream
// credentials or upstream connections are consumed.
type AdmissionController interface {
	Acquire(context.Context, model.Invocation) (release func(), err error)
}

// Service executes validated commands once, without retries.
type Service struct {
	authorizer model.OutboundAuthorizer
	admission  AdmissionController
	clients    sync.Map
}

// NewService constructs an invocation service.
func NewService(signer IdentitySigner) *Service {
	return &Service{authorizer: legacyAuthorizer{signer: signer}}
}

// NewServiceWithAuthorizer constructs an invocation service with a
// generation-scoped downstream credential broker.
func NewServiceWithAuthorizer(authorizer model.OutboundAuthorizer) *Service {
	return &Service{authorizer: authorizer}
}

// NewServiceWithAdmission adds generation-scoped rate and concurrency control.
func NewServiceWithAdmission(authorizer model.OutboundAuthorizer, admission AdmissionController) *Service {
	return &Service{authorizer: authorizer, admission: admission}
}

// Invoke implements model.InvocationService.
func (s *Service) Invoke(ctx context.Context, invocation model.Invocation) (*model.Execution, error) {
	arguments, validationErr := validateArguments(invocation.Command, invocation.Args)
	if validationErr != nil {
		validationErr.TraceID = invocation.TraceID
		return nil, validationErr
	}
	if authorizationErr := policy.Authorize(invocation.Principal, invocation.Invoker, invocation.Command, invocation.AIMaxRisk, invocation.Confirmed); authorizationErr != nil {
		authorizationErr.TraceID = invocation.TraceID
		return nil, authorizationErr
	}
	request, requestErr := buildRequest(ctx, invocation, arguments)
	if requestErr != nil {
		requestErr.TraceID = invocation.TraceID
		return nil, requestErr
	}
	release := func() {}
	if s.admission != nil {
		acquiredRelease, err := s.admission.Acquire(ctx, invocation)
		if err != nil {
			var apiErr *httpx.APIError
			if errors.As(err, &apiErr) && apiErr.TraceID == "" {
				apiErr.TraceID = invocation.TraceID
			}
			return nil, err
		}
		release = acquiredRelease
	}
	releaseOnReturn := true
	defer func() {
		if releaseOnReturn {
			release()
		}
	}()
	if s.authorizer == nil {
		return nil, &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream credential manager is unavailable", TraceID: invocation.TraceID}
	}
	endpoint, clientErr := s.client(invocation.Command)
	if clientErr != nil {
		return nil, &httpx.APIError{
			Status: http.StatusInternalServerError, Code: "E_INTERNAL",
			Message: "upstream transport could not be initialized", TraceID: invocation.TraceID, Cause: clientErr,
		}
	}
	if allowed, retryAfter := endpoint.breaker.Allow(); !allowed {
		return nil, &httpx.APIError{
			Status: http.StatusServiceUnavailable, Code: "E_UPSTREAM_CIRCUIT_OPEN",
			Message: "upstream dependency is temporarily unavailable", TraceID: invocation.TraceID, RetryAfter: retryAfter,
		}
	}
	if err := s.authorizer.Authorize(ctx, request, invocation); err != nil {
		endpoint.breaker.Ignore()
		var apiErr *httpx.APIError
		if errors.As(err, &apiErr) {
			if apiErr.TraceID == "" {
				apiErr.TraceID = invocation.TraceID
			}
			return nil, apiErr
		}
		return nil, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_DOWNSTREAM_AUTH", Message: "downstream credential could not be obtained", TraceID: invocation.TraceID, Cause: err}
	}

	response, err := endpoint.client.Do(request)
	if err != nil {
		endpoint.breaker.Failure()
		return nil, upstreamError(invocation.TraceID, err)
	}
	if response.StatusCode >= http.StatusInternalServerError {
		endpoint.breaker.Failure()
	} else {
		endpoint.breaker.Success()
	}
	if response.StatusCode == http.StatusUnauthorized {
		if invalidator, ok := s.authorizer.(model.CredentialInvalidator); ok {
			invalidator.Invalidate(invocation)
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBytes))
		_ = response.Body.Close()
		return nil, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_UPSTREAM", Message: "upstream returned an error", TraceID: invocation.TraceID, UpstreamStatus: response.StatusCode}
	}
	body := response.Body
	if invocation.Command.Streaming {
		body = newIdleTimeoutBody(body, 15*time.Minute)
	}
	releaseOnReturn = false
	return &model.Execution{
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Header:      response.Header.Clone(),
		Body:        &releaseBody{ReadCloser: body, release: release},
		Streaming:   invocation.Command.Streaming,
	}, nil
}

type releaseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

type idleTimeoutBody struct {
	body      io.ReadCloser
	timeout   time.Duration
	timer     *time.Timer
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	closeErr  error
}

func newIdleTimeoutBody(body io.ReadCloser, timeout time.Duration) io.ReadCloser {
	wrapped := &idleTimeoutBody{body: body, timeout: timeout}
	wrapped.timer = time.AfterFunc(timeout, func() { _ = wrapped.Close() })
	return wrapped
}

func (b *idleTimeoutBody) Read(data []byte) (int, error) {
	count, err := b.body.Read(data)
	b.mu.Lock()
	if !b.closed && count > 0 {
		b.timer.Reset(b.timeout)
	}
	b.mu.Unlock()
	return count, err
}

func (b *idleTimeoutBody) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		if b.timer != nil {
			b.timer.Stop()
		}
		b.mu.Unlock()
		b.closeErr = b.body.Close()
	})
	return b.closeErr
}

type legacyAuthorizer struct {
	signer IdentitySigner
}

func (a legacyAuthorizer) Authorize(_ context.Context, request *http.Request, invocation model.Invocation) error {
	switch invocation.Command.DownstreamAuth {
	case model.DownstreamBearerPassthrough:
		if invocation.BearerToken == "" {
			return &httpx.APIError{Status: http.StatusBadGateway, Code: "E_DOWNSTREAM_AUTH", Message: "inbound bearer is unavailable"}
		}
		request.Header.Set("Authorization", "Bearer "+invocation.BearerToken)
		return nil
	case model.DownstreamSignedIdentity:
		if a.signer == nil {
			return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "identity signer is unavailable"}
		}
		identityToken, err := a.signer.Sign(invocation)
		if err != nil {
			return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "identity signing failed", Cause: err}
		}
		request.Header.Set("X-Cli-Gateway-Identity", identityToken)
		return nil
	default:
		return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "downstream credential mode is not configured"}
	}
}

type endpointClient struct {
	client  *http.Client
	breaker *breaker.Breaker
}

func (s *Service) client(command *model.CompiledCommand) (*endpointClient, error) {
	key := fmt.Sprintf("%s|%s|%t|%t|%t|%s|%s|%s|%s", command.Domain, command.Upstream.Host, command.AllowLocal, command.TLS.InsecureSkipVerify, command.Streaming, command.Timeout, command.TLS.CAFile, command.TLS.ClientCertFile, command.TLS.ClientKeyFile)
	if existing, ok := s.clients.Load(key); ok {
		return existing.(*endpointClient), nil
	}
	client, err := upstream.NewClientWithTLS(command.Timeout, command.AllowLocal, command.TLS)
	if command.Streaming {
		client, err = upstream.NewStreamingClientWithTLS(command.Timeout, command.AllowLocal, command.TLS)
	}
	if err != nil {
		return nil, err
	}
	created := &endpointClient{
		client:  client,
		breaker: breaker.New(5, 30*time.Second),
	}
	actual, _ := s.clients.LoadOrStore(key, created)
	return actual.(*endpointClient), nil
}

// Preflight initializes every generation-scoped transport before publication.
func (s *Service) Preflight(snapshot *manifest.Snapshot) error {
	if snapshot == nil {
		return errors.New("runtime snapshot is required")
	}
	for _, key := range snapshot.CommandKeys {
		if _, err := s.client(snapshot.Commands[key]); err != nil {
			return fmt.Errorf("command %s transport: %w", key, err)
		}
	}
	return nil
}

// CloseIdleConnections releases idle transports owned by this service. Active
// response bodies remain valid until their adapter closes them.
func (s *Service) CloseIdleConnections() {
	s.clients.Range(func(_, value any) bool {
		value.(*endpointClient).client.CloseIdleConnections()
		return true
	})
}

func upstreamError(traceID string, err error) *httpx.APIError {
	code := "E_UPSTREAM_UNREACHABLE"
	message := "upstream is unreachable"
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		code = "E_UPSTREAM_TIMEOUT"
		message = "upstream request timed out"
	}
	return &httpx.APIError{Status: http.StatusBadGateway, Code: code, Message: message, TraceID: traceID, Cause: err}
}
