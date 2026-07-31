// Package mcpadapter exposes runtime commands through authenticated MCP
// Streamable HTTP.
package mcpadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyh0626/cli-gateway/internal/audit"
	gatewayauth "github.com/wyh0626/cli-gateway/internal/auth"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
	runtimecfg "github.com/wyh0626/cli-gateway/internal/runtime"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxToolResult         = 4 << 20
	sessionHeader         = "Mcp-Session-Id"
	protocolVersionHeader = "MCP-Protocol-Version"
	statelessProtocol     = "2026-07-28"
)

const (
	principalExtra = "cli-gateway.principal"
	bearerExtra    = "cli-gateway.bearer"
)

type requestState struct {
	mu        sync.Mutex
	pending   *sessionBundle
	transient *sessionBundle
}

type sessionBundle struct {
	mu        sync.Mutex
	server    *sdk.Server
	lease     *runtimecfg.Lease
	principal model.Principal
	tools     []string
	lastSeen  time.Time
}

// SessionObserver receives bounded MCP session counts.
type SessionObserver interface {
	SetActiveMCPSessions(int64)
	RecordAuthFailure()
}

// Handler is an authenticated MCP Streamable HTTP adapter.
type Handler struct {
	runtime      *runtimecfg.Manager
	verifier     gatewayauth.Verifier
	resourceMeta string
	sessionTTL   time.Duration
	userKey      []byte
	stream       http.Handler
	cancel       context.CancelFunc
	closed       atomic.Bool
	mu           sync.Mutex
	sessions     map[string]*sessionBundle
	transients   map[*sessionBundle]struct{}
	observer     SessionObserver
}

// New constructs the MCP adapter and starts idle-session lease cleanup.
func New(runtimeManager *runtimecfg.Manager, verifier gatewayauth.Verifier, resourceMetadataURL string, logger *slog.Logger, observers ...SessionObserver) (*Handler, error) {
	if runtimeManager == nil || verifier == nil {
		return nil, errors.New("MCP runtime and verifier are required")
	}
	userKey := make([]byte, 32)
	if _, err := rand.Read(userKey); err != nil {
		return nil, fmt.Errorf("initialize MCP session binding key: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &Handler{
		runtime: runtimeManager, verifier: verifier, resourceMeta: resourceMetadataURL,
		sessionTTL: 30 * time.Minute, userKey: userKey, cancel: cancel,
		sessions: make(map[string]*sessionBundle), transients: make(map[*sessionBundle]struct{}),
	}
	if len(observers) != 0 {
		handler.observer = observers[0]
	}
	statefulStream := sdk.NewStreamableHTTPHandler(handler.serverForRequest, &sdk.StreamableHTTPOptions{
		Logger: logger, SessionTimeout: handler.sessionTTL,
	})
	statelessStream := sdk.NewStreamableHTTPHandler(handler.serverForStatelessRequest, &sdk.StreamableHTTPOptions{
		Logger: logger, Stateless: true, PropagateRequestCancellation: true,
	})
	stream := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(protocolVersionHeader) >= statelessProtocol {
			statelessStream.ServeHTTP(writer, request)
			return
		}
		if sessionID := request.Header.Get(sessionHeader); sessionID != "" {
			handler.touchOwned(sessionID, request)
		}
		statefulStream.ServeHTTP(writer, request)
	})
	tokenVerifier := func(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		principal, err := handler.verifier.Verify(ctx, token)
		if err != nil {
			if handler.observer != nil {
				handler.observer.RecordAuthFailure()
			}
			return nil, fmt.Errorf("%w: invalid bearer token", mcpauth.ErrInvalidToken)
		}
		scopes := make([]string, 0, len(principal.Scopes))
		for scope := range principal.Scopes {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		return &mcpauth.TokenInfo{
			Scopes: scopes, Expiration: principal.ExpiresAt,
			UserID: handler.userID(principal),
			Extra:  map[string]any{principalExtra: principal, bearerExtra: token},
		}, nil
	}
	handler.stream = mcpauth.RequireBearerToken(tokenVerifier, &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
	})(stream)
	runtimeManager.Subscribe(handler.onReload)
	go handler.reap(ctx)
	return handler, nil
}

// ServeHTTP authenticates before the SDK creates or resumes a session and
// tracks generation leases outside the SDK's internal session map.
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h.closed.Load() {
		http.Error(writer, "MCP adapter is shutting down", http.StatusServiceUnavailable)
		return
	}
	state := &requestState{}
	request = request.WithContext(context.WithValue(request.Context(), requestStateKey{}, state))
	capture := &responseCapture{ResponseWriter: writer, status: http.StatusOK}
	requestSession := request.Header.Get(sessionHeader)
	h.stream.ServeHTTP(capture, request)

	state.mu.Lock()
	pending := state.pending
	state.pending = nil
	transient := state.transient
	state.transient = nil
	state.mu.Unlock()
	if pending != nil {
		sessionID := capture.Header().Get(sessionHeader)
		if sessionID == "" || capture.status < 200 || capture.status >= 300 || !h.store(sessionID, pending) {
			_ = pending.lease.Close()
		}
	}
	if transient != nil {
		h.releaseTransient(transient)
	}
	if request.Method == http.MethodDelete && requestSession != "" && capture.status >= 200 && capture.status < 300 {
		h.release(requestSession)
	}
}

type requestStateKey struct{}

func (h *Handler) serverForRequest(request *http.Request) *sdk.Server {
	bundle := h.newBundle(request)
	if bundle == nil {
		return nil
	}
	state, ok := request.Context().Value(requestStateKey{}).(*requestState)
	if !ok {
		_ = bundle.lease.Close()
		return nil
	}
	state.mu.Lock()
	state.pending = bundle
	state.mu.Unlock()
	return bundle.server
}

func (h *Handler) serverForStatelessRequest(request *http.Request) *sdk.Server {
	bundle := h.newBundle(request)
	if bundle == nil {
		return nil
	}
	state, ok := request.Context().Value(requestStateKey{}).(*requestState)
	if !ok || !h.storeTransient(bundle) {
		_ = bundle.lease.Close()
		return nil
	}
	state.mu.Lock()
	state.transient = bundle
	state.mu.Unlock()
	return bundle.server
}

func (h *Handler) newBundle(request *http.Request) *sessionBundle {
	tokenInfo := mcpauth.TokenInfoFromContext(request.Context())
	if tokenInfo == nil {
		return nil
	}
	principal, ok := tokenInfo.Extra[principalExtra].(model.Principal)
	if !ok {
		return nil
	}
	lease, ok := h.runtime.Acquire()
	if !ok {
		return nil
	}
	bundle := &sessionBundle{lease: lease, principal: principal, lastSeen: time.Now()}
	bundle.server, bundle.tools = h.buildServer(lease.Generation, principal)
	return bundle
}

func (h *Handler) buildServer(generation *runtimecfg.Generation, principal model.Principal) (*sdk.Server, []string) {
	server := sdk.NewServer(&sdk.Implementation{Name: "cli-gateway", Version: "v0.3.0"}, &sdk.ServerOptions{
		Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{ListChanged: true}},
	})
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, request sdk.Request) (sdk.Result, error) {
			result, err := next(ctx, method, request)
			if list, ok := result.(*sdk.ListToolsResult); ok {
				list.CacheScope = "private"
				list.TTLMs = 0
			}
			return result, err
		}
	})
	commands := generation.Catalog.Visible(principal, model.InvokerAI)
	names := make([]string, 0, len(commands))
	for _, command := range commands {
		command := command
		names = append(names, command.ToolName)
		server.AddTool(&sdk.Tool{
			Name: command.ToolName, Description: command.Summary + " [risk:" + string(command.Risk) + "]",
			InputSchema: command.InputSchema,
		}, func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return h.callTool(ctx, request, generation, command)
		})
	}
	sort.Strings(names)
	return server, names
}

func (h *Handler) callTool(ctx context.Context, request *sdk.CallToolRequest, generation *runtimecfg.Generation, command *model.CompiledCommand) (*sdk.CallToolResult, error) {
	started := time.Now()
	callLease, ok := generation.Retain()
	if !ok {
		return toolError("E_OVERLOADED", "runtime generation is draining"), nil
	}
	defer callLease.Close()
	if request == nil || request.Params == nil || request.Extra == nil || request.Extra.TokenInfo == nil {
		return toolError("E_AUTH_INVALID", "authenticated MCP request context is missing"), nil
	}
	principal, ok := request.Extra.TokenInfo.Extra[principalExtra].(model.Principal)
	if !ok {
		return toolError("E_AUTH_INVALID", "authenticated principal is missing"), nil
	}
	bearer, _ := request.Extra.TokenInfo.Extra[bearerExtra].(string)
	args := make(map[string]any)
	if len(request.Params.Arguments) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(request.Params.Arguments))
		decoder.UseNumber()
		if err := decoder.Decode(&args); err != nil {
			return toolError("E_ARG_INVALID", "tool arguments are invalid"), nil
		}
	}
	confirmed := false
	if value, exists := args["confirm"]; exists {
		var valid bool
		confirmed, valid = value.(bool)
		if !valid {
			return toolError("E_ARG_INVALID", "confirm must be a boolean"), nil
		}
		delete(args, "confirm")
	}
	traceID := httpx.RequestTraceID(request.Extra.Header)
	execution, err := generation.Invoker.Invoke(ctx, model.Invocation{
		Source: model.SourceMCP, Principal: principal, Command: command, Args: args,
		Invoker: model.InvokerAI, Confirmed: confirmed, AIMaxRisk: generation.Snapshot.AIMaxRisk,
		TraceID: traceID, TraceState: httpx.TraceState(request.Extra.Header),
		Client: request.Extra.Header.Get("User-Agent"), BearerToken: bearer,
	})
	event := audit.Event{
		Event: "completed", TraceID: traceID, Subject: principal.Subject, Invoker: string(model.InvokerAI),
		Command: command.Key, Risk: string(command.Risk), Generation: generation.ID,
		Credential: string(command.DownstreamAuth), Client: request.Extra.Header.Get("User-Agent"),
		ArgKeys: sortedArgumentKeys(args), LatencyMS: time.Since(started).Milliseconds(),
	}
	if err != nil {
		var apiErr *httpx.APIError
		if errors.As(err, &apiErr) {
			event.Decision = "deny"
			event.DenyReason = apiErr.Code
			event.Outcome = "rejected"
			event.Status = apiErr.Status
			if generation.Audit != nil {
				generation.Audit.Record(event)
			}
			return toolError(apiErr.Code, apiErr.Message), nil
		}
		event.Decision = "allow"
		event.Outcome = "error"
		if generation.Audit != nil {
			generation.Audit.Record(event)
		}
		return toolError("E_INTERNAL", "internal gateway error"), nil
	}
	defer execution.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(execution.Body, maxToolResult+1))
	event.Decision = "allow"
	event.Status = execution.Status
	event.LatencyMS = time.Since(started).Milliseconds()
	if readErr != nil || len(body) > maxToolResult {
		event.Outcome = "error"
		if generation.Audit != nil {
			generation.Audit.Record(event)
		}
		return toolError("E_UPSTREAM", "upstream result could not be represented as an MCP result"), nil
	}
	event.Outcome = "success"
	if generation.Audit != nil {
		generation.Audit.Record(event)
	}
	result := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(body)}}}
	if strings.Contains(strings.ToLower(execution.ContentType), "application/json") {
		var structured map[string]any
		if json.Unmarshal(body, &structured) == nil {
			result.StructuredContent = structured
		}
	}
	return result, nil
}

func toolError(code, message string) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		Content: []sdk.Content{&sdk.TextContent{Text: code + ": " + message}},
		IsError: true,
	}
}

func sortedArgumentKeys(args map[string]any) []string {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (h *Handler) userID(principal model.Principal) string {
	mac := hmac.New(sha256.New, h.userKey)
	_, _ = mac.Write([]byte(principal.Issuer))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(principal.Tenant))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(principal.Subject))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(h.resourceMeta))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) store(sessionID string, bundle *sessionBundle) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() {
		return false
	}
	if existing := h.sessions[sessionID]; existing != nil {
		return false
	}
	h.sessions[sessionID] = bundle
	if h.observer != nil {
		h.observer.SetActiveMCPSessions(int64(len(h.sessions)))
	}
	return true
}

func (h *Handler) storeTransient(bundle *sessionBundle) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() {
		return false
	}
	h.transients[bundle] = struct{}{}
	return true
}

func (h *Handler) releaseTransient(bundle *sessionBundle) {
	h.mu.Lock()
	delete(h.transients, bundle)
	h.mu.Unlock()
	h.closeBundle(bundle)
}

func (h *Handler) touchOwned(sessionID string, request *http.Request) {
	tokenInfo := mcpauth.TokenInfoFromContext(request.Context())
	if tokenInfo == nil {
		return
	}
	principal, ok := tokenInfo.Extra[principalExtra].(model.Principal)
	if !ok {
		return
	}
	h.mu.Lock()
	bundle := h.sessions[sessionID]
	h.mu.Unlock()
	if bundle != nil {
		bundle.mu.Lock()
		if bundle.principal.Issuer == principal.Issuer &&
			bundle.principal.Tenant == principal.Tenant &&
			bundle.principal.Subject == principal.Subject {
			bundle.lastSeen = time.Now()
		}
		bundle.mu.Unlock()
	}
}

func (h *Handler) release(sessionID string) {
	h.mu.Lock()
	bundle := h.sessions[sessionID]
	delete(h.sessions, sessionID)
	if h.observer != nil {
		h.observer.SetActiveMCPSessions(int64(len(h.sessions)))
	}
	h.mu.Unlock()
	if bundle != nil {
		h.closeBundle(bundle)
	}
}

func (h *Handler) closeBundle(bundle *sessionBundle) {
	if bundle == nil {
		return
	}
	bundle.mu.Lock()
	lease := bundle.lease
	bundle.lease = nil
	bundle.mu.Unlock()
	if lease != nil {
		_ = lease.Close()
	}
}

func (h *Handler) reap(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			var expired []string
			h.mu.Lock()
			for sessionID, bundle := range h.sessions {
				bundle.mu.Lock()
				stale := now.Sub(bundle.lastSeen) > h.sessionTTL+time.Minute
				bundle.mu.Unlock()
				if stale {
					expired = append(expired, sessionID)
				}
			}
			h.mu.Unlock()
			for _, sessionID := range expired {
				h.release(sessionID)
			}
		}
	}
}

func (h *Handler) onReload(_, next *runtimecfg.Generation) {
	if h.closed.Load() || next == nil {
		return
	}
	h.mu.Lock()
	bundles := make([]*sessionBundle, 0, len(h.sessions)+len(h.transients))
	for _, bundle := range h.sessions {
		bundles = append(bundles, bundle)
	}
	for bundle := range h.transients {
		bundles = append(bundles, bundle)
	}
	h.mu.Unlock()
	for _, bundle := range bundles {
		nextLease, ok := next.Retain()
		if !ok {
			continue
		}
		bundle.mu.Lock()
		if h.closed.Load() || bundle.lease == nil {
			bundle.mu.Unlock()
			_ = nextLease.Close()
			continue
		}
		oldLease := bundle.lease
		oldTools := append([]string(nil), bundle.tools...)
		if len(oldTools) > 0 {
			bundle.server.RemoveTools(oldTools...)
		}
		commands := next.Catalog.Visible(bundle.principal, model.InvokerAI)
		newTools := make([]string, 0, len(commands))
		for _, command := range commands {
			command := command
			newTools = append(newTools, command.ToolName)
			bundle.server.AddTool(&sdk.Tool{
				Name: command.ToolName, Description: command.Summary + " [risk:" + string(command.Risk) + "]",
				InputSchema: command.InputSchema,
			}, func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				return h.callTool(ctx, request, next, command)
			})
		}
		sort.Strings(newTools)
		bundle.tools = newTools
		bundle.lease = nextLease
		bundle.lastSeen = time.Now()
		bundle.mu.Unlock()
		_ = oldLease.Close()
	}
}

// Close releases all session generation leases.
func (h *Handler) Close() {
	if h == nil || !h.closed.CompareAndSwap(false, true) {
		return
	}
	h.cancel()
	h.mu.Lock()
	sessions := h.sessions
	h.sessions = make(map[string]*sessionBundle)
	transients := h.transients
	h.transients = make(map[*sessionBundle]struct{})
	if h.observer != nil {
		h.observer.SetActiveMCPSessions(0)
	}
	h.mu.Unlock()
	for _, bundle := range sessions {
		h.closeBundle(bundle)
	}
	for bundle := range transients {
		h.closeBundle(bundle)
	}
}

type responseCapture struct {
	http.ResponseWriter
	status int
}

func (w *responseCapture) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseCapture) Write(data []byte) (int, error) {
	return w.ResponseWriter.Write(data)
}

func (w *responseCapture) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *responseCapture) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
