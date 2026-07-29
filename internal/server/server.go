// Package server wires the cli-gateway HTTP surface.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/audit"
	"github.com/wyh0626/cli-gateway/internal/auth"
	"github.com/wyh0626/cli-gateway/internal/credential"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/identity"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/observability"
	"github.com/wyh0626/cli-gateway/internal/policy"
	runtimecfg "github.com/wyh0626/cli-gateway/internal/runtime"
)

const maxExecutionBody = 1 << 20
const maxExecutionResponse = 4 << 20

// Dependencies are the runtime services needed by protected endpoints.
type Dependencies struct {
	Verifier        auth.Verifier
	Invoker         model.InvocationService
	Signer          *identity.Signer
	Runtime         *runtimecfg.Manager
	Metrics         *observability.Registry
	MCP             http.Handler
	DownstreamOAuth *credential.AuthorizationCodeBroker
	DownloadDir     string
	PublicURL       string
}

// NewHandler builds the cli-gateway HTTP handler. Dependencies are optional only so
// the M1 health check remains usable before authentication is initialized.
func NewHandler(manager *manifest.Manager, dependencies ...Dependencies) http.Handler {
	var services Dependencies
	if len(dependencies) > 0 {
		services = dependencies[0]
	}
	mux := http.NewServeMux()
	liveness := func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	}
	mux.HandleFunc("GET /livez", liveness)
	mux.HandleFunc("GET /healthz", liveness)
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !ready(manager, services.Runtime) {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /install.sh", func(writer http.ResponseWriter, request *http.Request) {
		handleInstallScript(writer, request, services)
	})
	mux.HandleFunc("GET /downloads/{artifact}", func(writer http.ResponseWriter, request *http.Request) {
		handleCLIDownload(writer, request, services)
	})
	if services.Metrics != nil {
		mux.Handle("GET /metrics", services.Metrics)
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(writer http.ResponseWriter, _ *http.Request) {
		handleProtectedResourceMetadata(writer, manager, services, "")
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(writer http.ResponseWriter, _ *http.Request) {
		handleProtectedResourceMetadata(writer, manager, services, "/mcp")
	})
	mux.HandleFunc("GET /jwks", func(writer http.ResponseWriter, _ *http.Request) {
		if services.Signer == nil {
			writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_INTERNAL", Message: "identity signer is unavailable"})
			return
		}
		encoded, err := services.Signer.JWKS()
		if err != nil {
			writeAPIError(writer, &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "public key serialization failed", Cause: err})
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(encoded)
	})
	mux.HandleFunc("GET /manifest", func(writer http.ResponseWriter, request *http.Request) {
		handleManifest(writer, request, manager, services)
	})
	mux.HandleFunc("GET /whoami", func(writer http.ResponseWriter, request *http.Request) {
		handleWhoAmI(writer, request, services)
	})
	mux.HandleFunc("POST /oauth/downstream/{domain}/authorize", func(writer http.ResponseWriter, request *http.Request) {
		handleDownstreamAuthorizationStart(writer, request, manager, services)
	})
	mux.HandleFunc("GET /oauth/downstream/{domain}/status", func(writer http.ResponseWriter, request *http.Request) {
		handleDownstreamAuthorizationStatus(writer, request, manager, services)
	})
	mux.HandleFunc("DELETE /oauth/downstream/{domain}", func(writer http.ResponseWriter, request *http.Request) {
		handleDownstreamAuthorizationDisconnect(writer, request, manager, services)
	})
	mux.HandleFunc("GET /oauth/downstream/callback", func(writer http.ResponseWriter, request *http.Request) {
		handleDownstreamAuthorizationCallback(writer, request, services)
	})
	mux.HandleFunc("POST /exec/{domain}/{command}", func(writer http.ResponseWriter, request *http.Request) {
		handleExecution(writer, request, manager, services)
	})
	if services.MCP != nil {
		mux.Handle("/mcp", services.MCP)
	}
	if services.Metrics != nil {
		return services.Metrics.Middleware(mux)
	}
	return mux
}

func handleDownstreamAuthorizationStart(writer http.ResponseWriter, request *http.Request, manager *manifest.Manager, services Dependencies) {
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	principal, _, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		writeAPIError(writer, authErr)
		return
	}
	if services.DownstreamOAuth == nil {
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream OAuth is unavailable", TraceID: traceID})
		return
	}
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		runtimeErr.TraceID = traceID
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	command, findErr := downstreamAuthorizationCommand(acquired.catalog, request.PathValue("domain"))
	if findErr != nil {
		findErr.TraceID = traceID
		writeAPIError(writer, findErr)
		return
	}
	start, err := services.DownstreamOAuth.Begin(request.Context(), command, principal, acquired.snapshot.PublicURL)
	if err != nil {
		var apiErr *httpx.APIError
		if !errors.As(err, &apiErr) {
			apiErr = &httpx.APIError{Status: http.StatusBadGateway, Code: "E_DOWNSTREAM_AUTH", Message: "downstream authorization could not be started", Cause: err}
		}
		apiErr.TraceID = traceID
		writeAPIError(writer, apiErr)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, start)
}

func handleDownstreamAuthorizationStatus(writer http.ResponseWriter, request *http.Request, manager *manifest.Manager, services Dependencies) {
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	principal, _, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		writeAPIError(writer, authErr)
		return
	}
	if services.DownstreamOAuth == nil {
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream OAuth is unavailable", TraceID: traceID})
		return
	}
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		runtimeErr.TraceID = traceID
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	command, findErr := downstreamAuthorizationCommand(acquired.catalog, request.PathValue("domain"))
	if findErr != nil {
		findErr.TraceID = traceID
		writeAPIError(writer, findErr)
		return
	}
	status, err := services.DownstreamOAuth.Status(command, principal)
	if err != nil {
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream authorization status is unavailable", TraceID: traceID, Cause: err})
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, status)
}

func handleDownstreamAuthorizationDisconnect(writer http.ResponseWriter, request *http.Request, manager *manifest.Manager, services Dependencies) {
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	principal, _, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		writeAPIError(writer, authErr)
		return
	}
	if services.DownstreamOAuth == nil {
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream OAuth is unavailable", TraceID: traceID})
		return
	}
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		runtimeErr.TraceID = traceID
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	command, findErr := downstreamAuthorizationCommand(acquired.catalog, request.PathValue("domain"))
	if findErr != nil {
		findErr.TraceID = traceID
		writeAPIError(writer, findErr)
		return
	}
	if err := services.DownstreamOAuth.Disconnect(request.Context(), command, principal); err != nil {
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_DOWNSTREAM_AUTH", Message: "downstream authorization could not be removed", TraceID: traceID, Cause: err})
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "domain": command.Domain})
}

func handleDownstreamAuthorizationCallback(writer http.ResponseWriter, request *http.Request, services Dependencies) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if services.DownstreamOAuth == nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, "<!doctype html><title>Authorization unavailable</title><p>Downstream authorization is unavailable.</p>")
		return
	}
	completion, err := services.DownstreamOAuth.Complete(
		request.Context(), request.URL.Query().Get("state"), request.URL.Query().Get("code"), request.URL.Query().Get("error"),
	)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "<!doctype html><title>Authorization failed</title><p>Authorization failed or expired. Return to the terminal and try again.</p>")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, "<!doctype html><title>Authorization complete</title><p>Authorization for <strong>"+html.EscapeString(completion.Domain)+"</strong> is complete. You can close this window.</p>")
}

func downstreamAuthorizationCommand(catalog model.CommandCatalog, domain string) (*model.CompiledCommand, *httpx.APIError) {
	if strings.TrimSpace(domain) == "" {
		return nil, &httpx.APIError{Status: http.StatusNotFound, Code: "E_DOMAIN_NOT_FOUND", Message: "domain was not found"}
	}
	foundDomain := false
	for _, command := range catalog.List() {
		if command.Domain != domain {
			continue
		}
		foundDomain = true
		if command.DownstreamAuth == model.DownstreamAuthorizationCode {
			return command, nil
		}
	}
	if foundDomain {
		return nil, &httpx.APIError{Status: http.StatusBadRequest, Code: "E_DOWNSTREAM_AUTH_MODE", Message: "domain does not use per-user OAuth authorization"}
	}
	return nil, &httpx.APIError{Status: http.StatusNotFound, Code: "E_DOMAIN_NOT_FOUND", Message: "domain was not found"}
}

func handleProtectedResourceMetadata(writer http.ResponseWriter, manager *manifest.Manager, services Dependencies, resourcePath string) {
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	scopes := make(map[string]struct{})
	if _, configured := acquired.snapshot.AuthIdentityClaims["email"]; configured {
		scopes["email"] = struct{}{}
	}
	if _, configured := acquired.snapshot.AuthIdentityClaims["name"]; configured {
		scopes["profile"] = struct{}{}
	}
	scopeList := make([]string, 0, len(scopes))
	for scope := range scopes {
		scopeList = append(scopeList, scope)
	}
	sort.Strings(scopeList)
	writeJSON(writer, http.StatusOK, map[string]any{
		"resource":                 strings.TrimSuffix(acquired.snapshot.PublicURL, "/") + resourcePath,
		"authorization_servers":    []string{acquired.snapshot.AuthIssuer},
		"client_id":                acquired.snapshot.AuthClientID,
		"audience":                 acquired.snapshot.AuthAudience,
		"resource_parameter":       acquired.snapshot.AuthResourceParameter,
		"scopes_supported":         scopeList,
		"bearer_methods_supported": []string{"header"},
	})
}

func handleWhoAmI(writer http.ResponseWriter, request *http.Request, services Dependencies) {
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	principal, _, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		writeAPIError(writer, authErr)
		return
	}
	scopes := make([]string, 0, len(principal.Scopes))
	for scope := range principal.Scopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	writeJSON(writer, http.StatusOK, map[string]any{
		"subject": principal.Subject, "client_id": principal.ClientID,
		"invoker": principal.Invoker, "scopes": scopes, "expires_at": principal.ExpiresAt,
	})
}

func handleManifest(writer http.ResponseWriter, request *http.Request, manager *manifest.Manager, services Dependencies) {
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	principal, _, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		writeAPIError(writer, authErr)
		return
	}
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		runtimeErr.TraceID = traceID
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	snapshot := acquired.snapshot
	invoker := effectiveInvoker(principal.Invoker, request.Header.Get("X-Cli-Gateway-Invoker"))

	type catalogCommand struct {
		Path      []string             `json:"path"`
		Summary   string               `json:"summary,omitempty"`
		Method    string               `json:"method"`
		Risk      model.Risk           `json:"risk"`
		Confirm   bool                 `json:"confirm,omitempty"`
		Streaming bool                 `json:"streaming,omitempty"`
		Flags     []model.CompiledFlag `json:"flags,omitempty"`
	}
	type catalogDomain struct {
		Name     string           `json:"name"`
		Commands []catalogCommand `json:"commands"`
	}
	domains := make(map[string][]catalogCommand)
	for _, key := range snapshot.CommandKeys {
		command := snapshot.Commands[key]
		if !policy.Visible(principal, invoker, command, snapshot.AIMaxRisk) {
			continue
		}
		domains[command.Domain] = append(domains[command.Domain], catalogCommand{
			Path: command.Path, Summary: command.Summary, Method: command.Method, Risk: command.Risk,
			Confirm: command.Confirm, Streaming: command.Streaming, Flags: command.Flags,
		})
	}
	domainNames := make([]string, 0, len(domains))
	for name := range domains {
		domainNames = append(domainNames, name)
	}
	sort.Strings(domainNames)
	payloadDomains := make([]catalogDomain, 0, len(domainNames))
	for _, name := range domainNames {
		payloadDomains = append(payloadDomains, catalogDomain{Name: name, Commands: domains[name]})
	}
	base := struct {
		CLI     map[string]string `json:"cli"`
		Domains []catalogDomain   `json:"domains"`
	}{CLI: map[string]string{"name": snapshot.CLIName}, Domains: payloadDomains}
	canonical, _ := json.Marshal(base)
	digest := sha256.Sum256(canonical)
	etag := hex.EncodeToString(digest[:8])
	quotedETag := `"` + etag + `"`
	writer.Header().Set("Cache-Control", "private")
	writer.Header().Set("Vary", "Authorization")
	writer.Header().Set("ETag", quotedETag)
	if request.Header.Get("If-None-Match") == quotedETag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		CLI     map[string]string `json:"cli"`
		Domains []catalogDomain   `json:"domains"`
		ETag    string            `json:"etag"`
	}{CLI: base.CLI, Domains: base.Domains, ETag: etag})
}

func handleExecution(writer http.ResponseWriter, request *http.Request, manager *manifest.Manager, services Dependencies) {
	started := time.Now()
	traceID := httpx.RequestTraceID(request.Header)
	writer.Header().Set("X-Cli-Gateway-Trace-Id", traceID)
	acquired, runtimeErr := acquireRuntime(manager, services)
	if runtimeErr != nil {
		runtimeErr.TraceID = traceID
		writeAPIError(writer, runtimeErr)
		return
	}
	defer acquired.release()
	auditEvent := audit.Event{
		Event: "completed", TraceID: traceID, Decision: "deny", Outcome: "rejected",
		Client: request.UserAgent(), Generation: acquired.generation, AuthMethod: "bearer-jwt",
	}
	defer func() {
		auditEvent.LatencyMS = time.Since(started).Milliseconds()
		if acquired.audit != nil {
			acquired.audit.Record(auditEvent)
		}
	}()

	principal, bearerToken, authErr := authenticate(request, services.Verifier, traceID)
	if authErr != nil {
		if services.Metrics != nil {
			services.Metrics.RecordAuthFailure()
		}
		auditEvent.DenyReason = authErr.Code
		auditEvent.Status = authErr.Status
		writeAPIError(writer, authErr)
		return
	}
	auditEvent.Subject = principal.Subject
	snapshot := acquired.snapshot
	key := request.PathValue("domain") + "." + request.PathValue("command")
	command, found := acquired.catalog.Resolve(key)
	if !found {
		auditEvent.DenyReason = "E_CMD_NOT_FOUND"
		auditEvent.Status = http.StatusNotFound
		writeAPIError(writer, &httpx.APIError{Status: http.StatusNotFound, Code: "E_CMD_NOT_FOUND", Message: "command was not found", TraceID: traceID})
		return
	}
	auditEvent.Command = command.Key
	auditEvent.Risk = string(command.Risk)
	auditEvent.Credential = string(command.DownstreamAuth)

	request.Body = http.MaxBytesReader(writer, request.Body, maxExecutionBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var input struct {
		Args map[string]any `json:"args"`
	}
	if err := decoder.Decode(&input); err != nil {
		auditEvent.DenyReason = "E_ARG_INVALID"
		auditEvent.Status = http.StatusBadRequest
		writeAPIError(writer, &httpx.APIError{Status: http.StatusBadRequest, Code: "E_ARG_INVALID", Message: "request body must contain a valid args object", TraceID: traceID})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		auditEvent.DenyReason = "E_ARG_INVALID"
		auditEvent.Status = http.StatusBadRequest
		writeAPIError(writer, &httpx.APIError{Status: http.StatusBadRequest, Code: "E_ARG_INVALID", Message: "request body must contain one JSON document", TraceID: traceID})
		return
	}
	if input.Args == nil {
		input.Args = make(map[string]any)
	}
	invoker := effectiveInvoker(principal.Invoker, request.Header.Get("X-Cli-Gateway-Invoker"))
	auditEvent.Invoker = string(invoker)
	auditEvent.ArgKeys = sortedKeys(input.Args)
	if acquired.invoker == nil {
		auditEvent.DenyReason = "E_INTERNAL"
		auditEvent.Status = http.StatusServiceUnavailable
		writeAPIError(writer, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_INTERNAL", Message: "invocation service is unavailable", TraceID: traceID})
		return
	}
	auditEvent.Decision = "allow"
	auditEvent.Outcome = "error"
	result, err := acquired.invoker.Invoke(request.Context(), model.Invocation{
		Source: model.SourceHTTP, Principal: principal, Command: command, Args: input.Args,
		Invoker: invoker, Confirmed: strings.EqualFold(strings.TrimSpace(request.Header.Get("X-Cli-Gateway-Confirm")), "true"),
		AIMaxRisk: snapshot.AIMaxRisk, TraceID: traceID, TraceState: httpx.TraceState(request.Header),
		Client: request.UserAgent(), BearerToken: bearerToken,
	})
	if err != nil {
		var apiErr *httpx.APIError
		if !errors.As(err, &apiErr) {
			apiErr = &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "internal gateway error", TraceID: traceID, Cause: err}
		}
		auditEvent.Status = apiErr.Status
		if strings.HasPrefix(apiErr.Code, "E_AI_") || apiErr.Code == "E_CONFIRM_REQUIRED" {
			if services.Metrics != nil {
				services.Metrics.RecordPolicyDenial()
			}
			auditEvent.Decision = "deny"
			auditEvent.DenyReason = apiErr.Code
			auditEvent.Outcome = "rejected"
		}
		if services.Metrics != nil && strings.HasPrefix(apiErr.Code, "E_UPSTREAM") {
			services.Metrics.RecordUpstreamFailure()
		}
		if services.Metrics != nil && strings.Contains(apiErr.Code, "CIRCUIT_OPEN") {
			services.Metrics.RecordCircuitRejection()
		}
		if services.Metrics != nil && (apiErr.Code == "E_RATE_LIMITED" || apiErr.Code == "E_OVERLOADED") {
			services.Metrics.RecordLimiterRejection()
		}
		writeAPIError(writer, apiErr)
		return
	}
	defer result.Body.Close()
	auditEvent.Status = result.Status
	if result.Streaming {
		if acquired.audit != nil {
			streamStarted := auditEvent
			streamStarted.Event = "stream_started"
			streamStarted.Outcome = "started"
			streamStarted.LatencyMS = time.Since(started).Milliseconds()
			acquired.audit.Record(streamStarted)
		}
		auditEvent.Event = "stream_completed"
		if result.ContentType != "" {
			writer.Header().Set("Content-Type", result.ContentType)
		}
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(result.Status)
		streamWriter := io.Writer(writer)
		if flusher, ok := writer.(http.Flusher); ok {
			streamWriter = flushWriter{writer: writer, flusher: flusher}
		}
		if _, streamErr := io.Copy(streamWriter, result.Body); streamErr != nil {
			auditEvent.Outcome = "error"
			return
		}
		auditEvent.Outcome = "success"
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(result.Body, maxExecutionResponse+1))
	if readErr != nil {
		auditEvent.Outcome = "error"
		writeAPIError(writer, upstreamReadError(traceID, readErr))
		return
	}
	if len(raw) > maxExecutionResponse {
		auditEvent.Outcome = "error"
		writeAPIError(writer, &httpx.APIError{Status: http.StatusBadGateway, Code: "E_UPSTREAM", Message: "upstream response exceeds 4 MiB", TraceID: traceID})
		return
	}
	var data any
	if len(raw) == 0 {
		data = map[string]any{}
	} else if strings.Contains(strings.ToLower(result.ContentType), "application/json") && json.Unmarshal(raw, &data) == nil {
		// Preserve a decoded JSON value for the existing HTTP envelope.
	} else {
		data = map[string]any{"raw": string(raw)}
	}
	writeJSON(writer, http.StatusOK, struct {
		OK     bool `json:"ok"`
		Status int  `json:"status"`
		Data   any  `json:"data"`
	}{OK: true, Status: result.Status, Data: data})
	auditEvent.Outcome = "success"
}

type flushWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w flushWriter) Write(data []byte) (int, error) {
	count, err := w.writer.Write(data)
	if count > 0 {
		w.flusher.Flush()
	}
	return count, err
}

func sortedKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

type acquiredRuntime struct {
	snapshot   *manifest.Snapshot
	catalog    model.CommandCatalog
	invoker    model.InvocationService
	audit      *audit.Dispatcher
	generation uint64
	release    func()
}

func acquireRuntime(manager *manifest.Manager, services Dependencies) (acquiredRuntime, *httpx.APIError) {
	if services.Runtime != nil {
		lease, ok := services.Runtime.Acquire()
		if !ok {
			return acquiredRuntime{}, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_OVERLOADED", Message: "runtime is not accepting work"}
		}
		return acquiredRuntime{
			snapshot:   lease.Generation.Snapshot,
			catalog:    lease.Generation.Catalog,
			invoker:    lease.Generation.Invoker,
			audit:      lease.Generation.Audit,
			generation: lease.Generation.ID,
			release:    func() { _ = lease.Close() },
		}, nil
	}
	if manager == nil || manager.Current() == nil {
		return acquiredRuntime{}, &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_INTERNAL", Message: "runtime is unavailable"}
	}
	snapshot := manager.Current()
	return acquiredRuntime{
		snapshot: snapshot,
		catalog:  snapshotCatalog{snapshot: snapshot},
		invoker:  services.Invoker,
		release:  func() {},
	}, nil
}

type snapshotCatalog struct {
	snapshot *manifest.Snapshot
}

func (c snapshotCatalog) Resolve(key string) (*model.CompiledCommand, bool) {
	command, ok := c.snapshot.Commands[key]
	return command, ok
}

func (c snapshotCatalog) List() []*model.CompiledCommand {
	result := make([]*model.CompiledCommand, 0, len(c.snapshot.CommandKeys))
	for _, key := range c.snapshot.CommandKeys {
		result = append(result, c.snapshot.Commands[key])
	}
	return result
}

func ready(manager *manifest.Manager, runtimeManager *runtimecfg.Manager) bool {
	if runtimeManager != nil {
		return runtimeManager.Current() != nil
	}
	return manager != nil && manager.Current() != nil
}

func upstreamReadError(traceID string, err error) *httpx.APIError {
	if errors.Is(err, context.Canceled) {
		return &httpx.APIError{Status: 499, Code: "E_CANCELLED", Message: "request was cancelled", TraceID: traceID, Cause: err}
	}
	return &httpx.APIError{Status: http.StatusBadGateway, Code: "E_UPSTREAM", Message: "upstream response could not be read", TraceID: traceID, Cause: err}
}

func authenticate(request *http.Request, verifier auth.Verifier, traceID string) (model.Principal, string, *httpx.APIError) {
	if verifier == nil {
		return model.Principal{}, "", &httpx.APIError{Status: http.StatusServiceUnavailable, Code: "E_INTERNAL", Message: "authentication is unavailable", TraceID: traceID}
	}
	token, err := auth.BearerToken(request)
	if err != nil {
		code := "E_AUTH_INVALID"
		message := "bearer token is invalid"
		if errors.Is(err, auth.ErrMissingToken) {
			code = "E_AUTH_MISSING"
			message = "bearer token is required"
		}
		return model.Principal{}, "", &httpx.APIError{Status: http.StatusUnauthorized, Code: code, Message: message, TraceID: traceID}
	}
	principal, err := verifier.Verify(request.Context(), token)
	if err != nil {
		code := "E_AUTH_INVALID"
		message := "bearer token is invalid"
		if errors.Is(err, auth.ErrExpiredToken) {
			code = "E_AUTH_EXPIRED"
			message = "bearer token has expired"
		}
		return model.Principal{}, "", &httpx.APIError{Status: http.StatusUnauthorized, Code: code, Message: message, TraceID: traceID, Cause: err}
	}
	return principal, token, nil
}

func effectiveInvoker(trusted model.Invoker, requested string) model.Invoker {
	if strings.EqualFold(strings.TrimSpace(requested), string(model.InvokerAI)) {
		return model.InvokerAI
	}
	if trusted == "" {
		return model.InvokerUnknown
	}
	return trusted
}

func writeAPIError(writer http.ResponseWriter, apiErr *httpx.APIError) {
	status := apiErr.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if status == http.StatusUnauthorized {
		challenge := `Bearer realm="cli-gateway"`
		if apiErr.Code != "E_AUTH_MISSING" {
			challenge += `, error="invalid_token"`
		}
		writer.Header().Set("WWW-Authenticate", challenge)
	}
	if apiErr.RetryAfter > 0 {
		seconds := int64((apiErr.RetryAfter + time.Second - 1) / time.Second)
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	}
	writeJSON(writer, status, struct {
		OK       bool   `json:"ok"`
		Error    string `json:"error"`
		Message  string `json:"message"`
		Hint     string `json:"hint,omitempty"`
		TraceID  string `json:"trace_id,omitempty"`
		Upstream int    `json:"status,omitempty"`
	}{OK: false, Error: apiErr.Code, Message: apiErr.Message, Hint: apiErr.Hint, TraceID: apiErr.TraceID, Upstream: apiErr.UpstreamStatus})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
