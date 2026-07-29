# cli-gateway Implementation Specification

Version: v0.3

This document is the implementation authority for cli-gateway.

## 1. Product definition

cli-gateway is a single-server-binary capability gateway. It reads one declarative manifest and exposes HTTP APIs through:

1. an authenticated organization CLI whose commands are generated dynamically; and
2. an MCP Streamable HTTP server whose tools are generated from the same command catalog.

Both adapters use one invocation pipeline for authentication context, argument validation, invoker-risk and confirmation policy, upstream request construction, signed identity propagation, response normalization, tracing, and audit.

### 1.1 Explicit non-goals

- A built-in deployment controller, service registry, federation layer, or multi-tenant management portal.
- A mandatory database or Redis dependency. v0.3 ships only bounded in-process
  coordination and a single-writer encrypted token file; a reviewed shared
  store is a future extension boundary.
- User management; identity comes from the external OIDC system.
- A general policy language. v0.3 keeps a fixed invoker/risk policy plus destructive-operation confirmation; backends own business authorization.
- Automatic upstream retries.
- MCP-to-MCP proxying, MCP session affinity, resources, or prompts.

### 1.2 Data plane and control plane boundary

The process contains a data plane and a file-backed control plane with an explicit boundary:

- The control plane parses, validates, compiles, and atomically publishes an immutable runtime generation.
- The data plane accepts HTTP and MCP traffic and reads exactly one runtime generation for the lifetime of an invocation.
- A runtime generation owns its catalog, policy configuration, upstream transports, downstream credential providers, cache namespace, and audit dispatch configuration.
- A successful reload publishes the new generation before draining the old generation. Failed reloads do not affect the active generation.
- Optional catalog sources or a future management service implement the `CatalogSource` contract and are not part of the core request path.

## 2. Repository layout

```text
cli-gateway/
├── cmd/
│   ├── cli-gateway/
│   ├── demoapi/
│   ├── devissuer/
│   └── loadtest/
├── client/
│   ├── cmd/cg/
│   └── internal/
├── internal/
│   ├── model/
│   ├── manifest/
│   ├── catalog/
│   ├── auth/
│   ├── credential/
│   ├── cache/
│   ├── policy/
│   ├── invoke/
│   ├── runtime/
│   ├── limiter/
│   ├── breaker/
│   ├── upstream/
│   ├── identity/
│   ├── adapter/mcp/
│   ├── audit/
│   ├── observability/
│   ├── server/
│   └── httpx/
├── examples/
│   ├── auth0/
│   ├── e2e/
│   ├── github/
│   ├── keycloak/
│   └── invalid/
├── deploy/kubernetes/
├── scripts/install.sh
├── manifest.example.yaml
├── AGENTS.md
└── docs/implementation-spec.md
```

### 2.1 Dependency allowlist

- Go standard library.
- `github.com/fsnotify/fsnotify`.
- `github.com/lestrrat-go/jwx/v2`.
- `github.com/modelcontextprotocol/go-sdk`.
- `github.com/spf13/cobra`.
- `github.com/zalando/go-keyring`.
- `gopkg.in/yaml.v3` for strict manifest and CLI YAML handling.

Adding a dependency requires explicit review.

## 3. Core domain model

Adapters convert transport-specific input into one `Invocation`.

```go
type Invocation struct {
    Source     Source
    Principal  Principal
    Command    *CompiledCommand
    Args       map[string]any
    Invoker    Invoker
    Confirmed  bool
    TraceID    string
    Client     string
}
```

The invocation service owns the only implementation of:

```text
resolve → validate arguments → authorize → build request → sign identity
→ dispatch → normalize response → complete audit
```

HTTP handlers and MCP handlers may decode, adapt, call the service, and encode. They must not duplicate policy or upstream request logic.

The invocation service returns an `Execution`, not an already-buffered transport response:

```go
type Execution struct {
    Status      int
    ContentType string
    Header      http.Header
    Body        io.ReadCloser
    Streaming   bool
}
```

The adapter that consumes `Body` owns the close, buffering limit, cancellation behavior, and transport-specific encoding. The execution body retains the runtime generation until it is closed.

## 4. Manifest

### 4.1 Example

```yaml
version: 1

server:
  listen: ":8080"
  public_url: https://gateway.example.com
  environment: production
  identity_key_file: /etc/cli-gateway/signing.pem
  identity_previous_key_files:
    - /etc/cli-gateway/signing-previous.pem

auth:
  mode: oidc
  issuer: https://auth.example.com
  client_id: cg-cli
  audience: cli-gateway
  # both (default), audience, resource, or none
  resource_parameter: both
  tls:
    ca_file: /etc/cli-gateway/pki/ca.pem
    client_cert_file: /etc/cli-gateway/pki/cli-gateway-client.pem
    client_key_file: /etc/cli-gateway/pki/cli-gateway-client-key.pem

cli:
  name: cg

policy:
  ai_max_risk: write

audit:
  sinks:
    - type: jsonl
      path: /var/log/cli-gateway/audit.jsonl

limits:
  global_concurrency: 512
  queue_timeout: 250ms

domains:
  - name: inventory
    upstream: https://inventory.example.com
    timeout: 30s
    tls:
      insecure_skip_verify: false
      ca_file: /etc/cli-gateway/pki/ca.pem
      client_cert_file: /etc/cli-gateway/pki/cli-gateway-client.pem
      client_key_file: /etc/cli-gateway/pki/cli-gateway-client-key.pem
    network:
      allow_local: false
    downstream_auth:
      mode: signed-identity
      identity_audience: inventory-api
      cache:
        capacity: 10000
        refresh_skew: 30s
        negative_ttl: 2s
    limits:
      concurrency: 128
      requests_per_second: 200
      burst: 400
    commands:
      - path: [resource, apply]
        summary: 申请一个资源
        method: POST
        endpoint: /v1/resources
        risk: write
        flags:
          - name: type
            type: string
            required: true
            in: body
            desc: 资源类型
          - name: cpu
            type: int
            default: 1
            in: body
          - name: dry-run
            type: bool
            default: false
            in: query
            query_name: dryRun
      - path: [resource, get]
        method: GET
        endpoint: /v1/resources/{id}
        risk: read
        flags:
          - name: id
            type: string
            required: true
            in: path
      - path: [resource, delete]
        method: DELETE
        endpoint: /v1/resources/{id}
        risk: destroy
        confirm: true
        flags:
          - name: id
            type: string
            required: true
            in: path
      - path: [logs]
        method: GET
        endpoint: /v1/logs
        risk: read
        streaming: true
```

For a delegated downstream API, `downstream_auth` is instead:

```yaml
downstream_auth:
  mode: token-exchange
  token_exchange:
    token_url: https://auth.example.com/oauth2/token
    client_id: cli-gateway
    client_secret_ref: env:CLI_GATEWAY_EXCHANGE_SECRET
    audience: inventory-api
    scopes: [inventory.read, inventory.write]
    subject_token_type: urn:ietf:params:oauth:token-type:access_token
    requested_token_type: urn:ietf:params:oauth:token-type:access_token
    tls:
      ca_file: /etc/cli-gateway/pki/ca.pem
      client_cert_file: /etc/cli-gateway/pki/cli-gateway-client.pem
      client_key_file: /etc/cli-gateway/pki/cli-gateway-client-key.pem
  cache:
    capacity: 10000
    refresh_skew: 30s
    negative_ttl: 2s
```

For a downstream service with its own user login, Scheme C is:

```yaml
downstream_oauth:
  token_store_file: /var/lib/cli-gateway/downstream-oauth.enc
  encryption_key_ref: env:CLI_GATEWAY_OAUTH_STORE_KEY
  state_ttl: 5m

domains:
  - name: vendor
    upstream: https://api.vendor.example
    downstream_auth:
      mode: authorization-code
      authorization_code:
        authorization_url: https://accounts.vendor.example/oauth2/authorize
        token_url: https://accounts.vendor.example/oauth2/token
        revocation_url: https://accounts.vendor.example/oauth2/revoke
        client_id: cli-gateway-vendor
        client_secret_ref: env:CLI_GATEWAY_VENDOR_CLIENT_SECRET
        # client_secret_basic (default) or client_secret_post
        token_endpoint_auth_method: client_secret_basic
        scopes: [items.read, offline_access]
```

### 4.2 Strict validation

The loader rejects the initial manifest or retains the old snapshot during reload when any rule fails.

1. The YAML decoder uses known-field enforcement and accepts exactly one document.
2. `version` is exactly `1`.
3. Domain names are unique. Domain and command path elements match `^[a-z][a-z0-9-]{0,31}$`.
4. A domain plus dotted command path is globally unique. Generated MCP tool names are also unique.
5. `upstream` is an absolute `http` or `https` URL with no userinfo, query, or fragment.
6. Direct loopback, unspecified, multicast, and link-local IP addresses are rejected unless `network.allow_local=true`; cloud metadata addresses remain rejected.
7. `endpoint` is an absolute path relative to `upstream`. It cannot contain a scheme, host, query, fragment, backslash, or dot segment.
8. A placeholder must occupy a complete path segment, for example `/{id}`. Every placeholder maps to one required `in:path` flag and every path flag is used.
9. Risk is `read`, `write`, or `destroy`. Destroy requires `confirm:true`.
10. Flag type is `string`, `int`, `bool`, or `stringArray`. Location is `body`, `query`, `path`, or `header`.
11. Flag names are unique within a command. `confirm` is reserved for gateway control and cannot be a business flag.
12. Body flags are allowed only for POST, PUT, or PATCH.
13. Header flags require `header_name`; protected, hop-by-hop, forwarding, cookie, authorization, and `X-Cli-Gateway-*` headers are forbidden.
14. Defaults must match the declared flag type. Unknown invocation arguments are rejected.
15. `signed-identity` requires `identity_audience`. `bearer-passthrough` is opt-in. `token-exchange` requires a token endpoint, target audience or resource, client authentication reference, and an explicit scope set. `authorization-code` additionally requires an authorization endpoint. Its delegated scope set may be empty for providers such as GitHub Apps, where application permissions replace OAuth scopes.
16. Production requires `identity_key_file`; an ephemeral identity key is development-only.
17. OAuth, JWKS, token, webhook, and upstream URLs are validated as egress boundaries. Redirects are disabled for token and JWKS requests.
18. Secrets are references to environment, file, or secret-provider entries. Literal client secrets are rejected in production manifests.
19. Cache durations, capacities, refresh skew, rate limits, concurrency limits, and queue capacities must be positive and bounded.
20. A generated MCP tool name cannot collide with a built-in MCP method or another command.
21. Production `authorization-code` domains require an absolute encrypted token-store file, a non-literal encryption-key reference, and an authorization-state TTL of at most 15 minutes.
22. `auth.resource_parameter` is one of `both`, `audience`, `resource`, or `none`. The backward-compatible default is `both`; use `audience` for Auth0 APIs, `resource` for RFC 8707 providers, and `none` when an authorization-server mapper supplies the audience.
23. `token_endpoint_auth_method` is `client_secret_basic` by default and may be `client_secret_post` only for providers whose token endpoint requires it. Client secrets remain server-side references in both modes.

Semantic validation errors include the YAML path and source line when available.

### 4.3 Compilation and reload

The loader builds a complete immutable runtime generation containing:

- the normalized command index;
- generated MCP tool names and input schemas;
- parsed upstream URLs and timeouts;
- effective downstream OAuth scopes;
- per-domain transports and credential-provider configuration;
- the credential-cache namespace derived from the security-relevant domain configuration;
- audit and limiter configuration;
- the generation content hash; and
- a manifest content hash.

Reload is parse, validate, compile, build, preflight, then one `atomic.Pointer` swap. Any failure leaves the old runtime active. File replacement, write, rename, and SIGHUP trigger reload. After a successful swap the old runtime stops accepting new work, waits for its bounded drain period, closes idle transports, flushes audit work, and releases credential and cache resources.

The listen address, OIDC issuer, and signing key location require restart and cannot change through hot reload.

## 5. Argument mapping

- Path values replace complete placeholder segments and are escaped as path segments.
- Query values use `query_name` or the flag name. `stringArray` emits repeated parameters.
- Body values form one JSON object.
- Header values use `header_name`; `stringArray` headers are not supported in v0.3.
- User values never influence scheme, host, port, or static path text.
- Header values containing CR, LF, NUL, or other control characters are rejected.

Commands do not define OAuth permission scopes. The CLI requests identity scopes
only; downstream OAuth providers retain their own explicit delegated scopes.

## 6. Authentication and invoker trust

### 6.1 OIDC mode

The CLI is an OAuth public client. It obtains tokens directly from the configured authorization server using Authorization Code with PKCE or Device Authorization Grant. Refresh is also performed directly between the CLI and authorization server. cli-gateway is the protected resource and does not proxy authorization, token, or refresh requests by default.

The gateway publishes RFC 9728 Protected Resource Metadata for each MCP resource and returns its URL in `WWW-Authenticate` challenges. It verifies signed JWT access tokens using issuer discovery and JWKS, including signature, an explicit algorithm allowlist, expiry, not-before, issuer, audience/resource, authorized party where configured, and bounded clock skew.

Provider interoperability is explicit rather than inferred. Protected Resource
Metadata publishes the configured `resource_parameter`, and the CLI sends:

- `both`: both RFC 8707 `resource` and Auth0-style `audience`;
- `audience`: only `audience`;
- `resource`: only `resource`;
- `none`: neither parameter.

The JWKS manager supports HTTP cache headers, background refresh, immediate refresh on an unknown `kid`, bounded stale-if-error behavior, and current/previous key overlap. Token validation never falls back to accepting an unverifiable token.

v0.3 requires JWT access tokens. Opaque access tokens are unsupported until introspection is specified.

### 6.2 Trusted JWT mode

The server verifies the bearer JWT against `trusted_jwks`, including an explicitly configured `issuer` and `audience`. Claim names may be mapped. `/auth/*` returns 404. The CLI may obtain a token externally; phase one supports `CLI_GATEWAY_TOKEN`. HTTP issuer and JWKS URLs are accepted only in development so the local integration stack can run without an external IdP; production requires HTTPS.

### 6.3 Principal and invoker

Trusted invoker precedence is:

1. verified token `invoker` claim;
2. server-side mapping from a verified `client_id` or `azp`;
3. otherwise `unknown`.

`X-Cli-Gateway-Invoker: ai` can only reduce privileges. It cannot create human privilege. `unknown` uses the same maximum risk as `ai`. MCP tool calls always use `ai`.

### 6.4 CLI token storage and refresh

- Access tokens remain in memory and are never written to the CLI configuration file.
- Refresh tokens are stored only through the operating-system keyring.
- Refresh is single-flight per region and identity so concurrent CLI commands trigger at most one refresh.
- A request may refresh and retry only when authentication fails before any upstream invocation is dispatched.
- Logout removes local keyring entries and best-effort calls the authorization server revocation endpoint when one is advertised.
- Manifest cache entries are isolated by server, authenticated subject/session binding, and effective invoker. Raw tokens are never used as filenames.

## 7. Outbound identity and authentication

All inbound `X-Cli-Gateway-*` headers are consumed or removed before processing. The gateway constructs trusted outbound headers itself.

For `signed-identity`, the gateway sends an ES256 JWT in `X-Cli-Gateway-Identity`:

```json
{
  "iss": "cli-gateway",
  "aud": "inventory-api",
  "sub": "zhangsan",
  "invoker": "human",
  "trace_id": "0123456789abcdef0123456789abcdef",
  "iat": 0,
  "exp": 60
}
```

JWT headers contain `alg=ES256` and `kid`. `/jwks` publishes the current key and the previous key during rotation. Backend SDKs verify algorithm, signature, key ID, issuer, audience, and expiry.

Downstream modes:

- `signed-identity`: default; do not forward inbound Authorization.
- `bearer-passthrough`: forward only when explicitly configured and the downstream audience contract is valid.
- `token-exchange`: exchange the inbound user JWT using RFC 8693 and send only the exchanged bearer token downstream.
- `client-credentials`: obtain a service token when no user delegation is required. This mode never claims to act on behalf of the inbound user.
- `authorization-code`: redirect the authenticated user to the downstream
  provider once, store that user's downstream refresh token encrypted, and
  send only the resulting downstream access token to that domain.

### 7.1 Downstream credential manager

Invocation code requests a credential from one domain-scoped `CredentialProvider`. Providers implement signed identity, token exchange, client credentials, and reviewed bearer passthrough. Providers own no routing or policy decisions.

The authorization-code provider returns `E_DOWNSTREAM_AUTH_REQUIRED` until the
user completes `POST /oauth/downstream/{domain}/authorize` and the public
`GET /oauth/downstream/callback`. Pending state is random, one-time, expires
quickly, and is bound to the authenticated principal, domain, configuration
digest, redirect URI, and PKCE verifier. Tokens are keyed by opaque HMAC values
over issuer, tenant, subject, domain, and provider configuration. Raw identity
or token values never appear in the file.

Token exchange requires:

- exact target audience/resource and normalized requested scopes;
- a validated token endpoint with redirects disabled;
- optional private CA and mTLS client authentication;
- response validation for `access_token`, Bearer `token_type`, `expires_in`, and JWT `exp` when present;
- sanitized errors that never expose authorization-server bodies or credentials; and
- structured success/failure audit events carrying correlation ID but no token values.

OAuth token endpoints use `client_secret_basic` unless a domain explicitly
sets `token_endpoint_auth_method: client_secret_post`. The latter supports
providers such as GitHub Apps without putting a confidential-client secret in
the distributed CLI binary.

### 7.2 Credential cache

Remote token-exchange and client-credentials results are cached. Request-bound signed identity tokens are not cached because they contain command and trace claims.

Authorization-code grants use a persistent AES-256-GCM file store in production.
Writes are atomic and mode `0600`; access and refresh tokens are never exposed
to the CLI. Access-token refresh is single-flight per user/domain/config key.
Permanent refresh rejection deletes the grant and requires browser
authorization again; a transient refresh failure may use the previous access
token only until its hard expiry.

The credential cache provides:

- a bounded in-process backend;
- an HMAC-derived key over issuer, tenant, subject/session binding, downstream domain, provider configuration digest, audience/resource, sorted scopes, and requested token type;
- hard expiry from the minimum trustworthy token lifetime and an earlier `serve_until` refresh boundary;
- per-key single-flight with a double-check after acquiring the flight;
- jittered refresh-ahead while a still-valid token may continue serving;
- short negative caching only for transient timeout, 429, and 5xx failures;
- invalidation on provider configuration change, downstream `invalid_token`, explicit operator flush, and available logout/revocation events;
- no raw token, email, subject token, or client secret in a cache key or log;
- encryption of bearer-token values before writing to a distributed cache; and
- hit, miss, refresh, eviction, failure, and waiter metrics without principal labels.

## 8. Policy

Gateway authorization requires all of:

1. the requested operation resolves to a compiled manifest command;
2. `ai` or `unknown` risk does not exceed `policy.ai_max_risk`; and
3. a destructive invocation is confirmed.

The downstream business system is authoritative for whether the authenticated
user may perform the requested operation.

Destroy confirmation sources are adapted before policy evaluation:

- HTTP: `X-Cli-Gateway-Confirm: true`;
- CLI: `--yes`, or interactive exact command confirmation;
- MCP: required boolean tool argument `confirm`.

The MCP adapter removes `confirm` from business arguments. List endpoints filter
commands by effective invoker risk, but execution always re-authorizes the
safety policy.

## 9. HTTP API

### 9.1 Public endpoints

- `GET /livez` reports process liveness only.
- `GET /readyz` reports whether a complete runtime generation is available and mandatory local dependencies are usable. It returns 503 when unready.
- `GET /healthz` is a compatibility alias for liveness.
- `GET /version` returns build version, commit, Go version, manifest version, and runtime generation without secrets.
- `GET /metrics` exposes Prometheus metrics when enabled.
- `GET /jwks` returns public signing keys.
- `GET /.well-known/oauth-protected-resource...` returns RFC 9728 metadata matching the actual MCP resource URI.

### 9.2 Authentication support endpoints

- `GET /whoami` returns the authenticated subject, effective invoker, client ID, and non-sensitive effective scopes.
- `/auth/*` is not implemented in the default protected-resource deployment. The CLI follows authorization-server metadata directly.

### 9.3 Manifest endpoint

`GET /manifest` requires authentication and returns the command tree filtered by effective invoker risk.

Responses use an ETag calculated from the filtered representation and include:

```http
Cache-Control: private
Vary: Authorization
```

`If-None-Match` returns 304 when appropriate.

### 9.4 Execution endpoint

`POST /exec/{domain}/{command}` accepts `{"args":{...}}` and follows this order:

1. validate or generate trace ID and consume all `X-Cli-Gateway-*` headers;
2. authenticate and build Principal;
3. resolve command;
4. validate arguments;
5. authorize invoker/risk and confirmation;
6. construct the upstream request and trusted headers;
7. dispatch once, with no automatic retry;
8. normalize the response; and
9. complete audit for every exit path.

All error responses include the trace ID. Authentication errors include a standards-compliant `WWW-Authenticate` header. Expired credentials use `E_AUTH_EXPIRED`, while signature, issuer, audience, and malformed-token failures use `E_AUTH_INVALID`.

Errors use:

```json
{"ok":false,"error":"E_CODE","message":"human message","hint":"next action","trace_id":"..."}
```

Required codes are `E_AUTH_MISSING`, `E_AUTH_INVALID`, `E_AUTH_EXPIRED`, `E_AI_RISK_FORBIDDEN`, `E_CONFIRM_REQUIRED`, `E_CMD_NOT_FOUND`, `E_ARG_INVALID`, `E_RATE_LIMITED`, `E_OVERLOADED`, `E_CANCELLED`, `E_DOWNSTREAM_AUTH`, `E_TOKEN_EXCHANGE`, `E_UPSTREAM`, `E_UPSTREAM_TIMEOUT`, `E_UPSTREAM_UNREACHABLE`, and `E_INTERNAL`.

## 10. MCP endpoint

`/mcp` uses Streamable HTTP from the official Go SDK and the same bearer authentication middleware as `/exec`.

- POST, GET, and DELETE semantics follow the negotiated MCP protocol version.
- Authentication and resource authorization complete before a session is created or resumed.
- Stateful sessions, when enabled, are bound to authenticated principal, MCP resource, and runtime generation. Session IDs are accepted only from the protocol header and have a strict length and character allowlist.
- `tools/list` converts authorized commands to tools named `<domain>_<path_parts>`.
- Descriptions append `[risk:<risk>]`.
- Input schemas come from compiled flags.
- Destroy tools require a boolean `confirm` property.
- Commands above the effective AI risk limit are omitted.
- `tools/call` adapts arguments into the shared invocation service with invoker fixed to `ai`.
- `notifications/cancelled` and client disconnect cancel the matching upstream invocation through a shared run registry.
- A successful runtime reload emits `notifications/tools/list_changed` to eligible active sessions.
- Streaming commands preserve cancellation and backpressure. MCP adapters buffer only where the negotiated result shape requires it, for at most 30 seconds and 4 MiB, then return captured content plus a truncation indicator.

MCP authorization failures must not reveal hidden tool existence.

## 11. Upstream HTTP safety

Each domain owns one `http.Transport` with:

- `MaxIdleConnsPerHost=128` and `MaxConnsPerHost=256`; the earlier value of 16 caused connection churn and intermittent dial failures under sustained 128-way concurrency in the local E2E benchmark;
- `TLSHandshakeTimeout=5s`;
- `ResponseHeaderTimeout=min(domain timeout, 30s)`;
- overall timeout equal to domain timeout, default 30 seconds;
- no overall timeout for streaming, with a 15-minute idle timeout; and
- no automatic retry.

Request bodies are limited to 1 MiB. Buffered responses are limited to 4 MiB. Upstream error bodies are limited to 64 KiB.

A safe `DialContext` resolves and validates every address at connection time, including IPv6 and IPv4-mapped IPv6. It dials only validated addresses. Redirects are disabled by default and can never cross hosts.

Hop-by-hop headers and headers named by the `Connection` header are removed.

The invocation service returns a closeable execution body rather than unconditionally buffering. HTTP and CLI adapters may stream it directly. An adapter that buffers is responsible for the relevant size and time limit. Closing the body releases the upstream connection and completes outcome accounting.

Each domain has:

- a bounded in-flight semaphore and queue policy;
- an optional request-rate budget by subject/client and command risk;
- a circuit breaker for connection and 5xx failures;
- no automatic replay of business requests; and
- explicit overload errors with `Retry-After` when available.

Read-only requests may be retried only by a separately reviewed idempotency policy. Write and destroy requests are never automatically retried after dispatch.

## 12. Trace and audit

Trace IDs are exactly 32 hexadecimal characters. Invalid inbound values are replaced. Response headers, upstream requests, structured logs, identity assertions, and audit use the same trace ID.

Audit sinks are asynchronous and best-effort. Queue capacity is 1024. A full queue drops the event, increments a dropped counter, and logs a warning; it never rejects business traffic.

Audit does not record argument values, only argument keys.

Non-streaming calls emit one completion event containing both policy decision and outcome. Streaming calls emit `stream_started` before the first byte and `stream_completed` on success, error, timeout, or disconnect.

Audit entries include runtime generation, authentication method, downstream credential mode, policy decision, cache result category, upstream status, latency, and argument keys. They never contain request argument values, Authorization headers, cookies, subject tokens, exchanged tokens, refresh tokens, or client secrets.

JSONL, webhook, and stdout sinks implement one common sink contract. Webhook delivery has its own bounded timeout and circuit breaker and cannot recursively traverse the gateway proxy path. Shutdown drains the queue for a bounded duration.

The gateway accepts W3C `traceparent` and `tracestate`, generates a valid trace when missing, propagates the trace to upstream requests, logs, audit, metrics exemplars, and credential exchange, and continues returning `X-Cli-Gateway-Trace-Id` as a compatibility alias.

Required metrics include request totals and duration, in-flight executions, policy denials, authentication failures, upstream failures, limiter rejections, token-cache outcomes, token-exchange duration and failures, audit drops, manifest reload outcomes, active runtime generation, and active MCP sessions. User identifiers, tokens, raw paths with IDs, and unbounded command values are forbidden metric labels.

```json
{
  "ts":"2026-07-22T10:00:00Z",
  "event":"completed",
  "trace_id":"...",
  "sub":"zhangsan",
  "invoker":"ai",
  "cmd":"inventory.resource.apply",
  "risk":"write",
  "decision":"allow",
  "deny_reason":null,
  "outcome":"success",
  "status":201,
  "latency_ms":132,
  "client":"cg-cli/0.2.0",
  "arg_keys":["cpu","type"]
}
```

## 13. CLI

Built-ins are `login`, `logout`, `whoami`, `config`, `update-commands`,
`capabilities`, `authorize`, `disconnect`, `version`, and Cobra's
help/completion commands. `capabilities` refreshes and prints the
caller-filtered manifest as table, JSON, or YAML so terminal agents can inspect
the exact command and argument schema before execution.
Dynamic commands are generated from `/manifest` using Cobra.

Production deployments may expose `GET /install.sh` and fixed-name artifacts
under `GET /downloads/`. The installer supports macOS/Linux on amd64/arm64,
verifies an adjacent SHA-256 file before installation, and configures the
gateway's production region. Download routing is an exact allowlist and never
maps arbitrary URL paths into the filesystem.

- Configuration lives at `~/.config/<cli>/config.yaml`.
- Refresh tokens use the OS keyring. If the keyring is unavailable, persistent login fails closed; a process-scoped access token supplied through the environment remains available for automation.
- Manifest cache lives under `~/.cache/<cli>/` and refreshes after 24 hours using ETag.
- The default brand is `cg`. A build-time `CLI_NAME` creates an isolated
  white-label client whose root command, environment prefix, config/cache
  directories, keyring service, User-Agent, help, manifest validation, and
  downstream authorization hints use the branded name.
- A branded client accepts only a catalog whose `cli.name` matches its build
  identity. OAuth `client_id` remains server-discovered and independent.
- Network failure may use stale command metadata, but server-side authorization remains authoritative.
- Required flags are checked locally.
- `--yes` controls destroy confirmation.
- Non-TTY destroy calls without `--yes` fail without prompting.
- `-o json` prints the original JSON response.
- Authentication exit code is 3, argument error is 2, upstream/server failure is 4, success is 0.
- One expired-token refresh and retry is allowed only before an upstream invocation has been sent.

## 14. Rate limiting, concurrency, and failure policy

Rate limiting and concurrency admission are separate:

- Rate limiting controls request budget by trusted client identity, subject, domain, and command risk.
- Concurrency limiting controls in-flight work globally and per domain.
- A request rejected before dispatch returns 429 with a bounded `Retry-After`.
- A request rejected because the process cannot safely accept more work returns 503.
- Unknown or unauthenticated callers are limited before expensive JWT, JWKS, and token-exchange work where an IP boundary is trustworthy.
- Authenticated destructive work uses the strictest tier.
- The shipped limiter is process-local. A future distributed implementation
  must define explicit failure policy and must never silently make write or
  destroy traffic unlimited.

Circuit breakers protect token endpoints, audit webhooks, and upstream services independently. Opening one dependency breaker must not open unrelated domains. Breaker state is observable and bounded in cardinality.

## 15. Secrets, keys, and egress

- Production secrets use `env:`, `file:`, or a registered secret-provider reference.
- Secret values are resolved only when constructing a runtime generation and are never included in snapshots returned by diagnostics.
- Signing keys support current and previous keys, explicit key IDs, scheduled rotation, and bounded verification overlap.
- Token, JWKS, webhook, and upstream clients support private CA bundles and optional mTLS.
- Token and JWKS clients never follow redirects.
- Upstream redirects are disabled unless a command explicitly enables a same-origin redirect policy.
- DNS is resolved and every result is checked at connection time. The connection is made to a validated address to prevent DNS rebinding between validation and dial.
- Cloud metadata, unspecified, multicast, link-local, loopback, and disallowed private ranges are rejected according to the domain egress policy.

## 16. Runtime lifecycle

A runtime generation is immutable after publication. Each invocation retains its generation until its execution body closes. Reload publication and old-generation drain are observable.

Shutdown order is:

1. mark readiness false;
2. stop accepting new executions;
3. notify MCP sessions of shutdown where supported;
4. cancel work after the configured drain timeout;
5. close execution bodies and upstream idle connections;
6. drain audit and observability exporters; and
7. close cache, keyring, and secret-provider clients.

Background loops use the process context, expose health state, apply jittered backoff, and stop synchronously during shutdown.

## 17. Extension contracts

The core supports small typed extension contracts without a dynamic in-process plugin runtime:

- `CatalogSource`
- `CredentialProvider`
- `SecretProvider`
- `AuditSink`
- `MetricsExporter`
- `Authorizer`

Extensions receive typed, redacted inputs. They cannot access raw inbound bearer or refresh tokens unless their contract explicitly requires that credential. A future out-of-process extension protocol is preferred over loading arbitrary Go plugins.

## 18. Testing and release requirements

Required automated coverage includes:

- table-driven validation, policy, cache-key, expiry, and error-classification tests;
- deny-path security tests for missing auth, wrong audience, excessive invoker risk, hidden command, expired or wrong-audience identity assertions, session replay, forged identity headers, backend permission denial, and disabled features;
- race tests for runtime reload, token single-flight, audit shutdown, and cancellation;
- fuzz tests for manifest parsing, argument mapping, trace headers, session IDs, JWT headers, and upstream URL construction;
- E2E tests for CLI → authorization server → cli-gateway → multiple downstream audiences;
- MCP Inspector acceptance for initialization, listing, calling, cancellation, reload notification, GET stream, and DELETE session;
- load tests for direct and gateway paths, cold token-exchange bursts, slow clients, upstream stalls, and graceful shutdown; and
- failure injection for JWKS, authorization server, audit webhook, DNS, and upstream outages.

Releases provide checksummed multi-platform CLI binaries, container images, SBOMs, provenance/signatures, a compatibility matrix, upgrade notes, and a documented vulnerability-reporting process.

## 19. Milestones

### M0: core contracts

Deliver Principal, CompiledCommand, Invocation, Execution, APIError, AuditEvent, risk ordering, and interfaces. Add table-driven tests.

### M1: manifest and lifecycle

Deliver strict YAML load, semantic validation with positions, compilation, atomic reload through fsnotify and SIGHUP, example invalid manifests, `/healthz`, and golden snapshot tests.

### M2a: authentication, catalog, and policy

Deliver trusted JWT verification, Principal construction, filtered `/manifest`, ETag behavior, invoker-risk/confirmation policy, and deny audit.

### M2b: HTTP invocation

Deliver `/exec`, safe URL builder, safe Dialer, header policy, transport limits, response normalization, streaming, and the full error table.

### M2c: runtime generation and streaming contract

Deliver the catalog service, immutable runtime generation, closeable execution body, graceful generation drain, run registry, and reload lifecycle tests.

### M3a: identity, JWKS, and downstream credentials

Deliver ES256 identity JWT, audience and key ID enforcement, `/jwks`, signing-key rotation window, OIDC discovery/JWKS manager, RFC 8693 token exchange, client credentials, credential cache, and downstream verification middleware.

### M3b: audit, observability, and admission

Deliver JSONL/stdout/webhook audit sinks, bounded drain behavior, metrics, W3C tracing, liveness/readiness, rate limiting, concurrency admission, circuit breakers, and overload tests.

### M4: CLI and OIDC

Deliver Authorization Code with PKCE and Device Flow, keyring, single-flight token refresh, logout/revocation, whoami, dynamic Cobra commands, local validation, confirmation, cache, streaming, and output modes.

### M5: MCP adapter

Deliver authenticated Streamable HTTP POST/GET/DELETE, RFC 9728 metadata and challenges, filtered tools/list, shared tools/call execution, confirm adaptation, session ownership, cancellation, tools/list_changed, bounded streaming fallback, and MCP Inspector acceptance tests.

### M6: open-source and release hardening

Deliver public documentation, threat model, security policy, contribution
workflow, container and Kubernetes examples, SBOM/provenance, compatibility
guarantees, E2E and load environments, checksummed multi-platform releases, and
white-label client builds.

Every milestone has a `make verify-mN` target and table-driven tests. A change does not advance milestones until its corresponding verification target passes.
