# Engineering Rules

- Use Go 1.25.12 or newer. The canonical module path is `github.com/wyh0626/cli-gateway`.
- Dependencies are limited to the Go standard library plus the allowlist in `docs/implementation-spec.md`. Ask before adding another dependency.
- Keep protocol adapters thin. HTTP `/exec` and MCP `tools/call` must call the same invocation service.
- Treat `invoker` as trusted only when derived from a verified token claim or a server-side client mapping. Client headers may only reduce privileges.
- Never forward an inbound bearer token unless the target domain explicitly selects `bearer-passthrough` and its audience contract has been reviewed.
- Strip every inbound `X-Cli-Gateway-*` header before constructing trusted outbound headers.
- Business errors use `internal/httpx.APIError`; never return an internal error string to clients.
- Use `log/slog` with JSON output. Include `trace_id` when one exists; do not use `fmt.Println` for application logging.
- Manifest reload is compile-then-swap. A failed reload must leave the previous immutable snapshot active.
- Use table-driven tests for validation and policy behavior. Every milestone has a matching `make verify-mN` target.
- Do not add databases, Redis, service discovery, load balancing, a general policy engine, or automatic upstream retries before 1.0 without an approved design.
