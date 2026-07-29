# Threat model

## Assets

- inbound access and refresh tokens;
- downstream exchanged or client-credentials tokens;
- gateway signing keys and downstream client secrets;
- command catalog, safety policy, backend authorization, and audit evidence; and
- internal upstream services reachable from the gateway.

## Trust boundaries

The CLI, MCP clients, authorization server, cli-gateway process, optional distributed
cache, audit sinks, and every upstream domain are separate trust boundaries.
An authenticated client is not trusted to choose its invoker classification,
downstream audience, upstream URL, identity headers, or command ownership.

## Primary threats and controls

| Threat | Required control |
| --- | --- |
| Forged user or AI identity | Derive identity only from a verified token and server mapping; strip inbound `X-Cli-Gateway-*` |
| Confused deputy | Resolve only compiled commands, enforce invoker risk and confirmation, restrict each identity assertion to the backend audience, and require the backend to authorize the user |
| Bearer-token replay or leakage | Do not forward inbound bearer by default; never log tokens; keep refresh tokens in OS keyring |
| SSRF and DNS rebinding | Compile fixed origins, validate every resolved address at dial time, disable redirects |
| Cache credential crossover | HMAC cache keys over tenant, subject/session, provider digest, audience, and scopes |
| Reload use-after-close | Retain one immutable runtime generation through response-body close |
| MCP session hijack | Authenticate before session creation and bind session to principal, resource, and generation |
| Resource exhaustion | Bound request/response bodies, queues, caches, concurrency, and rate budgets |
| Audit-driven outage | Use a bounded best-effort audit queue and independent sink breakers |
| Secret disclosure in diagnostics | Resolve references at runtime construction and expose only redacted configuration |

## Deployment assumptions

TLS terminates at a trusted edge or at cli-gateway. The authorization server publishes
correct issuer metadata and rotates keys with overlap. Hosts running cli-gateway
protect its manifest, signing key, keyring, and environment. Private upstream
DNS and firewall rules are still required; application-level SSRF protection is
defense in depth, not a replacement for network policy.
