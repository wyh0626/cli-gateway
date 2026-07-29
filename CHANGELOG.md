# Changelog

This project follows Keep a Changelog structure. It has not made its first
stable release.

## Unreleased

### Added

- A clean, vendor-neutral open-source distribution with the `cli-gateway`
  server, the default `cg` client, generic examples, and fresh project metadata.
- Strict manifest loading and atomic reload.
- JWT authentication, scope/risk policy, and filtered command discovery.
- Safe upstream request construction and ES256 downstream identity.
- HTTP gateway, dynamic CLI, local integration services, and load driver.
- Immutable runtime generations and closeable streaming executions.
- OIDC PKCE and Device Flow login with OS-keyring refresh-token rotation.
- Authenticated MCP Streamable HTTP with generation-aware sessions and reload notifications.
- RFC 8693 token exchange, client credentials, and bounded coalescing token cache.
- Per-user downstream OAuth Authorization Code + PKCE, encrypted persistent
  refresh-token storage, CLI first-use authorization, and coalesced refresh.
- Rate/concurrency admission, independent circuit breakers, Prometheus metrics, and bounded audit sinks.
- Current/previous downstream signing-key publication for safe rotation.
- Container, Compose, Kubernetes, CI, release checksums, SBOM, and provenance workflows.
- Build-time white-label CLI branding with isolated environment variables,
  config/cache directories, keyring entries, User-Agent, manifest validation,
  and downstream authorization hints.
- English and Simplified Chinese onboarding, white-label build instructions,
  and a production-readiness checklist.
- The canonical Go module path `github.com/wyh0626/cli-gateway`.
- Checksum-verifying client installation, documentation index, project
  governance, support guidance, design references, and an explicit roadmap.
- Runnable local Keycloak integration plus Auth0 Device Flow and GitHub App
  per-user authorization tutorials and manifests.
- Provider-compatible inbound OAuth target parameters (`both`, `audience`,
  `resource`, or `none`) and downstream token endpoint authentication via
  `client_secret_basic` or `client_secret_post`.
- MCP Go SDK v1.4.1 and a patched Go 1.25.12 release toolchain after
  reachability-based vulnerability scanning.
