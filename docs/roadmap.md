# Roadmap

CLI Gateway is pre-1.0. The roadmap prioritizes security and operability over
adding more protocols.

## Before 1.0

- Stabilize the manifest schema and publish migration notes.
- Add provider conformance tests for Auth0, Keycloak, GitHub Apps, and an RFC
  8693 authorization server.
- Add an optional shared store for multi-replica downstream OAuth state and
  user grants.
- Add OpenTelemetry export while preserving bounded in-process metrics.
- Add signed release installation for Windows and package-manager recipes.
- Complete independent security review of OAuth callbacks, egress controls,
  identity propagation, and audit redaction.

## Later candidates

- Dynamic Client Registration behind an issuer allowlist.
- Declarative static upstream headers with protected-header validation.
- Pluggable secret managers and distributed credential caches.
- A read-only catalog validation and visualization command.
- Additional API adapters only when they reuse the same invocation pipeline.

## Explicitly not planned

- A built-in user/password database.
- A general service mesh or arbitrary reverse proxy.
- Automatic retries for non-idempotent business operations.
- Treating the local CLI command cache as an authorization authority.
