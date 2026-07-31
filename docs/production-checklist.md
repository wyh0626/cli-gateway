# Production checklist / 生产上线清单

This checklist complements the implementation specification and threat model.
It is not a substitute for an organization-specific security review.

## Identity and authorization / 身份与授权

- [ ] Use a production OAuth/OIDC issuer over HTTPS.
- [ ] Register the CLI as a public client; require PKCE and/or Device Flow.
- [ ] Configure exact issuer and audience validation; do not accept arbitrary
      issuers or audiences.
- [ ] Keep CLI login scopes identity-only; do not model backend permissions in
      the OAuth consent screen.
- [ ] Verify every backend authorizes the signed user for the requested
      business operation.
- [ ] Review human, CI, and AI invoker risk limits.
- [ ] Require explicit confirmation for every destructive command.
- [ ] Verify deny paths: missing token, wrong audience, wrong invoker, missing
      confirmation, expired identity assertion, and backend permission denial.

## Downstream credentials / 后端凭证

- [ ] Select one explicit downstream authentication mode for every domain.
- [ ] Prefer signed identity or a real RFC 8693 exchange for first-party APIs.
- [ ] Give each backend a distinct audience/resource.
- [ ] Confirm that token exchange is actually implemented by the authorization
      server; accepting a grant type in client metadata is not sufficient.
- [ ] Restrict bearer passthrough to a reviewed same-token trust boundary.
- [ ] For Authorization Code mode, configure encrypted persistent storage,
      refresh rotation, revocation, and a provider-approved redirect URI.
- [ ] Never place client secrets or tokens directly in the manifest.

## Keys, secrets, and data / 密钥、Secret 与数据

- [ ] Generate a persistent P-256 downstream identity key outside the image.
- [ ] Document and test current/previous key rotation.
- [ ] Store secret references in a secret manager or protected files.
- [ ] Protect the downstream OAuth encryption key and token-store volume.
- [ ] Ensure logs, traces, metrics, and audits never contain raw tokens,
      authorization codes, client secrets, or unbounded user input.
- [ ] Define retention and access policy for audit data.

## Network and TLS / 网络与 TLS

- [ ] Terminate TLS at a trusted ingress or cli-gateway and redirect/reject plaintext.
- [ ] Keep production `network.allow_local` disabled unless explicitly needed
      and reviewed.
- [ ] Restrict egress to approved issuer, JWKS, token, and upstream endpoints.
- [ ] Install private CA bundles explicitly; do not enable insecure TLS.
- [ ] Disable upstream redirects unless a reviewed same-origin policy requires
      them.
- [ ] Apply request/body/response/stream time and size limits.

## Availability and scaling / 可用性与扩容

- [ ] Size global and per-domain concurrency and rate limits from load tests.
- [ ] Configure readiness, liveness, graceful termination, and a disruption
      budget.
- [ ] Use session affinity for legacy stateful MCP clients before running
      multiple replicas. MCP `2026-07-28` stateless requests need no affinity.
- [ ] Keep the encrypted file token store on one writer. Use an audited shared
      store before multi-replica downstream Authorization Code operation.
- [ ] Decide whether process-local caches, breakers, and quotas are acceptable;
      otherwise implement and test distributed coordination deliberately.
- [ ] Test dependency timeouts, breaker behavior, cancellation, and recovery.

## Operations / 运维

- [ ] Send structured logs and metadata-only audit records to durable sinks.
- [ ] Scrape metrics and configure alerts for auth failures, policy denials,
      upstream failures, token exchange, cache behavior, saturation, audit
      drops, and reload failures.
- [ ] Propagate W3C trace context without sensitive attributes.
- [ ] Test manifest reload failure and confirm the previous generation remains
      active.
- [ ] Maintain rollback procedures for binary, manifest, and signing keys.

## Supply chain and release / 供应链与发布

- [ ] Verify `/install.sh` uses the configured HTTPS `public_url`, serves only
      allowlisted artifacts, and rejects missing or unknown downloads with 404.
- [ ] Publish separate macOS/Linux amd64/arm64 binaries and matching SHA-256
      files; test checksum failure before announcing the installer.
- [ ] Keep the installer and downloads public but read-only; never place
      manifests, keys, tokens, or configuration in the download directory.
- [ ] Verify the canonical Go module path, container image, repository links,
      and release download URLs before publishing.
- [ ] Confirm organizational approval for Apache-2.0 and publish a private
      security contact.
- [ ] Pin CI actions and dependencies according to organizational policy.
- [ ] Run `make verify` and `make test-race`.
- [ ] Generate checksums, SBOM, provenance, and platform code signatures.
- [ ] Scan the container and Go dependencies for known vulnerabilities.
- [ ] Publish supported-version and security-reporting policy.
