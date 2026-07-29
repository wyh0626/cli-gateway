# Contributing

Thank you for helping improve cli-gateway. Discuss security-sensitive,
protocol-level, or compatibility-breaking changes in an issue before starting
a large implementation. Report vulnerabilities privately according to
[SECURITY.md](SECURITY.md).

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requirements:

- Go 1.25.12 or newer
- Docker with Compose for the local integration environment
- `curl` and `jq` for the README examples

```bash
git clone https://github.com/wyh0626/cli-gateway.git
cd cli-gateway
go mod download
make verify
```

Useful commands:

```bash
make help
make build
make test
make test-race
docker compose up --build
```

## Change guidelines

- Keep HTTP and MCP adapters thin. Shared argument validation, authorization,
  credential selection, upstream construction, and auditing belong in the
  core pipeline.
- Never log credentials or accept user identity from unverified headers.
- Changes to authentication, token exchange, URL/egress validation, session
  ownership, or secret handling need success and deny-path tests.
- New manifest fields must be strict-loaded, semantically validated, compiled
  into an immutable snapshot, covered by reload compatibility, and documented
  in the implementation specification.
- Keep the default `cg` brand backward compatible. White-label behavior must be
  tested with a second name such as `acme`.
- Do not add an upstream business-request retry without an explicit
  idempotency design.

## Pull requests

1. Keep the change focused and include tests.
2. Run `make verify` and `make test-race`.
3. Update the changelog and relevant documentation for user-visible changes.
4. Use a conventional commit prefix such as `feat:`, `fix:`, `docs:`, `test:`,
   `refactor:`, or `chore:`.
5. Sign off commits with `git commit -s` to certify the
   [Developer Certificate of Origin](https://developercertificate.org/).

Pull requests should explain the problem, the security or compatibility impact,
and the validation evidence. Do not include real tokens, secrets, internal
hostnames, or personal data in issues, tests, logs, or screenshots.

## Compatibility

The project is pre-1.0. Avoid unnecessary format changes, but clearly document
any configuration migration. Once a stable release is published, breaking
manifest or API changes require a major version.
