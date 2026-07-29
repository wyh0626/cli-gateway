# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/wyh0626/cli-gateway/security/advisories/new)
and include:

- affected version or commit;
- configuration and deployment shape;
- minimal reproduction steps;
- expected and observed behavior;
- security impact; and
- a safe way to contact the reporter.

Do not include production tokens, private keys, authorization codes, client
secrets, internal data, or personal data. If the repository host does not offer
private advisories, contact a maintainer privately before sending sensitive
details.

Maintainers will acknowledge a complete report, validate its scope, coordinate
a fix and release, and credit the reporter when requested. Public disclosure
should wait until a fixed release is available.

## Supported versions

Until the first stable release, only the latest published development release
is intended to receive security fixes. After 1.0, this table will be updated
with the supported release lines.

| Version | Supported |
|---|---|
| Latest pre-1.0 release | Yes |
| Older snapshots | No |

## Security-sensitive areas

Changes involving inbound authentication, token exchange, downstream
credentials, identity signing, OAuth callbacks, session ownership, SSRF/egress
validation, protected headers, secret storage, or audit redaction require
deny-path regression tests and security review.
