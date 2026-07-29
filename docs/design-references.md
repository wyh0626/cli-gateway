# Design references

CLI Gateway is an original Go implementation. It does not copy source code from
the projects below. Their public designs and user experience informed specific
decisions.

## Projects

### ContextForge

[IBM ContextForge](https://github.com/IBM/mcp-context-forge) informed the clear
separation between gateway login and per-user downstream OAuth, encrypted
user-scoped token storage, refresh-token handling, and a shared governance
boundary for HTTP APIs and MCP tools.

CLI Gateway intentionally has a smaller scope: one binary, one declarative
manifest, no built-in user database, no management UI, and no mandatory
database.

### GitHub CLI

[GitHub CLI](https://github.com/cli/cli) informed device-friendly browser
authentication, predictable command trees, machine-readable output, shell
completion, and explicit authentication status commands. CLI Gateway differs
by downloading its business command catalog from the server.

### kubectl

[kubectl](https://github.com/kubernetes/kubectl) informed the stable root
command, context-like region selection, `-o` output behavior, discovery before
execution, and keeping authorization decisions on the server.

### Envoy and Kong

[Envoy](https://github.com/envoyproxy/envoy) and
[Kong Gateway](https://github.com/Kong/kong) informed the data-plane/control-
plane boundary, strict declarative configuration, bounded retries, health
endpoints, circuit breaking, and metrics. CLI Gateway does not attempt to
replace a general L7 proxy.

## Standards

- OAuth 2.0 for Native Apps: RFC 8252
- OAuth 2.0 Device Authorization Grant: RFC 8628
- OAuth 2.0 Token Exchange: RFC 8693
- OAuth 2.0 Protected Resource Metadata: RFC 9728
- OAuth 2.0 Security Best Current Practice: RFC 9700
- Proof Key for Code Exchange: RFC 7636
- OAuth 2.0 Resource Indicators: RFC 8707
- Model Context Protocol Streamable HTTP transport

When a project and a standard conflict, the security requirements in the
standards and this repository's threat model take precedence.
