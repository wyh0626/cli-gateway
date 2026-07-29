# Getting started

CLI Gateway has three onboarding levels. Start locally without an account, then
switch to a real OIDC provider, and only then connect a third-party API.

## 1. Five-minute local demo

Requirements: Docker with Compose, `curl`, and `jq`.

```bash
git clone https://github.com/wyh0626/cli-gateway.git
cd cli-gateway
docker compose up --build -d

TOKEN="$(curl -fsS http://127.0.0.1:18080/token | jq -r .access_token)"
curl -fsS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:18082/manifest | jq
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"args":{"delay-ms":5}}' \
  http://127.0.0.1:18082/exec/demo/work | jq

docker compose down
```

This uses the repository's deliberately insecure development issuer and demo
API. It exercises OIDC discovery, JWT verification, dynamic command discovery,
the shared invocation pipeline, and signed downstream identity.

## 2. Try the real CLI login

Build the two binaries:

```bash
make build
```

Start the three development processes in separate terminals:

```bash
go run ./cmd/devissuer
go run ./cmd/demoapi
go run ./cmd/cli-gateway -manifest examples/e2e/manifest.yaml
```

Configure the CLI once:

```bash
./bin/cg config add-region local http://127.0.0.1:18082 \
  --display-name "Local development"
./bin/cg config use-region local
./bin/cg login --device
./bin/cg capabilities -o json
./bin/cg demo item get --id seed -o json
./bin/cg whoami
```

The device page is local and requires no credentials. Never expose
`cmd/devissuer` outside an isolated development machine.

## 3. Replace the development issuer

Choose either:

- [Auth0](tutorials/auth0.md): hosted free plan and the shortest route to a
  remotely managed OIDC provider.
- [Keycloak](tutorials/keycloak.md): open source, self-hosted, and supplied as a
  reproducible local Compose example.

CLI Gateway validates access-token signature, issuer, audience, expiry, and
not-before time. It does not accept an ID token as an API bearer token.

## 4. Connect an API

Each domain in the manifest defines:

1. the upstream URL and egress policy;
2. one downstream authentication mode;
3. an allowlist of commands, HTTP methods, paths, arguments, and risk levels;
4. concurrency and rate limits.

Start with a read-only command. Add write and destructive commands only after
the backend's authorization behavior is verified.

```yaml
domains:
  - name: inventory
    upstream: https://inventory.example.com
    downstream_auth:
      mode: signed-identity
      identity_audience: inventory-api
    commands:
      - path: [item, get]
        summary: Get one item
        method: GET
        endpoint: /v1/items/{id}
        risk: read
        flags:
          - name: id
            type: string
            required: true
            in: path
```

Reload the gateway, then run:

```bash
cg update-commands
cg inventory item get --id server-42 -o json
```

The same command is available to MCP clients as `inventory_item_get`.

## 5. Next steps

- After deployment, give users the checksum-verifying
  `curl https://YOUR-GATEWAY/install.sh | sh` bootstrap command.
- Proxy a real third-party account with the [GitHub App tutorial](tutorials/github.md).
- Select the correct downstream trust model in
  [Authentication and identity](authentication-and-identity-guide.md).
- Complete every item in the [production checklist](production-checklist.md).
