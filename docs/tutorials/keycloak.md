# Local Keycloak quick start

This example runs a real open-source OIDC provider, CLI Gateway, and the demo
API locally. It is the recommended integration test before configuring a
hosted identity provider.

The Compose file tracks the version shown in Keycloak's
[official Docker quick start](https://www.keycloak.org/getting-started/getting-started-docker).
Review and update the pinned image deliberately.

## Start the environment

```bash
docker compose -f examples/keycloak/compose.yaml up --build -d
```

Wait until discovery is ready:

```bash
curl -fsS \
  http://127.0.0.1:18080/realms/cli-gateway/.well-known/openid-configuration \
  | jq .issuer
curl -fsS http://127.0.0.1:18082/readyz
```

The imported development realm contains:

- realm: `cli-gateway`
- public native client: `cg-cli`
- the CLI sends PKCE `S256` for browser authorization
- Device Authorization enabled
- access-token audience mapper: `cli-gateway`
- demo user: `demo`
- demo password: `demo`

These credentials are intentionally public and must never be reused outside
this local example.

## Log in and call the demo API

```bash
make build-client
./bin/cg config add-region keycloak http://127.0.0.1:18082 \
  --display-name "Local Keycloak"
./bin/cg config use-region keycloak
./bin/cg login --device
```

Open the displayed URL and sign in with `demo` / `demo`, then:

```bash
./bin/cg whoami
./bin/cg capabilities -o json
./bin/cg demo item get --id seed -o json
```

Stop and remove the environment:

```bash
docker compose -f examples/keycloak/compose.yaml down -v
```

## Production differences

Do not use `start-dev`, imported plaintext users, public admin credentials, or
HTTP in production. Configure a database, TLS, hostname validation, backup,
admin separation, MFA, event auditing, and explicit redirect URIs. Keycloak's
special native callback `http://127.0.0.1` permits random loopback ports; avoid
the unrestricted `*` redirect URI. If production policy must reject every
non-PKCE authorization request, use a dedicated browser-login client with
Keycloak's S256 requirement and a separate Device Flow client; the local
single-client example favors easy testing of both flows.
