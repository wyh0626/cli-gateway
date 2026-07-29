# Auth0 Device Flow quick start

This tutorial replaces the bundled development issuer with Auth0 while keeping
the demo API local. Auth0 currently offers a no-credit-card free plan; always
check the [current pricing page](https://auth0.com/pricing) before depending on
plan limits.

Device Authorization is used because it is CLI-friendly and does not require a
fixed loopback callback port.

## 1. Create an Auth0 API

In the Auth0 dashboard:

1. Open **Applications → APIs → Create API**.
2. Name it `CLI Gateway`.
3. Set **Identifier** to `https://cli-gateway.local`.
4. Select `RS256`.
5. Enable **Allow Offline Access**.

The identifier becomes the JWT access-token audience verified by CLI Gateway.

## 2. Create a Native application

1. Open **Applications → Applications → Create Application**.
2. Select **Native** and name it `CG CLI`.
3. Under **Advanced Settings → Grant Types**, enable:
   - Authorization Code
   - Device Code
   - Refresh Token
4. Enable refresh-token rotation.
5. Enable at least one database or social connection for the application.

Auth0's Device Authorization endpoint issues a refresh token only when the
application allows Refresh Token, the API allows offline access, and the CLI
requests `offline_access`. CLI Gateway's client does this automatically.

Official references:

- [Device Authorization Flow](https://auth0.com/docs/quickstart/native/device)
- [Authorization Code with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce/call-your-api-using-the-authorization-code-flow-with-pkce)
- [Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)

## 3. Configure CLI Gateway

Copy [examples/auth0/manifest.yaml](../../examples/auth0/manifest.yaml) and
replace:

- `issuer` with the exact Auth0 tenant issuer, without inventing a custom path;
- `client_id` with the Native application's Client ID;
- `audience` only if you chose a different API Identifier.

Keep `resource_parameter: audience`. It prevents the CLI from sending an RFC
8707 `resource` parameter to a tenant configured for Auth0's audience
extension.

## 4. Run and log in

```bash
make build
go run ./cmd/demoapi
```

In another terminal:

```bash
go run ./cmd/cli-gateway -manifest examples/auth0/manifest.yaml
```

Then:

```bash
./bin/cg config add-region auth0 http://127.0.0.1:18082 \
  --display-name "Auth0 local gateway"
./bin/cg config use-region auth0
./bin/cg login --device
./bin/cg whoami
./bin/cg demo item get --id seed -o json
```

The CLI stores only the refresh token in the operating-system keyring. Access
tokens remain process-local and are refreshed when needed.

## Troubleshooting

- **`audience is invalid`**: the manifest audience must exactly equal the
  Auth0 API Identifier.
- **No refresh token**: enable Refresh Token on the Native application, enable
  Allow Offline Access on the API, then log in again.
- **Gateway rejects the access token**: verify the issuer, audience, and RS256
  signing algorithm; do not pass an ID token.
- **Device endpoint unavailable**: enable Device Code in the application's
  grant types.
