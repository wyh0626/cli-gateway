# Proxy GitHub with per-user authorization

This tutorial exposes a small, read-only GitHub command set through CLI
Gateway. It intentionally uses two separate authorizations:

1. Keycloak authenticates the user to CLI Gateway.
2. A GitHub App authorizes that user to call GitHub through the gateway.

The two tokens have different issuers, audiences, permissions, lifetimes, and
storage rules. CLI Gateway never forwards the Keycloak token to GitHub.

## Why a GitHub App

GitHub recommends GitHub Apps over traditional OAuth Apps for fine-grained
permissions, repository selection, short-lived user tokens, and refresh-token
rotation. CLI Gateway uses Authorization Code with PKCE, encrypts each user's
GitHub refresh token at rest, coalesces refreshes, and sends only the GitHub
user access token to `api.github.com`. The shared upstream pipeline also emits
a stable gateway User-Agent required by GitHub's REST API.

Official references:

- [Register a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
- [Generate a user access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [Refresh user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens)
- [GitHub REST API](https://docs.github.com/en/rest)

## 1. Register the GitHub App

In GitHub **Settings → Developer settings → GitHub Apps**, create an app:

- Homepage URL: `https://github.com/wyh0626/cli-gateway`
- Callback URL:
  `http://127.0.0.1:18082/oauth/downstream/callback`
- Webhook: disable it for this read-only tutorial
- User-to-server token expiration: keep enabled
- Repository permissions:
  - Metadata: Read-only
  - Issues: Read-only

Install the app on your account or a test organization and select only the
repositories needed for the tutorial. Generate a client secret and copy the
app's **Client ID**; the Client ID is not the numeric App ID.

## 2. Configure secrets

Edit [examples/github/manifest.yaml](../../examples/github/manifest.yaml) and
replace `replace-with-github-app-client-id`.

Export the two runtime secrets:

```bash
export CLI_GATEWAY_GITHUB_CLIENT_SECRET='your-github-app-client-secret'
export CLI_GATEWAY_OAUTH_STORE_KEY="$(openssl rand -base64 32)"
```

The second value encrypts the token store. Changing or losing it makes existing
stored grants unreadable. Never commit either value.

## 3. Start Keycloak and CLI Gateway

```bash
docker compose -f examples/github/compose.yaml up --build -d
make build-client

./bin/cg config add-region github http://127.0.0.1:18082 \
  --display-name "GitHub tutorial"
./bin/cg config use-region github
./bin/cg login --device
```

Sign in to local Keycloak with `demo` / `demo`.

## 4. Authorize GitHub

```bash
./bin/cg authorize github
```

The CLI prints and opens GitHub's authorization URL. After GitHub redirects to
the gateway callback, the terminal observes the completed authorization.

Run the generated commands:

```bash
./bin/cg github user get -o json
./bin/cg github installations list --per-page 10 -o json
./bin/cg github repositories list --per-page 10 -o json
./bin/cg github repository get --owner OWNER --repo REPOSITORY -o json
./bin/cg github issues list --owner OWNER --repo REPOSITORY --state open -o json
```

Disconnect only this gateway's stored GitHub authorization:

```bash
./bin/cg disconnect github
```

If no revocation endpoint is configured, disconnect deletes the encrypted local
grant. Revoke the app remotely from GitHub settings when immediate server-side
revocation is required.

Stop the environment and delete the local token volume:

```bash
docker compose -f examples/github/compose.yaml down -v
```

## Security notes

- Keep the command catalog read-only until repository selection and backend
  permissions are verified.
- A GitHub App user token can access only resources allowed to both the app
  installation and the user.
- Organization SAML SSO may require an active SAML session.
- The tutorial uses HTTP loopback callbacks only for local development.
  Production callback URLs must use HTTPS.
- Do not use `bearer-passthrough` for this integration.
