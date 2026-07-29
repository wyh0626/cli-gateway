package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

const validManifest = `version: 1
server:
  listen: ":8080"
  public_url: https://tools.example.com
  environment: development
auth:
  mode: trusted-header
  issuer: https://auth.example.com
  trusted_jwks: https://auth.example.com/.well-known/jwks.json
  audience: cli-gateway
cli:
  name: cg
policy:
  ai_max_risk: write
audit:
  sinks:
    - type: jsonl
      path: /tmp/cli-gateway-audit.jsonl
domains:
  - name: inventory
    upstream: https://inventory.example.com/api
    timeout: 10s
    downstream_auth:
      mode: signed-identity
      identity_audience: inventory-api
    commands:
      - path: [resource, get]
        summary: Get a resource
        method: GET
        endpoint: /v1/resources/{id}
        risk: read
        flags:
          - name: id
            type: string
            required: true
            in: path
      - path: [resource, delete]
        method: DELETE
        endpoint: /v1/resources/{id}
        risk: destroy
        confirm: true
        flags:
          - name: id
            type: string
            required: true
            in: path
`

func TestLoadCompilesSnapshot(t *testing.T) {
	t.Parallel()

	snapshot, err := Load([]byte(validManifest), "test.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.CLIName != "cg" || snapshot.Environment != "development" {
		t.Fatalf("unexpected snapshot metadata: %#v", snapshot)
	}
	if len(snapshot.ETag) != 16 {
		t.Fatalf("ETag length = %d, want 16", len(snapshot.ETag))
	}

	command := snapshot.Commands["inventory.resource.get"]
	if command == nil {
		t.Fatal("compiled command inventory.resource.get is missing")
	}
	if command.ToolName != "inventory_resource_get" {
		t.Fatalf("ToolName = %q", command.ToolName)
	}
	if command.Timeout.String() != "10s" {
		t.Fatalf("Timeout = %v", command.Timeout)
	}

	destroy := snapshot.Commands["inventory.resource.delete"]
	required, ok := destroy.InputSchema["required"].([]string)
	if !ok || !contains(required, "confirm") {
		t.Fatalf("destroy required schema = %#v", destroy.InputSchema["required"])
	}
}

func TestLoadRejectsInsecureTLSInProduction(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest, "environment: development", "environment: production\n  identity_key_file: /tmp/current.pem", 1)
	input = strings.Replace(input, "    timeout: 10s", "    timeout: 10s\n    tls:\n      insecure_skip_verify: true", 1)
	_, err := Load([]byte(input), "production-insecure.yaml")
	if err == nil || !strings.Contains(err.Error(), "insecure_skip_verify") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestCompiledSnapshotGolden(t *testing.T) {
	t.Parallel()

	snapshot, err := Load([]byte(validManifest), "test.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	type goldenCommand struct {
		Key              string   `json:"key"`
		ToolName         string   `json:"tool_name"`
		Method           string   `json:"method"`
		Risk             string   `json:"risk"`
		Timeout          string   `json:"timeout"`
		EndpointSegments []string `json:"endpoint_segments"`
		Required         []string `json:"required"`
	}
	type goldenSnapshot struct {
		CLIName   string          `json:"cli_name"`
		AIMaxRisk string          `json:"ai_max_risk"`
		Commands  []goldenCommand `json:"commands"`
	}
	actual := goldenSnapshot{CLIName: snapshot.CLIName, AIMaxRisk: string(snapshot.AIMaxRisk)}
	for _, key := range snapshot.CommandKeys {
		command := snapshot.Commands[key]
		required, _ := command.InputSchema["required"].([]string)
		actual.Commands = append(actual.Commands, goldenCommand{
			Key:              command.Key,
			ToolName:         command.ToolName,
			Method:           command.Method,
			Risk:             string(command.Risk),
			Timeout:          command.Timeout.String(),
			EndpointSegments: command.EndpointSegments,
			Required:         required,
		})
	}
	encoded, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent() error = %v", err)
	}
	encoded = append(encoded, '\n')
	expected, err := os.ReadFile(filepath.Join("testdata", "compiled.golden.json"))
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if string(encoded) != string(expected) {
		t.Fatalf("compiled snapshot differs from golden\nactual:\n%s\nexpected:\n%s", encoded, expected)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validManifest, "  name: cg\n", "  name: cg\n  surprise: true\n", 1)
	_, err := Load([]byte(input), "unknown.yaml")
	if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("Load() error = %v, want strict unknown-field error", err)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	t.Parallel()

	_, err := Load([]byte(validManifest+"---\nversion: 1\n"), "multi.yaml")
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("Load() error = %v, want multiple-document error", err)
	}
}

func TestLoadSemanticErrorsIncludePathAndPosition(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validManifest, "        confirm: true\n", "        confirm: false\n", 1)
	_, err := Load([]byte(input), "invalid.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	var validationErrors ValidationErrors
	if !errors.As(err, &validationErrors) {
		t.Fatalf("error type = %T, want ValidationErrors", err)
	}
	found := false
	for _, validationErr := range validationErrors {
		if validationErr.Path == "domains[0].commands[1].confirm" {
			found = true
			if validationErr.Line == 0 {
				t.Fatalf("validation position = %#v, want source line", validationErr)
			}
		}
	}
	if !found {
		t.Fatalf("validation errors = %#v", validationErrors)
	}
}

func TestLoadRejectsProtectedHeader(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validManifest, "            in: path\n", "            in: header\n            header_name: Authorization\n", 1)
	_, err := Load([]byte(input), "header.yaml")
	if err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("Load() error = %v, want protected-header error", err)
	}
}

func TestLoadCompilesTokenExchange(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: token-exchange
      token_exchange:
        token_url: https://auth.example.com/oauth2/token
        client_id: cli-gateway
        client_secret_ref: env:CLI_GATEWAY_EXCHANGE_SECRET
        audience: inventory-api
        scopes: [inventory.write, inventory.read]
      cache:
        capacity: 100
        refresh_skew: 20s
        negative_ttl: 1s`,
		1,
	)
	snapshot, err := Load([]byte(input), "exchange.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	command := snapshot.Commands["inventory.resource.get"]
	if command.DownstreamAuth != model.DownstreamTokenExchange || command.OAuthCredential == nil {
		t.Fatalf("credential config = %#v", command)
	}
	if command.OAuthCredential.TokenEndpointAuth != "client_secret_basic" ||
		command.OAuthCredential.Audience != "inventory-api" ||
		strings.Join(command.OAuthCredential.Scopes, " ") != "inventory.read inventory.write" {
		t.Fatalf("OAuthCredential = %#v", command.OAuthCredential)
	}
	if command.CredentialCache.Capacity != 100 || command.CredentialCache.RefreshSkew != 20*time.Second {
		t.Fatalf("CredentialCache = %#v", command.CredentialCache)
	}
}

func TestLoadCompilesOAuthResourceParameterMode(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest, "  audience: cli-gateway\n", "  audience: cli-gateway\n  resource_parameter: audience\n", 1)
	snapshot, err := Load([]byte(input), "auth0.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.AuthResourceParameter != "audience" {
		t.Fatalf("AuthResourceParameter = %q", snapshot.AuthResourceParameter)
	}
}

func TestLoadRejectsUnknownOAuthResourceParameterMode(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest, "  audience: cli-gateway\n", "  audience: cli-gateway\n  resource_parameter: vendor\n", 1)
	_, err := Load([]byte(input), "resource-parameter.yaml")
	if err == nil || !strings.Contains(err.Error(), "both, audience, resource, or none") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadCompilesAuthorizationCode(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest,
		`audit:
  sinks:`,
		`downstream_oauth:
  token_store_file: /var/lib/cli-gateway/downstream-oauth.enc
  encryption_key_ref: env:CLI_GATEWAY_OAUTH_STORE_KEY
  state_ttl: 4m
audit:
  sinks:`,
		1,
	)
	input = strings.Replace(input,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: authorization-code
      authorization_code:
        authorization_url: https://accounts.example.com/oauth2/authorize
        token_url: https://accounts.example.com/oauth2/token
        client_id: cli-gateway
        client_secret_ref: env:CLI_GATEWAY_CMBD_OAUTH_SECRET
        token_endpoint_auth_method: client_secret_post
        scopes: [offline_access, inventory.read]`,
		1,
	)
	snapshot, err := Load([]byte(input), "authorization-code.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	command := snapshot.Commands["inventory.resource.get"]
	if command.DownstreamAuth != model.DownstreamAuthorizationCode || command.OAuthCredential == nil {
		t.Fatalf("credential config = %#v", command)
	}
	if command.OAuthCredential.AuthorizationURL.String() != "https://accounts.example.com/oauth2/authorize" ||
		command.OAuthCredential.TokenURL.String() != "https://accounts.example.com/oauth2/token" ||
		command.OAuthCredential.TokenEndpointAuth != "client_secret_post" ||
		strings.Join(command.OAuthCredential.Scopes, " ") != "inventory.read offline_access" {
		t.Fatalf("OAuthCredential = %#v", command.OAuthCredential)
	}
	if snapshot.OAuthTokenStoreFile != "/var/lib/cli-gateway/downstream-oauth.enc" ||
		snapshot.OAuthEncryptionKeyRef != "env:CLI_GATEWAY_OAUTH_STORE_KEY" ||
		snapshot.OAuthStateTTL != 4*time.Minute {
		t.Fatalf("downstream OAuth snapshot = %#v", snapshot)
	}
}

func TestLoadAuthorizationCodeAllowsProviderWithoutScopes(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: authorization-code
      authorization_code:
        authorization_url: https://github.com/login/oauth/authorize
        token_url: https://github.com/login/oauth/access_token
        client_id: github-app-client
        client_secret_ref: env:CLI_GATEWAY_GITHUB_CLIENT_SECRET
        token_endpoint_auth_method: client_secret_post`,
		1,
	)
	snapshot, err := Load([]byte(input), "github-app.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	command := snapshot.Commands["inventory.resource.get"]
	if command.OAuthCredential == nil || len(command.OAuthCredential.Scopes) != 0 ||
		command.OAuthCredential.TokenEndpointAuth != "client_secret_post" {
		t.Fatalf("OAuthCredential = %#v", command.OAuthCredential)
	}
}

func TestLoadRejectsUnknownTokenEndpointAuthMethod(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: token-exchange
      token_exchange:
        token_url: https://auth.example.com/oauth2/token
        client_id: cli-gateway
        client_secret_ref: env:CLI_GATEWAY_EXCHANGE_SECRET
        token_endpoint_auth_method: private_key_jwt
        audience: inventory-api
        scopes: [inventory.read]`,
		1,
	)
	_, err := Load([]byte(input), "token-auth-method.yaml")
	if err == nil || !strings.Contains(err.Error(), "client_secret_basic or client_secret_post") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRequiresPersistentAuthorizationStoreInProduction(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest, "environment: development", "environment: production\n  identity_key_file: /tmp/current.pem", 1)
	input = strings.Replace(input,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: authorization-code
      authorization_code:
        authorization_url: https://accounts.example.com/oauth2/authorize
        token_url: https://accounts.example.com/oauth2/token
        client_id: cli-gateway
        client_secret_ref: env:CLI_GATEWAY_CMBD_OAUTH_SECRET
        scopes: [offline_access, inventory.read]`,
		1,
	)
	_, err := Load([]byte(input), "authorization-code-production.yaml")
	if err == nil || !strings.Contains(err.Error(), "downstream_oauth.token_store_file") ||
		!strings.Contains(err.Error(), "downstream_oauth.encryption_key_ref") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsLiteralTokenExchangeSecret(t *testing.T) {
	t.Parallel()
	input := strings.Replace(validManifest,
		`      mode: signed-identity
      identity_audience: inventory-api`,
		`      mode: token-exchange
      token_exchange:
        token_url: https://auth.example.com/oauth2/token
        client_id: cli-gateway
        client_secret_ref: literal-secret
        audience: inventory-api
        scopes: [inventory.read]`,
		1,
	)
	_, err := Load([]byte(input), "exchange-secret.yaml")
	if err == nil || !strings.Contains(err.Error(), "env: or file:") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestManagerReloadRetainsPreviousSnapshotOnFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.yaml")
	writeFile(t, path, validManifest)
	manager, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	previous := manager.Current()

	writeFile(t, path, strings.Replace(validManifest, "risk: destroy", "risk: explode", 1))
	if err := manager.Reload(); err == nil {
		t.Fatal("Reload() error = nil, want validation failure")
	}
	if manager.Current() != previous {
		t.Fatal("failed reload replaced the active snapshot")
	}
}

func TestManagerRejectsRestartOnlyChange(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.yaml")
	oidcManifest := strings.Replace(
		validManifest,
		"  mode: trusted-header\n  issuer: https://auth.example.com\n  trusted_jwks: https://auth.example.com/.well-known/jwks.json\n  audience: cli-gateway",
		"  mode: oidc\n  issuer: https://auth.example.com\n  client_id: cli-gateway-cli\n  audience: cli-gateway",
		1,
	)
	writeFile(t, path, oidcManifest)
	manager, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	previous := manager.Current()

	writeFile(t, path, strings.Replace(oidcManifest, "https://auth.example.com", "https://new-auth.example.com", 1))
	if err := manager.Reload(); err == nil || !strings.Contains(err.Error(), "auth.issuer") {
		t.Fatalf("Reload() error = %v, want auth.issuer restart error", err)
	}
	if manager.Current() != previous {
		t.Fatal("restart-only reload replaced the active snapshot")
	}
}

func TestInvalidExamplesAreRejected(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob(filepath.Join("..", "..", "examples", "invalid", "*.yaml"))
	if err != nil {
		t.Fatalf("glob invalid examples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no invalid examples found")
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			if _, err := LoadFile(path); err == nil {
				t.Fatalf("LoadFile(%q) error = nil, want rejection", path)
			}
		})
	}
}

func TestPublishedManifestExamplesLoad(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "manifest.example.yaml"),
		filepath.Join("..", "..", "examples", "e2e", "manifest.yaml"),
		filepath.Join("..", "..", "examples", "compose", "manifest.yaml"),
		filepath.Join("..", "..", "examples", "auth0", "manifest.yaml"),
		filepath.Join("..", "..", "examples", "github", "manifest.yaml"),
		filepath.Join("..", "..", "examples", "keycloak", "manifest.yaml"),
	} {
		if _, err := LoadFile(path); err != nil {
			t.Errorf("LoadFile(%q) error = %v", path, err)
		}
	}
}

func TestPublishedManifestInventoryMappings(t *testing.T) {
	t.Parallel()
	snapshot, err := LoadFile(filepath.Join("..", "..", "manifest.example.yaml"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	get := snapshot.Commands["inventory.item.get"]
	if get == nil || get.Method != "GET" {
		t.Fatalf("inventory.item.get = %#v", get)
	}

	list := snapshot.Commands["inventory.item.list"]
	if list == nil || list.Method != "GET" {
		t.Fatalf("inventory.item.list = %#v", list)
	}
	queryNames := map[string]string{}
	for _, flag := range list.Flags {
		queryNames[flag.Name] = flag.QueryName
	}
	if queryNames["page-size"] != "pageSize" {
		t.Fatalf("page-size query name = %q", queryNames["page-size"])
	}

	create := snapshot.Commands["inventory.item.create"]
	if create == nil || create.Method != "POST" || !create.Confirm {
		t.Fatalf("inventory.item.create = %#v", create)
	}
}

func TestRiskDefaultAndToolCollision(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validManifest, "      - path: [resource, delete]", "      - path: [resource-get]", 1)
	_, err := Load([]byte(input), "collision.yaml")
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("Load() error = %v, want generated tool collision", err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
