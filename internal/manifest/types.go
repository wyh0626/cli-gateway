package manifest

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultDomainTimeout = 30 * time.Second

// Duration is a strict YAML duration backed by time.Duration.
type Duration time.Duration

// UnmarshalYAML accepts duration strings such as "30s".
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("line %d: duration must be a string", node.Line)
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", node.Line, node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// Manifest is the declarative source configuration.
type Manifest struct {
	Version         int                   `yaml:"version"`
	Server          ServerConfig          `yaml:"server"`
	Auth            AuthConfig            `yaml:"auth"`
	CLI             CLIConfig             `yaml:"cli"`
	Policy          PolicyConfig          `yaml:"policy"`
	Limits          LimitsConfig          `yaml:"limits"`
	Audit           AuditConfig           `yaml:"audit"`
	DownstreamOAuth DownstreamOAuthConfig `yaml:"downstream_oauth"`
	Domains         []Domain              `yaml:"domains"`
}

type ServerConfig struct {
	Listen                   string   `yaml:"listen"`
	PublicURL                string   `yaml:"public_url"`
	Environment              string   `yaml:"environment"`
	IdentityKeyFile          string   `yaml:"identity_key_file"`
	IdentityPreviousKeyFiles []string `yaml:"identity_previous_key_files"`
}

type AuthConfig struct {
	Mode              string            `yaml:"mode"`
	Issuer            string            `yaml:"issuer"`
	ClientID          string            `yaml:"client_id"`
	Audience          string            `yaml:"audience"`
	ResourceParameter string            `yaml:"resource_parameter"`
	TrustedJWKS       string            `yaml:"trusted_jwks"`
	IdentityClaims    map[string]string `yaml:"identity_claims"`
	TLS               TLSConfig         `yaml:"tls"`
}

type CLIConfig struct {
	Name string `yaml:"name"`
}

type PolicyConfig struct {
	AIMaxRisk string `yaml:"ai_max_risk"`
}

type LimitsConfig struct {
	GlobalConcurrency int      `yaml:"global_concurrency"`
	QueueTimeout      Duration `yaml:"queue_timeout"`
}

type AuditConfig struct {
	Sinks []AuditSink `yaml:"sinks"`
}

// DownstreamOAuthConfig controls process-wide encrypted storage and pending
// state for per-user downstream OAuth authorization-code grants.
type DownstreamOAuthConfig struct {
	TokenStoreFile   string   `yaml:"token_store_file"`
	EncryptionKeyRef string   `yaml:"encryption_key_ref"`
	StateTTL         Duration `yaml:"state_ttl"`
}

type AuditSink struct {
	Type    string    `yaml:"type"`
	Path    string    `yaml:"path"`
	URL     string    `yaml:"url"`
	Timeout Duration  `yaml:"timeout"`
	TLS     TLSConfig `yaml:"tls"`
}

type Domain struct {
	Name           string               `yaml:"name"`
	Upstream       string               `yaml:"upstream"`
	TLS            TLSConfig            `yaml:"tls"`
	Network        NetworkConfig        `yaml:"network"`
	Timeout        Duration             `yaml:"timeout"`
	DownstreamAuth DownstreamAuthConfig `yaml:"downstream_auth"`
	Limits         DomainLimitsConfig   `yaml:"limits"`
	Commands       []Command            `yaml:"commands"`
}

type DomainLimitsConfig struct {
	Concurrency       int     `yaml:"concurrency"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
}

type NetworkConfig struct {
	AllowLocal bool `yaml:"allow_local"`
}

type DownstreamAuthConfig struct {
	Mode              string                `yaml:"mode"`
	IdentityAudience  string                `yaml:"identity_audience"`
	TokenExchange     OAuthCredentialConfig `yaml:"token_exchange"`
	ClientCredentials OAuthCredentialConfig `yaml:"client_credentials"`
	AuthorizationCode OAuthCredentialConfig `yaml:"authorization_code"`
	Cache             CredentialCacheConfig `yaml:"cache"`
}

type OAuthCredentialConfig struct {
	AuthorizationURL   string    `yaml:"authorization_url"`
	TokenURL           string    `yaml:"token_url"`
	RevocationURL      string    `yaml:"revocation_url"`
	ClientID           string    `yaml:"client_id"`
	ClientSecretRef    string    `yaml:"client_secret_ref"`
	TokenEndpointAuth  string    `yaml:"token_endpoint_auth_method"`
	Audience           string    `yaml:"audience"`
	Resource           string    `yaml:"resource"`
	Scopes             []string  `yaml:"scopes"`
	SubjectTokenType   string    `yaml:"subject_token_type"`
	RequestedTokenType string    `yaml:"requested_token_type"`
	TLS                TLSConfig `yaml:"tls"`
}

type CredentialCacheConfig struct {
	Capacity    int      `yaml:"capacity"`
	RefreshSkew Duration `yaml:"refresh_skew"`
	NegativeTTL Duration `yaml:"negative_ttl"`
}

type Command struct {
	Path     []string `yaml:"path"`
	Summary  string   `yaml:"summary"`
	Method   string   `yaml:"method"`
	Endpoint string   `yaml:"endpoint"`
	Risk     string   `yaml:"risk"`
	// Scope is accepted only so older manifests continue to load. Command
	// authorization is delegated to the downstream business system.
	Scope     string `yaml:"scope"`
	Confirm   bool   `yaml:"confirm"`
	Streaming bool   `yaml:"streaming"`
	Flags     []Flag `yaml:"flags"`
}

type Flag struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Required    bool   `yaml:"required"`
	Default     any    `yaml:"default"`
	In          string `yaml:"in"`
	Description string `yaml:"desc"`
	QueryName   string `yaml:"query_name"`
	HeaderName  string `yaml:"header_name"`
}
