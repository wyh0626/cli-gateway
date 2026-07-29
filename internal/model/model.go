// Package model contains transport-neutral cli-gateway domain types.
package model

import (
	"io"
	"net/http"
	"net/url"
	"time"
)

// Source identifies the protocol adapter that created an invocation.
type Source string

const (
	SourceHTTP Source = "http"
	SourceMCP  Source = "mcp"
)

// Invoker is the trusted execution actor classification.
type Invoker string

const (
	InvokerHuman   Invoker = "human"
	InvokerAI      Invoker = "ai"
	InvokerCI      Invoker = "ci"
	InvokerUnknown Invoker = "unknown"
)

// Risk is the side-effect classification of a command.
type Risk string

const (
	RiskRead    Risk = "read"
	RiskWrite   Risk = "write"
	RiskDestroy Risk = "destroy"
)

var riskRank = map[Risk]int{
	RiskRead:    1,
	RiskWrite:   2,
	RiskDestroy: 3,
}

// Valid reports whether the risk is supported.
func (r Risk) Valid() bool {
	_, ok := riskRank[r]
	return ok
}

// Exceeds reports whether r is more dangerous than maximum.
func (r Risk) Exceeds(maximum Risk) bool {
	return riskRank[r] > riskRank[maximum]
}

// Principal is derived only from verified authentication material.
type Principal struct {
	Subject   string
	Email     string
	Name      string
	Issuer    string
	Tenant    string
	SessionID string
	ExpiresAt time.Time
	Scopes    map[string]struct{}
	Invoker   Invoker
	ClientID  string
}

// FlagLocation controls how an argument is sent upstream.
type FlagLocation string

const (
	FlagInBody   FlagLocation = "body"
	FlagInQuery  FlagLocation = "query"
	FlagInPath   FlagLocation = "path"
	FlagInHeader FlagLocation = "header"
)

// FlagType is the accepted argument value type.
type FlagType string

const (
	FlagString      FlagType = "string"
	FlagInt         FlagType = "int"
	FlagBool        FlagType = "bool"
	FlagStringArray FlagType = "stringArray"
)

// CompiledFlag is a validated command argument definition.
type CompiledFlag struct {
	Name        string       `json:"name"`
	Type        FlagType     `json:"type"`
	Location    FlagLocation `json:"in"`
	Required    bool         `json:"required"`
	Default     any          `json:"default,omitempty"`
	QueryName   string       `json:"query_name,omitempty"`
	HeaderName  string       `json:"header_name,omitempty"`
	Description string       `json:"desc,omitempty"`
}

// DownstreamAuthMode controls credentials sent to an upstream domain.
type DownstreamAuthMode string

const (
	DownstreamSignedIdentity    DownstreamAuthMode = "signed-identity"
	DownstreamBearerPassthrough DownstreamAuthMode = "bearer-passthrough"
	DownstreamTokenExchange     DownstreamAuthMode = "token-exchange"
	DownstreamClientCredentials DownstreamAuthMode = "client-credentials"
	DownstreamAuthorizationCode DownstreamAuthMode = "authorization-code"
)

// OAuthCredentialConfig is the compiled configuration for RFC 8693 token
// exchange or OAuth client credentials.
type OAuthCredentialConfig struct {
	AuthorizationURL   *url.URL
	TokenURL           *url.URL
	RevocationURL      *url.URL
	ClientID           string
	ClientSecretRef    string
	TokenEndpointAuth  string
	Audience           string
	Resource           string
	Scopes             []string
	SubjectTokenType   string
	RequestedTokenType string
	AllowLocal         bool
	TLS                TLSConfig
}

// CredentialCacheConfig controls a generation-local bearer-token cache.
type CredentialCacheConfig struct {
	Capacity    int
	RefreshSkew time.Duration
	NegativeTTL time.Duration
}

// TLSConfig is compiled transport trust configuration.
type TLSConfig struct {
	InsecureSkipVerify bool
	CAFile             string
	ClientCertFile     string
	ClientKeyFile      string
}

// CompiledCommand is safe for use by all protocol adapters.
type CompiledCommand struct {
	Key               string
	ToolName          string
	Domain            string
	Path              []string
	Summary           string
	Method            string
	Upstream          *url.URL
	EndpointSegments  []string
	Risk              Risk
	Confirm           bool
	Streaming         bool
	Timeout           time.Duration
	Flags             []CompiledFlag
	InputSchema       map[string]any
	DownstreamAuth    DownstreamAuthMode
	IdentityAudience  string
	OAuthCredential   *OAuthCredentialConfig
	CredentialCache   CredentialCacheConfig
	DomainConcurrency int
	RequestsPerSecond float64
	RateBurst         int
	AllowLocal        bool
	TLS               TLSConfig
}

// Invocation is the only input accepted by the future invocation service.
type Invocation struct {
	Source      Source
	Principal   Principal
	Command     *CompiledCommand
	Args        map[string]any
	Invoker     Invoker
	Confirmed   bool
	AIMaxRisk   Risk
	TraceID     string
	TraceState  string
	Client      string
	BearerToken string
}

// Execution is a transport-neutral, closeable upstream response. The protocol
// adapter that consumes Body owns closing it and any buffering limits.
type Execution struct {
	Status      int
	ContentType string
	Header      http.Header
	Body        io.ReadCloser
	Streaming   bool
}
