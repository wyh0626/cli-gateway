package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

// Snapshot is a compiled, immutable-by-contract manifest view.
type Snapshot struct {
	Version                  int
	ETag                     string
	Source                   string
	LoadedAt                 time.Time
	Listen                   string
	PublicURL                string
	Environment              string
	AuthMode                 string
	AuthIssuer               string
	AuthAudience             string
	AuthClientID             string
	AuthResourceParameter    string
	AuthTrustedJWKS          string
	AuthIdentityClaims       map[string]string
	AuthTLS                  model.TLSConfig
	IdentityKeyFile          string
	IdentityPreviousKeyFiles []string
	OAuthTokenStoreFile      string
	OAuthEncryptionKeyRef    string
	OAuthStateTTL            time.Duration
	CLIName                  string
	AIMaxRisk                model.Risk
	GlobalConcurrency        int
	QueueTimeout             time.Duration
	AuditSinks               []CompiledAuditSink
	Commands                 map[string]*model.CompiledCommand
	ToolCommands             map[string]*model.CompiledCommand
	CommandKeys              []string
}

// CompiledAuditSink is safe to construct during runtime preflight.
type CompiledAuditSink struct {
	Type    string
	Path    string
	URL     *url.URL
	Timeout time.Duration
	TLS     model.TLSConfig
}

func compile(raw Manifest, data []byte, source string) *Snapshot {
	digest := sha256.Sum256(data)
	snapshot := &Snapshot{
		Version:                  raw.Version,
		ETag:                     hex.EncodeToString(digest[:8]),
		Source:                   source,
		LoadedAt:                 time.Now().UTC(),
		Listen:                   raw.Server.Listen,
		PublicURL:                raw.Server.PublicURL,
		Environment:              raw.Server.Environment,
		AuthMode:                 raw.Auth.Mode,
		AuthIssuer:               raw.Auth.Issuer,
		AuthAudience:             raw.Auth.Audience,
		AuthClientID:             raw.Auth.ClientID,
		AuthResourceParameter:    authResourceParameter(raw.Auth.ResourceParameter),
		AuthTrustedJWKS:          raw.Auth.TrustedJWKS,
		AuthIdentityClaims:       cloneStringMap(raw.Auth.IdentityClaims),
		AuthTLS:                  compileTLS(raw.Auth.TLS),
		IdentityKeyFile:          raw.Server.IdentityKeyFile,
		IdentityPreviousKeyFiles: append([]string(nil), raw.Server.IdentityPreviousKeyFiles...),
		OAuthTokenStoreFile:      raw.DownstreamOAuth.TokenStoreFile,
		OAuthEncryptionKeyRef:    raw.DownstreamOAuth.EncryptionKeyRef,
		OAuthStateTTL:            downstreamOAuthStateTTL(raw.DownstreamOAuth.StateTTL),
		CLIName:                  raw.CLI.Name,
		AIMaxRisk:                model.Risk(raw.Policy.AIMaxRisk),
		GlobalConcurrency:        globalConcurrency(raw.Limits.GlobalConcurrency),
		QueueTimeout:             queueTimeout(raw.Limits.QueueTimeout),
		AuditSinks:               compileAuditSinks(raw.Audit),
		Commands:                 make(map[string]*model.CompiledCommand),
		ToolCommands:             make(map[string]*model.CompiledCommand),
	}
	if snapshot.Environment == "" {
		snapshot.Environment = "development"
	}

	for _, domain := range raw.Domains {
		upstream, _ := url.Parse(domain.Upstream)
		authMode := model.DownstreamAuthMode(domain.DownstreamAuth.Mode)
		if authMode == "" {
			authMode = model.DownstreamSignedIdentity
		}
		var oauthCredential *model.OAuthCredentialConfig
		switch authMode {
		case model.DownstreamTokenExchange:
			oauthCredential = compileOAuthCredential(domain.DownstreamAuth.TokenExchange, domain.Network.AllowLocal)
		case model.DownstreamClientCredentials:
			oauthCredential = compileOAuthCredential(domain.DownstreamAuth.ClientCredentials, domain.Network.AllowLocal)
		case model.DownstreamAuthorizationCode:
			oauthCredential = compileOAuthCredential(domain.DownstreamAuth.AuthorizationCode, domain.Network.AllowLocal)
		}
		credentialCache := compileCredentialCache(domain.DownstreamAuth.Cache)
		for _, command := range domain.Commands {
			key := domain.Name + "." + strings.Join(command.Path, ".")
			compiled := &model.CompiledCommand{
				Key:               key,
				ToolName:          generatedToolName(domain.Name, command.Path),
				Domain:            domain.Name,
				Path:              append([]string(nil), command.Path...),
				Summary:           command.Summary,
				Method:            strings.ToUpper(command.Method),
				Upstream:          cloneURL(upstream),
				EndpointSegments:  endpointSegments(command.Endpoint),
				Risk:              model.Risk(command.Risk),
				Confirm:           command.Confirm,
				Streaming:         command.Streaming,
				Timeout:           domainTimeout(domain.Timeout),
				DownstreamAuth:    authMode,
				IdentityAudience:  domain.DownstreamAuth.IdentityAudience,
				OAuthCredential:   oauthCredential,
				CredentialCache:   credentialCache,
				DomainConcurrency: domainConcurrency(domain.Limits.Concurrency),
				RequestsPerSecond: domain.Limits.RequestsPerSecond,
				RateBurst:         rateBurst(domain.Limits.Burst, domain.Limits.RequestsPerSecond),
				AllowLocal:        domain.Network.AllowLocal,
				TLS:               compileTLS(domain.TLS),
			}
			compiled.Flags = compileFlags(command.Flags)
			compiled.InputSchema = compileInputSchema(command)
			snapshot.Commands[key] = compiled
			snapshot.ToolCommands[compiled.ToolName] = compiled
			snapshot.CommandKeys = append(snapshot.CommandKeys, key)
		}
	}
	sort.Strings(snapshot.CommandKeys)
	return snapshot
}

func authResourceParameter(configured string) string {
	if configured == "" {
		return "both"
	}
	return configured
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func globalConcurrency(configured int) int {
	if configured == 0 {
		return 512
	}
	return configured
}

func domainConcurrency(configured int) int {
	if configured == 0 {
		return 128
	}
	return configured
}

func queueTimeout(configured Duration) time.Duration {
	if configured == 0 {
		return 250 * time.Millisecond
	}
	return time.Duration(configured)
}

func rateBurst(configured int, requestsPerSecond float64) int {
	if requestsPerSecond <= 0 {
		return 0
	}
	if configured > 0 {
		return configured
	}
	value := int(requestsPerSecond * 2)
	if value < 1 {
		value = 1
	}
	return value
}

func compileAuditSinks(config AuditConfig) []CompiledAuditSink {
	result := make([]CompiledAuditSink, 0, len(config.Sinks))
	for _, sink := range config.Sinks {
		parsedURL, _ := url.Parse(sink.URL)
		timeout := time.Duration(sink.Timeout)
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		result = append(result, CompiledAuditSink{Type: sink.Type, Path: sink.Path, URL: parsedURL, Timeout: timeout, TLS: compileTLS(sink.TLS)})
	}
	return result
}

func compileOAuthCredential(config OAuthCredentialConfig, allowLocal bool) *model.OAuthCredentialConfig {
	authorizationURL, _ := url.Parse(config.AuthorizationURL)
	tokenURL, _ := url.Parse(config.TokenURL)
	var revocationURL *url.URL
	if config.RevocationURL != "" {
		revocationURL, _ = url.Parse(config.RevocationURL)
	}
	subjectType := config.SubjectTokenType
	if subjectType == "" {
		subjectType = "urn:ietf:params:oauth:token-type:access_token"
	}
	requestedType := config.RequestedTokenType
	if requestedType == "" {
		requestedType = "urn:ietf:params:oauth:token-type:access_token"
	}
	scopes := append([]string(nil), config.Scopes...)
	sort.Strings(scopes)
	tokenEndpointAuth := config.TokenEndpointAuth
	if tokenEndpointAuth == "" {
		tokenEndpointAuth = "client_secret_basic"
	}
	return &model.OAuthCredentialConfig{
		AuthorizationURL: authorizationURL, TokenURL: tokenURL, RevocationURL: revocationURL,
		ClientID: config.ClientID, ClientSecretRef: config.ClientSecretRef, TokenEndpointAuth: tokenEndpointAuth,
		Audience: config.Audience, Resource: config.Resource, Scopes: scopes,
		SubjectTokenType: subjectType, RequestedTokenType: requestedType, AllowLocal: allowLocal,
		TLS: compileTLS(config.TLS),
	}
}

func downstreamOAuthStateTTL(configured Duration) time.Duration {
	if configured == 0 {
		return 5 * time.Minute
	}
	return time.Duration(configured)
}

func compileTLS(config TLSConfig) model.TLSConfig {
	return model.TLSConfig{
		InsecureSkipVerify: config.InsecureSkipVerify, CAFile: config.CAFile,
		ClientCertFile: config.ClientCertFile, ClientKeyFile: config.ClientKeyFile,
	}
}

func compileCredentialCache(config CredentialCacheConfig) model.CredentialCacheConfig {
	capacity := config.Capacity
	if capacity == 0 {
		capacity = 10_000
	}
	refreshSkew := time.Duration(config.RefreshSkew)
	if refreshSkew == 0 {
		refreshSkew = 30 * time.Second
	}
	negativeTTL := time.Duration(config.NegativeTTL)
	if negativeTTL == 0 {
		negativeTTL = 2 * time.Second
	}
	return model.CredentialCacheConfig{Capacity: capacity, RefreshSkew: refreshSkew, NegativeTTL: negativeTTL}
}

func compileFlags(flags []Flag) []model.CompiledFlag {
	result := make([]model.CompiledFlag, 0, len(flags))
	for _, flag := range flags {
		queryName := ""
		if flag.In == string(model.FlagInQuery) {
			queryName = flag.QueryName
		}
		if flag.In == string(model.FlagInQuery) && queryName == "" {
			queryName = flag.Name
		}
		result = append(result, model.CompiledFlag{
			Name:        flag.Name,
			Type:        model.FlagType(flag.Type),
			Location:    model.FlagLocation(flag.In),
			Required:    flag.Required,
			Default:     cloneDefault(flag.Default),
			QueryName:   queryName,
			HeaderName:  flag.HeaderName,
			Description: flag.Description,
		})
	}
	return result
}

func compileInputSchema(command Command) map[string]any {
	properties := make(map[string]any, len(command.Flags)+1)
	required := make([]string, 0, len(command.Flags)+1)
	for _, flag := range command.Flags {
		property := map[string]any{"type": jsonSchemaType(model.FlagType(flag.Type))}
		if flag.Type == string(model.FlagStringArray) {
			property["items"] = map[string]any{"type": "string"}
		}
		if flag.Description != "" {
			property["description"] = flag.Description
		}
		if flag.Default != nil {
			property["default"] = cloneDefault(flag.Default)
		}
		properties[flag.Name] = property
		if flag.Required {
			required = append(required, flag.Name)
		}
	}
	if command.Confirm {
		properties["confirm"] = map[string]any{
			"type":        "boolean",
			"description": "Confirm this operation",
		}
		required = append(required, "confirm")
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		sort.Strings(required)
		schema["required"] = required
	}
	return schema
}

func jsonSchemaType(flagType model.FlagType) string {
	switch flagType {
	case model.FlagInt:
		return "integer"
	case model.FlagBool:
		return "boolean"
	case model.FlagStringArray:
		return "array"
	default:
		return "string"
	}
}

func endpointSegments(endpoint string) []string {
	parsed, _ := url.Parse(endpoint)
	return strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDefault(value any) any {
	values, ok := value.([]any)
	if !ok {
		return value
	}
	return append([]any(nil), values...)
}
