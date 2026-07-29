package manifest

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

var (
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	placeholderPattern = regexp.MustCompile(`^\{([a-z][a-z0-9-]{0,31})\}$`)
	headerNamePattern  = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
)

type validator struct {
	positions map[string]Position
	errors    ValidationErrors
}

func validate(raw Manifest, positions map[string]Position) error { //nolint:gocyclo
	v := &validator{positions: positions}

	if raw.Version != 1 {
		v.add("version", "must be exactly 1")
	}
	if raw.Server.Listen == "" {
		v.add("server.listen", "is required")
	}
	if raw.Server.Environment == "" {
		raw.Server.Environment = "development"
	}
	if raw.Server.Environment != "development" && raw.Server.Environment != "production" {
		v.add("server.environment", "must be development or production")
	}
	if raw.Server.Environment == "production" && raw.Server.IdentityKeyFile == "" {
		v.add("server.identity_key_file", "is required in production")
	}
	previousKeys := make(map[string]struct{}, len(raw.Server.IdentityPreviousKeyFiles))
	for index, keyFile := range raw.Server.IdentityPreviousKeyFiles {
		path := fmt.Sprintf("server.identity_previous_key_files[%d]", index)
		if strings.TrimSpace(keyFile) == "" {
			v.add(path, "must not be empty")
		}
		if keyFile == raw.Server.IdentityKeyFile {
			v.add(path, "must differ from identity_key_file")
		}
		if _, exists := previousKeys[keyFile]; exists {
			v.add(path, "duplicates another previous key file")
		}
		previousKeys[keyFile] = struct{}{}
	}
	validateAbsoluteHTTPURL(v, "server.public_url", raw.Server.PublicURL, false)
	validateAuth(v, raw.Auth, raw.Server.Environment)
	if !namePattern.MatchString(raw.CLI.Name) {
		v.add("cli.name", "must match ^[a-z][a-z0-9-]{0,31}$")
	}
	if !model.Risk(raw.Policy.AIMaxRisk).Valid() {
		v.add("policy.ai_max_risk", "must be read, write, or destroy")
	}
	if raw.Limits.GlobalConcurrency < 0 || raw.Limits.GlobalConcurrency > 100_000 {
		v.add("limits.global_concurrency", "must be between 1 and 100000 when configured")
	}
	if configured := time.Duration(raw.Limits.QueueTimeout); configured < 0 || configured > 30*time.Second {
		v.add("limits.queue_timeout", "must be between 0 and 30s")
	}
	validateAudit(v, raw.Audit)
	validateDownstreamOAuth(v, raw.DownstreamOAuth, raw.Server.Environment, raw.Domains)
	if len(raw.Domains) == 0 {
		v.add("domains", "must contain at least one domain")
	}

	domainNames := make(map[string]struct{})
	commandKeys := make(map[string]struct{})
	toolNames := make(map[string]string)
	for domainIndex, domain := range raw.Domains {
		domainPath := fmt.Sprintf("domains[%d]", domainIndex)
		if !namePattern.MatchString(domain.Name) {
			v.add(domainPath+".name", "must match ^[a-z][a-z0-9-]{0,31}$")
		}
		if _, exists := domainNames[domain.Name]; exists {
			v.add(domainPath+".name", "duplicates another domain")
		}
		domainNames[domain.Name] = struct{}{}
		validateUpstream(v, domainPath+".upstream", domain.Upstream, domain.Network.AllowLocal)
		validateTLS(v, domainPath+".tls", domain.TLS, raw.Server.Environment)
		if timeValue := domainTimeout(domain.Timeout); timeValue <= 0 {
			v.add(domainPath+".timeout", "must be greater than zero")
		}
		validateDownstreamAuth(v, domainPath+".downstream_auth", domain.DownstreamAuth, raw.Server.Environment, domain.Network.AllowLocal)
		validateDomainLimits(v, domainPath+".limits", domain.Limits)
		if len(domain.Commands) == 0 {
			v.add(domainPath+".commands", "must contain at least one command")
		}

		for commandIndex, command := range domain.Commands {
			commandPath := fmt.Sprintf("%s.commands[%d]", domainPath, commandIndex)
			validateCommand(v, commandPath, command)
			partsValid := len(command.Path) > 0
			for pathIndex, part := range command.Path {
				if !namePattern.MatchString(part) {
					v.add(fmt.Sprintf("%s.path[%d]", commandPath, pathIndex), "must match ^[a-z][a-z0-9-]{0,31}$")
					partsValid = false
				}
			}
			if len(command.Path) == 0 {
				v.add(commandPath+".path", "must not be empty")
			}
			if partsValid {
				key := domain.Name + "." + strings.Join(command.Path, ".")
				if _, exists := commandKeys[key]; exists {
					v.add(commandPath+".path", "duplicates command "+key)
				}
				commandKeys[key] = struct{}{}
				toolName := generatedToolName(domain.Name, command.Path)
				if existing, exists := toolNames[toolName]; exists {
					v.add(commandPath+".path", fmt.Sprintf("generated MCP tool %q collides with %s", toolName, existing))
				}
				toolNames[toolName] = key
			}
		}
	}

	if len(v.errors) > 0 {
		return v.errors
	}
	return nil
}

func validateDomainLimits(v *validator, path string, limits DomainLimitsConfig) {
	if limits.Concurrency < 0 || limits.Concurrency > 10_000 {
		v.add(path+".concurrency", "must be between 1 and 10000 when configured")
	}
	if limits.RequestsPerSecond < 0 || limits.RequestsPerSecond > 1_000_000 {
		v.add(path+".requests_per_second", "must be between 0 and 1000000")
	}
	if limits.Burst < 0 || limits.Burst > 1_000_000 {
		v.add(path+".burst", "must be between 0 and 1000000")
	}
	if limits.RequestsPerSecond == 0 && limits.Burst != 0 {
		v.add(path+".burst", "requires requests_per_second")
	}
}

func validateAuth(v *validator, auth AuthConfig, environment string) {
	requireHTTPS := environment == "production"
	switch auth.Mode {
	case "oidc":
		validateAbsoluteHTTPURL(v, "auth.issuer", auth.Issuer, requireHTTPS)
		if auth.ClientID == "" {
			v.add("auth.client_id", "is required for oidc mode")
		}
	case "trusted-header":
		validateAbsoluteHTTPURL(v, "auth.issuer", auth.Issuer, requireHTTPS)
		validateAbsoluteHTTPURL(v, "auth.trusted_jwks", auth.TrustedJWKS, requireHTTPS)
	case "":
		v.add("auth.mode", "is required")
	default:
		v.add("auth.mode", "must be oidc or trusted-header")
	}
	if auth.Audience == "" {
		v.add("auth.audience", "is required")
	}
	switch auth.ResourceParameter {
	case "", "both", "audience", "resource", "none":
	default:
		v.add("auth.resource_parameter", "must be both, audience, resource, or none")
	}
	for target, source := range auth.IdentityClaims {
		path := "auth.identity_claims." + target
		if target != "email" && target != "name" {
			v.add(path, "target must be email or name")
		}
		if strings.TrimSpace(source) == "" || len(source) > 128 || strings.ContainsAny(source, " \t\r\n") {
			v.add(path, "source claim must be a non-empty claim name without whitespace")
		}
	}
	validateTLS(v, "auth.tls", auth.TLS, environment)
}

func validateAudit(v *validator, audit AuditConfig) {
	for index, sink := range audit.Sinks {
		path := fmt.Sprintf("audit.sinks[%d]", index)
		switch sink.Type {
		case "jsonl":
			if sink.Path == "" {
				v.add(path+".path", "is required for jsonl sink")
			}
		case "stdout":
		case "webhook":
			validateAbsoluteHTTPURL(v, path+".url", sink.URL, true)
		case "":
			v.add(path+".type", "is required")
		default:
			v.add(path+".type", "must be jsonl, stdout, or webhook")
		}
		if configured := time.Duration(sink.Timeout); configured < 0 || configured > time.Minute {
			v.add(path+".timeout", "must be between 0 and 1m")
		}
		validateTLS(v, path+".tls", sink.TLS, "production")
	}
}

func validateDownstreamAuth(v *validator, path string, auth DownstreamAuthConfig, environment string, allowLocal bool) {
	mode := auth.Mode
	if mode == "" {
		mode = string(model.DownstreamSignedIdentity)
	}
	switch model.DownstreamAuthMode(mode) {
	case model.DownstreamSignedIdentity:
		if auth.IdentityAudience == "" {
			v.add(path+".identity_audience", "is required for signed-identity mode")
		}
	case model.DownstreamBearerPassthrough:
		if auth.IdentityAudience != "" {
			v.add(path+".identity_audience", "must be empty for bearer-passthrough mode")
		}
	case model.DownstreamTokenExchange:
		if auth.IdentityAudience != "" {
			v.add(path+".identity_audience", "must be empty for token-exchange mode")
		}
		validateOAuthCredential(v, path+".token_exchange", auth.TokenExchange, environment, allowLocal, true, true)
	case model.DownstreamClientCredentials:
		if auth.IdentityAudience != "" {
			v.add(path+".identity_audience", "must be empty for client-credentials mode")
		}
		validateOAuthCredential(v, path+".client_credentials", auth.ClientCredentials, environment, allowLocal, false, true)
	case model.DownstreamAuthorizationCode:
		if auth.IdentityAudience != "" {
			v.add(path+".identity_audience", "must be empty for authorization-code mode")
		}
		validateOAuthCredential(v, path+".authorization_code", auth.AuthorizationCode, environment, allowLocal, false, false)
		validateAbsoluteHTTPURL(v, path+".authorization_code.authorization_url", auth.AuthorizationCode.AuthorizationURL, environment == "production")
		if auth.AuthorizationCode.AuthorizationURL != "" {
			if parsed, err := url.Parse(auth.AuthorizationCode.AuthorizationURL); err == nil && parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
				v.add(path+".authorization_code.authorization_url", "http is allowed only for a loopback development endpoint")
			}
			if parsed, err := url.Parse(auth.AuthorizationCode.AuthorizationURL); err == nil && parsed.Scheme == "http" && !allowLocal {
				v.add(path+".authorization_code.authorization_url", "loopback authorization endpoint requires network.allow_local=true")
			}
		}
		if auth.AuthorizationCode.RevocationURL != "" {
			validateAbsoluteHTTPURL(v, path+".authorization_code.revocation_url", auth.AuthorizationCode.RevocationURL, environment == "production")
			if parsed, err := url.Parse(auth.AuthorizationCode.RevocationURL); err == nil && parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
				v.add(path+".authorization_code.revocation_url", "http is allowed only for a loopback development endpoint")
			}
			if parsed, err := url.Parse(auth.AuthorizationCode.RevocationURL); err == nil && parsed.Scheme == "http" && !allowLocal {
				v.add(path+".authorization_code.revocation_url", "loopback revocation endpoint requires network.allow_local=true")
			}
		}
	default:
		v.add(path+".mode", "must be signed-identity, bearer-passthrough, token-exchange, client-credentials, or authorization-code")
	}
	if auth.Cache.Capacity < 0 || auth.Cache.Capacity > 1_000_000 {
		v.add(path+".cache.capacity", "must be between 1 and 1000000 when configured")
	}
	if configured := time.Duration(auth.Cache.RefreshSkew); configured < 0 || configured > time.Hour {
		v.add(path+".cache.refresh_skew", "must be between 0 and 1h")
	}
	if configured := time.Duration(auth.Cache.NegativeTTL); configured < 0 || configured > time.Minute {
		v.add(path+".cache.negative_ttl", "must be between 0 and 1m")
	}
}

func validateDownstreamOAuth(v *validator, config DownstreamOAuthConfig, environment string, domains []Domain) {
	enabled := false
	for _, domain := range domains {
		if domain.DownstreamAuth.Mode == string(model.DownstreamAuthorizationCode) {
			enabled = true
			break
		}
	}
	if !enabled && config.TokenStoreFile == "" && config.EncryptionKeyRef == "" && config.StateTTL == 0 {
		return
	}
	if (config.TokenStoreFile == "") != (config.EncryptionKeyRef == "") {
		v.add("downstream_oauth.token_store_file", "token_store_file and encryption_key_ref must be configured together")
	}
	if config.TokenStoreFile != "" && !filepath.IsAbs(config.TokenStoreFile) {
		v.add("downstream_oauth.token_store_file", "must be an absolute path")
	}
	if config.EncryptionKeyRef != "" && !validSecretReference(config.EncryptionKeyRef) {
		v.add("downstream_oauth.encryption_key_ref", "must use a non-empty env: or file: reference")
	}
	if enabled && environment == "production" {
		if config.TokenStoreFile == "" {
			v.add("downstream_oauth.token_store_file", "is required for authorization-code mode in production")
		}
		if config.EncryptionKeyRef == "" {
			v.add("downstream_oauth.encryption_key_ref", "is required for authorization-code mode in production")
		}
	}
	if ttl := time.Duration(config.StateTTL); ttl < 0 || ttl > 15*time.Minute {
		v.add("downstream_oauth.state_ttl", "must be between 0 and 15m")
	}
}

func validateOAuthCredential(v *validator, path string, config OAuthCredentialConfig, environment string, allowLocal, delegated, targetRequired bool) {
	validateAbsoluteHTTPURL(v, path+".token_url", config.TokenURL, environment == "production")
	if parsed, err := url.Parse(config.TokenURL); err == nil && parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
		v.add(path+".token_url", "http is allowed only for a loopback development endpoint")
	}
	if parsed, err := url.Parse(config.TokenURL); err == nil && parsed.Scheme == "http" && !allowLocal {
		v.add(path+".token_url", "loopback token endpoint requires network.allow_local=true")
	}
	if config.ClientID == "" {
		v.add(path+".client_id", "is required")
	}
	if !validSecretReference(config.ClientSecretRef) {
		v.add(path+".client_secret_ref", "must use a non-empty env: or file: reference")
	}
	if config.TokenEndpointAuth != "" &&
		config.TokenEndpointAuth != "client_secret_basic" &&
		config.TokenEndpointAuth != "client_secret_post" {
		v.add(path+".token_endpoint_auth_method", "must be client_secret_basic or client_secret_post")
	}
	if targetRequired && config.Audience == "" && config.Resource == "" {
		v.add(path+".audience", "audience or resource is required")
	}
	seenScopes := make(map[string]struct{}, len(config.Scopes))
	for index, scope := range config.Scopes {
		if strings.TrimSpace(scope) == "" || strings.ContainsAny(scope, " \t\r\n") {
			v.add(fmt.Sprintf("%s.scopes[%d]", path, index), "must be one non-empty OAuth scope")
		}
		if _, exists := seenScopes[scope]; exists {
			v.add(fmt.Sprintf("%s.scopes[%d]", path, index), "duplicates another scope")
		}
		seenScopes[scope] = struct{}{}
	}
	if delegated && len(config.Scopes) == 0 {
		v.add(path+".scopes", "must contain at least one explicit delegated scope")
	}
	validateTLS(v, path+".tls", config.TLS, environment)
}

func validateTLS(v *validator, path string, config TLSConfig, environment string) {
	if environment == "production" && config.InsecureSkipVerify {
		v.add(path+".insecure_skip_verify", "is forbidden in production")
	}
	if (config.ClientCertFile == "") != (config.ClientKeyFile == "") {
		v.add(path+".client_cert_file", "client_cert_file and client_key_file must be configured together")
	}
}

func validSecretReference(reference string) bool {
	prefix, value, found := strings.Cut(reference, ":")
	if !found || strings.TrimSpace(value) == "" {
		return false
	}
	return prefix == "env" || prefix == "file"
}

func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateCommand(v *validator, path string, command Command) {
	method := strings.ToUpper(command.Method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		v.add(path+".method", "must be GET, POST, PUT, PATCH, or DELETE")
	}
	risk := model.Risk(command.Risk)
	if !risk.Valid() {
		v.add(path+".risk", "must be read, write, or destroy")
	}
	if risk == model.RiskDestroy && !command.Confirm {
		v.add(path+".confirm", "must be true for destroy commands")
	}

	placeholders := validateEndpoint(v, path+".endpoint", command.Endpoint)
	flags := make(map[string]Flag)
	for index, flag := range command.Flags {
		flagPath := fmt.Sprintf("%s.flags[%d]", path, index)
		if !namePattern.MatchString(flag.Name) {
			v.add(flagPath+".name", "must match ^[a-z][a-z0-9-]{0,31}$")
		}
		if flag.Name == "confirm" {
			v.add(flagPath+".name", "confirm is reserved by the gateway")
		}
		if _, exists := flags[flag.Name]; exists {
			v.add(flagPath+".name", "duplicates another flag")
		}
		flags[flag.Name] = flag
		validateFlag(v, flagPath, flag, method)
	}

	for placeholder := range placeholders {
		flag, exists := flags[placeholder]
		if !exists {
			v.add(path+".endpoint", fmt.Sprintf("placeholder %q has no matching flag", placeholder))
			continue
		}
		if flag.In != string(model.FlagInPath) || !flag.Required {
			v.add(path+".endpoint", fmt.Sprintf("placeholder %q must map to a required path flag", placeholder))
		}
	}
	for name, flag := range flags {
		if flag.In == string(model.FlagInPath) {
			if _, exists := placeholders[name]; !exists {
				v.add(path+".endpoint", fmt.Sprintf("path flag %q is not used by endpoint", name))
			}
		}
	}
}

func validateFlag(v *validator, path string, flag Flag, method string) {
	flagType := model.FlagType(flag.Type)
	switch flagType {
	case model.FlagString, model.FlagInt, model.FlagBool, model.FlagStringArray:
	default:
		v.add(path+".type", "must be string, int, bool, or stringArray")
	}
	location := model.FlagLocation(flag.In)
	switch location {
	case model.FlagInBody, model.FlagInQuery, model.FlagInPath, model.FlagInHeader:
	default:
		v.add(path+".in", "must be body, query, path, or header")
	}
	if location == model.FlagInPath && !flag.Required {
		v.add(path+".required", "must be true for path flags")
	}
	if location == model.FlagInBody && method != "POST" && method != "PUT" && method != "PATCH" {
		v.add(path+".in", "body flags require POST, PUT, or PATCH")
	}
	if location == model.FlagInHeader {
		if flag.HeaderName == "" {
			v.add(path+".header_name", "is required for header flags")
		} else if !headerNamePattern.MatchString(flag.HeaderName) {
			v.add(path+".header_name", "is not a valid HTTP header name")
		} else if forbiddenHeader(flag.HeaderName) {
			v.add(path+".header_name", "is protected and cannot be set by command arguments")
		}
		if flagType == model.FlagStringArray {
			v.add(path+".type", "stringArray is not supported for header flags")
		}
	} else if flag.HeaderName != "" {
		v.add(path+".header_name", "is only valid for header flags")
	}
	if flag.QueryName != "" && location != model.FlagInQuery {
		v.add(path+".query_name", "is only valid for query flags")
	}
	if flag.Default != nil && !defaultMatches(flagType, flag.Default) {
		v.add(path+".default", "does not match the declared flag type")
	}
}

func validateEndpoint(v *validator, path, endpoint string) map[string]struct{} {
	result := make(map[string]struct{})
	if endpoint == "" || !strings.HasPrefix(endpoint, "/") {
		v.add(path, "must be a non-empty absolute path")
		return result
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		v.add(path, "must be a relative upstream path without scheme, host, query, userinfo, or fragment")
		return result
	}
	if strings.Contains(endpoint, "\\") {
		v.add(path, "must not contain backslashes")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			v.add(path, "must not contain empty or dot path segments")
			continue
		}
		match := placeholderPattern.FindStringSubmatch(segment)
		if len(match) == 2 {
			if _, duplicate := result[match[1]]; duplicate {
				v.add(path, fmt.Sprintf("placeholder %q appears more than once", match[1]))
			}
			result[match[1]] = struct{}{}
			continue
		}
		if strings.ContainsAny(segment, "{}") {
			v.add(path, "placeholders must occupy a complete path segment")
		}
	}
	return result
}

func validateAbsoluteHTTPURL(v *validator, path, raw string, requireHTTPS bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		v.add(path, "must be an absolute HTTP URL without userinfo, query, or fragment")
		return
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		v.add(path, "scheme must be http or https")
	}
	if requireHTTPS && parsed.Scheme != "https" {
		v.add(path, "must use https")
	}
}

func validateUpstream(v *validator, path, raw string, allowLocal bool) {
	validateAbsoluteHTTPURL(v, path, raw, false)
	parsed, err := url.Parse(raw)
	if err != nil {
		return
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") && !allowLocal {
		v.add(path, "localhost requires network.allow_local=true")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		v.add(path, "link-local, multicast, and unspecified addresses are forbidden")
		return
	}
	if ip.IsLoopback() && !allowLocal {
		v.add(path, "loopback addresses require network.allow_local=true")
	}
}

func defaultMatches(flagType model.FlagType, value any) bool {
	switch flagType {
	case model.FlagString:
		_, ok := value.(string)
		return ok
	case model.FlagInt:
		_, ok := value.(int)
		return ok
	case model.FlagBool:
		_, ok := value.(bool)
		return ok
	case model.FlagStringArray:
		values, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range values {
			if _, ok := item.(string); !ok {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func forbiddenHeader(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "x-cli-gateway-") || strings.HasPrefix(lower, "x-forwarded-") {
		return true
	}
	switch lower {
	case "authorization", "host", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade", "cookie", "set-cookie", "forwarded":
		return true
	default:
		return false
	}
}

func generatedToolName(domain string, path []string) string {
	parts := append([]string{domain}, path...)
	return strings.ReplaceAll(strings.Join(parts, "_"), "-", "_")
}

func domainTimeout(value Duration) time.Duration {
	if value == 0 {
		return defaultDomainTimeout
	}
	return time.Duration(value)
}

func (v *validator) add(path, message string) {
	position := v.positions[path]
	v.errors = append(v.errors, ValidationError{
		Path: path, Line: position.Line, Column: position.Column, Message: message,
	})
}
