// Package auth verifies external identity tokens and builds trusted principals.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	// ErrMissingToken means no bearer credential was supplied.
	ErrMissingToken = errors.New("missing bearer token")
	// ErrInvalidToken means the credential failed cryptographic or claim validation.
	ErrInvalidToken = errors.New("invalid bearer token")
	// ErrExpiredToken means a correctly signed credential is outside its expiry.
	ErrExpiredToken = errors.New("expired bearer token")
)

const (
	maxJWTHeaderBytes         = 8 << 10
	maxIdentityClaimPathDepth = 8
)

// Verifier converts a bearer token into a trusted Principal.
type Verifier interface {
	Verify(context.Context, string) (model.Principal, error)
}

type keySource interface {
	Current() jwk.Set
	Refresh(context.Context) error
}

type fixedKeySource struct {
	keys jwk.Set
}

func (s fixedKeySource) Current() jwk.Set            { return s.keys }
func (fixedKeySource) Refresh(context.Context) error { return nil }

// JWTVerifier verifies access tokens with an explicit algorithm allowlist.
type JWTVerifier struct {
	keys           keySource
	issuer         string
	audience       string
	algorithms     map[string]struct{}
	identityClaims map[string]string
	manager        *JWKSManager
}

// NewRemoteJWTVerifier fetches the configured JWKS before serving traffic and
// enables cache-aware refresh on unknown key IDs.
func NewRemoteJWTVerifier(ctx context.Context, jwksURL, issuer, audience string, allowLocal bool) (*JWTVerifier, error) {
	return NewRemoteJWTVerifierWithTLS(ctx, jwksURL, issuer, audience, allowLocal, model.TLSConfig{})
}

// NewRemoteJWTVerifierWithTLS fetches JWKS using configured trust material.
func NewRemoteJWTVerifierWithTLS(ctx context.Context, jwksURL, issuer, audience string, allowLocal bool, tlsConfig model.TLSConfig) (*JWTVerifier, error) {
	manager, err := NewJWKSManagerWithTLS(jwksURL, allowLocal, JWKSOptions{}, tlsConfig)
	if err != nil {
		return nil, err
	}
	if err := manager.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("fetch trusted JWKS: %w", err)
	}
	verifier, err := newJWTVerifier(manager, issuer, audience)
	if err != nil {
		return nil, err
	}
	verifier.manager = manager
	return verifier, nil
}

// NewJWTVerifier constructs a verifier from an already loaded key set.
func NewJWTVerifier(keys jwk.Set, issuer, audience string) (*JWTVerifier, error) {
	if keys == nil || keys.Len() == 0 {
		return nil, errors.New("trusted JWKS contains no keys")
	}
	return newJWTVerifier(fixedKeySource{keys: keys}, issuer, audience)
}

func newJWTVerifier(keys keySource, issuer, audience string) (*JWTVerifier, error) {
	if keys == nil || keys.Current() == nil || keys.Current().Len() == 0 {
		return nil, errors.New("trusted JWKS contains no keys")
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("issuer and audience are required")
	}
	return &JWTVerifier{
		keys: keys, issuer: issuer, audience: audience,
		algorithms: map[string]struct{}{"ES256": {}, "RS256": {}}, identityClaims: map[string]string{},
	}, nil
}

// ConfigureIdentityClaims selects verified inbound claims that may be copied
// into a short-lived downstream signed identity. Only the stable email and
// display-name targets are supported.
func (v *JWTVerifier) ConfigureIdentityClaims(mapping map[string]string) error {
	configured := make(map[string]string, len(mapping))
	for target, source := range mapping {
		if target != "email" && target != "name" {
			return fmt.Errorf("unsupported identity claim target %q", target)
		}
		source = strings.TrimSpace(source)
		if !validIdentityClaimSource(source) {
			return fmt.Errorf("invalid source claim for %q", target)
		}
		configured[target] = source
	}
	v.identityClaims = configured
	return nil
}

// Start runs periodic JWKS refresh until ctx is cancelled.
func (v *JWTVerifier) Start(ctx context.Context) {
	if v != nil && v.manager != nil {
		v.manager.Start(ctx)
	}
}

// Verify validates algorithm, signature, kid, registered time claims, issuer,
// audience, and subject.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (model.Principal, error) {
	if strings.TrimSpace(raw) == "" {
		return model.Principal{}, ErrMissingToken
	}
	header, err := parseJWTHeader(raw)
	if err != nil {
		return model.Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if _, allowed := v.algorithms[header.Algorithm]; !allowed {
		return model.Principal{}, fmt.Errorf("%w: signing algorithm is not allowed", ErrInvalidToken)
	}
	if header.KeyID == "" {
		return model.Principal{}, fmt.Errorf("%w: key ID is missing", ErrInvalidToken)
	}

	keys := v.keys.Current()
	if !containsKeyID(keys, header.KeyID) {
		if v.manager != nil {
			_ = v.manager.RefreshUnknownKey(ctx, header.KeyID)
		} else {
			_ = v.keys.Refresh(ctx)
		}
		keys = v.keys.Current()
	}
	if !containsKeyID(keys, header.KeyID) {
		return model.Principal{}, fmt.Errorf("%w: signing key is unavailable", ErrInvalidToken)
	}
	token, err := jwt.Parse(
		[]byte(raw),
		jwt.WithKeySet(keys),
		jwt.WithValidate(false),
	)
	if err != nil {
		return model.Principal{}, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidToken, err)
	}
	if err := jwt.Validate(
		token,
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
	); err != nil {
		if errors.Is(err, jwt.ErrTokenExpired()) {
			return model.Principal{}, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return model.Principal{}, fmt.Errorf("%w: claim validation failed: %v", ErrInvalidToken, err)
	}
	if token.Subject() == "" {
		return model.Principal{}, fmt.Errorf("%w: subject is missing", ErrInvalidToken)
	}

	principal := model.Principal{
		Subject:   token.Subject(),
		Issuer:    token.Issuer(),
		ExpiresAt: token.Expiration(),
		Scopes:    extractScopes(token),
		Invoker:   model.InvokerUnknown,
	}
	if claim := v.identityClaims["email"]; claim != "" {
		if value, ok := identityClaimValue(token, claim); ok {
			principal.Email = stringClaim(value)
		}
	}
	if claim := v.identityClaims["name"]; claim != "" {
		if value, ok := identityClaimValue(token, claim); ok {
			principal.Name = stringClaim(value)
		}
	}
	if value, ok := token.Get("tid"); ok {
		principal.Tenant = stringClaim(value)
	} else if value, ok := token.Get("tenant_id"); ok {
		principal.Tenant = stringClaim(value)
	}
	if value, ok := token.Get("sid"); ok {
		principal.SessionID = stringClaim(value)
	}
	if value, ok := token.Get("invoker"); ok {
		if parsed := model.Invoker(stringClaim(value)); parsed == model.InvokerHuman || parsed == model.InvokerAI || parsed == model.InvokerCI {
			principal.Invoker = parsed
		}
	}
	if value, ok := token.Get("client_id"); ok {
		principal.ClientID = stringClaim(value)
	} else if value, ok := token.Get("azp"); ok {
		principal.ClientID = stringClaim(value)
	}
	return principal, nil
}

func validIdentityClaimSource(source string) bool {
	if source == "" || len(source) > 128 || strings.ContainsAny(source, " \t\r\n") {
		return false
	}
	segments := strings.Split(source, ".")
	if len(segments) > maxIdentityClaimPathDepth {
		return false
	}
	for _, segment := range segments {
		if segment == "" {
			return false
		}
	}
	return true
}

func identityClaimValue(token jwt.Token, source string) (any, bool) {
	// Preserve exact top-level claim behavior, including claim names containing
	// dots. Only traverse nested objects when no exact claim exists.
	if value, ok := token.Get(source); ok {
		return value, true
	}
	segments := strings.Split(source, ".")
	if len(segments) < 2 {
		return nil, false
	}
	value, ok := token.Get(segments[0])
	if !ok {
		return nil, false
	}
	for _, segment := range segments[1:] {
		object, isObject := value.(map[string]any)
		if !isObject {
			return nil, false
		}
		value, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return value, true
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

func parseJWTHeader(raw string) (jwtHeader, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[0]) == 0 {
		return jwtHeader{}, errors.New("token is not compact JWS")
	}
	encoded := parts[0]
	if len(encoded) > base64.RawURLEncoding.EncodedLen(maxJWTHeaderBytes) {
		return jwtHeader{}, errors.New("JWT header is too large")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return jwtHeader{}, errors.New("JWT header is not base64url")
	}
	var header jwtHeader
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	if err := decoder.Decode(&header); err != nil {
		return jwtHeader{}, errors.New("JWT header is invalid")
	}
	return header, nil
}

func containsKeyID(keys jwk.Set, expected string) bool {
	if keys == nil {
		return false
	}
	for index := 0; index < keys.Len(); index++ {
		key, ok := keys.Key(index)
		if ok && key.KeyID() == expected {
			return true
		}
	}
	return false
}

func extractScopes(token jwt.Token) map[string]struct{} {
	result := make(map[string]struct{})
	value, ok := token.Get("scope")
	if !ok {
		value, ok = token.Get("scp")
	}
	if !ok {
		return result
	}
	switch typed := value.(type) {
	case string:
		for _, scope := range strings.Fields(typed) {
			result[scope] = struct{}{}
		}
	case []string:
		for _, scope := range typed {
			if scope != "" {
				result[scope] = struct{}{}
			}
		}
	case []any:
		for _, item := range typed {
			if scope, ok := item.(string); ok && scope != "" {
				result[scope] = struct{}{}
			}
		}
	}
	return result
}

func stringClaim(value any) string {
	text, _ := value.(string)
	return text
}
