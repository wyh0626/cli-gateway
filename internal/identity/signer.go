// Package identity signs short-lived downstream identity assertions.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Signer owns the current ES256 signing key.
type Signer struct {
	private jwk.Key
	public  jwk.Set
	kid     string
}

// NewSigner loads a configured EC key or generates an ephemeral development key.
func NewSigner(keyFile, environment string) (*Signer, error) {
	return NewRotatingSigner(keyFile, nil, environment)
}

// NewRotatingSigner loads one active signing key plus verification-only
// previous public keys for a bounded deployment rotation window.
func NewRotatingSigner(keyFile string, previousKeyFiles []string, environment string) (*Signer, error) {
	var privateKey *ecdsa.PrivateKey
	var err error
	if keyFile == "" {
		if environment == "production" {
			return nil, errors.New("production identity key file is required")
		}
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		privateKey, err = loadPrivateKey(keyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("load identity signing key: %w", err)
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("identity signing key must use P-256")
	}

	encodedPublic, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal identity public key: %w", err)
	}
	digest := sha256.Sum256(encodedPublic)
	kid := hex.EncodeToString(digest[:8])

	privateJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create private JWK: %w", err)
	}
	if err := configureJWK(privateJWK, kid); err != nil {
		return nil, err
	}
	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		return nil, fmt.Errorf("create public JWK: %w", err)
	}
	if err := configureJWK(publicJWK, kid); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(publicJWK); err != nil {
		return nil, fmt.Errorf("add public JWK: %w", err)
	}
	seen := map[string]struct{}{kid: {}}
	for _, previousFile := range previousKeyFiles {
		previousPublic, loadErr := loadPreviousPublicKey(previousFile)
		if loadErr != nil {
			return nil, fmt.Errorf("load previous identity signing key %s: %w", previousFile, loadErr)
		}
		previousPublicDER, marshalErr := x509.MarshalPKIXPublicKey(previousPublic)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal previous identity public key: %w", marshalErr)
		}
		previousDigest := sha256.Sum256(previousPublicDER)
		previousKID := hex.EncodeToString(previousDigest[:8])
		if _, duplicate := seen[previousKID]; duplicate {
			return nil, fmt.Errorf("duplicate identity signing key %s", previousKID)
		}
		seen[previousKID] = struct{}{}
		previousJWK, jwkErr := jwk.FromRaw(previousPublic)
		if jwkErr != nil {
			return nil, fmt.Errorf("create previous public JWK: %w", jwkErr)
		}
		if configureErr := configureJWK(previousJWK, previousKID); configureErr != nil {
			return nil, configureErr
		}
		if addErr := set.AddKey(previousJWK); addErr != nil {
			return nil, fmt.Errorf("add previous public JWK: %w", addErr)
		}
	}
	return &Signer{private: privateJWK, public: set, kid: kid}, nil
}

// Sign returns a one-minute ES256 identity assertion for the authenticated user.
func (s *Signer) Sign(invocation model.Invocation) (string, error) {
	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Issuer("cli-gateway").
		Audience([]string{invocation.Command.IdentityAudience}).
		Subject(invocation.Principal.Subject).
		IssuedAt(now).
		Expiration(now.Add(time.Minute)).
		Claim("invoker", string(invocation.Invoker)).
		Claim("trace_id", invocation.TraceID)
	if invocation.Principal.Email != "" {
		builder = builder.Claim("email", invocation.Principal.Email)
	}
	if invocation.Principal.Name != "" {
		builder = builder.Claim("name", invocation.Principal.Name)
	}
	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("build identity JWT: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, s.private))
	if err != nil {
		return "", fmt.Errorf("sign identity JWT: %w", err)
	}
	return string(signed), nil
}

// JWKS serializes the public key set.
func (s *Signer) JWKS() ([]byte, error) {
	return json.Marshal(s.public)
}

// KeyID returns the active signing key identifier.
func (s *Signer) KeyID() string {
	return s.kid
}

func configureJWK(key jwk.Key, kid string) error {
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("set JWK kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return fmt.Errorf("set JWK algorithm: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("set JWK usage: %w", err)
	}
	return nil
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("identity key file is not PEM")
	}
	if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return parsed, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC or PKCS8 private key: %w", err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not ECDSA")
	}
	return privateKey, nil
}

func loadPreviousPublicKey(path string) (*ecdsa.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("previous identity key file is not PEM")
	}
	if parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes); parseErr == nil {
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return nil, errors.New("previous identity public key must use ECDSA P-256")
		}
		return publicKey, nil
	}
	if certificate, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return nil, errors.New("previous identity certificate must use ECDSA P-256")
		}
		return publicKey, nil
	}
	privateKey, parseErr := loadPrivateKey(path)
	if parseErr != nil {
		return nil, errors.New("previous identity key must be a P-256 public key, certificate, or private key")
	}
	return &privateKey.PublicKey, nil
}
