package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestJWTVerifier(t *testing.T) {
	t.Parallel()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = privateJWK.Set(jwk.KeyIDKey, "test-key")
	_ = privateJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicJWK.Set(jwk.KeyIDKey, "test-key")
	_ = publicJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	set := jwk.NewSet()
	if err := set.AddKey(publicJWK); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewJWTVerifier(set, "https://issuer.example", "cli-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.ConfigureIdentityClaims(map[string]string{"email": "email", "name": "name"}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	token, err := jwt.NewBuilder().Issuer("https://issuer.example").Audience([]string{"cli-gateway"}).Subject("alice").
		IssuedAt(now).Expiration(now.Add(time.Minute)).Claim("scope", []string{"demo:read", "demo:write"}).Claim("invoker", "human").
		Claim("email", "alice@example.com").Claim("name", "Alice").Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateJWK))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.Verify(context.Background(), string(signed))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	_, hasWriteScope := principal.Scopes["demo:write"]
	if principal.Subject != "alice" || principal.Email != "alice@example.com" || principal.Name != "Alice" ||
		principal.Invoker != model.InvokerHuman || !hasWriteScope {
		t.Fatalf("principal = %#v", principal)
	}

	wrongAudience, err := NewJWTVerifier(set, "https://issuer.example", "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongAudience.Verify(context.Background(), string(signed)); err == nil {
		t.Fatal("wrong audience token was accepted")
	}
}

func TestJWTVerifierIdentityClaimPaths(t *testing.T) {
	t.Parallel()
	privateKey, publicKey := testJWKPair(t, "identity-paths")
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewJWTVerifier(set, "https://issuer.example", "cli-gateway")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		mapping   map[string]string
		claims    map[string]any
		wantEmail string
		wantName  string
	}{
		{
			name:      "top level behavior is unchanged",
			mapping:   map[string]string{"email": "email", "name": "name"},
			claims:    map[string]any{"email": "alice@example.com", "name": "Alice"},
			wantEmail: "alice@example.com",
			wantName:  "Alice",
		},
		{
			name:    "nested object paths",
			mapping: map[string]string{"email": "ext.email", "name": "ext.profile.name"},
			claims: map[string]any{"ext": map[string]any{
				"email":   "nested@example.com",
				"profile": map[string]any{"name": "Nested Alice"},
			}},
			wantEmail: "nested@example.com",
			wantName:  "Nested Alice",
		},
		{
			name:    "exact dotted top level claim takes precedence",
			mapping: map[string]string{"email": "ext.email"},
			claims: map[string]any{
				"ext.email": "exact@example.com",
				"ext":       map[string]any{"email": "nested@example.com"},
			},
			wantEmail: "exact@example.com",
		},
		{
			name:    "non object intermediate value fails closed",
			mapping: map[string]string{"email": "ext.email"},
			claims:  map[string]any{"ext": "not-an-object"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifier.ConfigureIdentityClaims(test.mapping); err != nil {
				t.Fatal(err)
			}
			builder := jwt.NewBuilder().
				Issuer("https://issuer.example").
				Audience([]string{"cli-gateway"}).
				Subject("alice").
				Expiration(time.Now().Add(time.Minute))
			for claim, value := range test.claims {
				builder.Claim(claim, value)
			}
			token, err := builder.Build()
			if err != nil {
				t.Fatal(err)
			}
			signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
			if err != nil {
				t.Fatal(err)
			}
			principal, err := verifier.Verify(context.Background(), string(signed))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if principal.Email != test.wantEmail || principal.Name != test.wantName {
				t.Fatalf("principal identity = (%q, %q), want (%q, %q)", principal.Email, principal.Name, test.wantEmail, test.wantName)
			}
		})
	}
}

func TestJWTVerifierRejectsInvalidIdentityClaimPaths(t *testing.T) {
	t.Parallel()
	_, publicKey := testJWKPair(t, "invalid-identity-paths")
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewJWTVerifier(set, "https://issuer.example", "cli-gateway")
	if err != nil {
		t.Fatal(err)
	}

	for _, source := range []string{"", ".email", "ext.", "ext..email", "a.b.c.d.e.f.g.h.i"} {
		t.Run(source, func(t *testing.T) {
			if err := verifier.ConfigureIdentityClaims(map[string]string{"email": source}); err == nil {
				t.Fatalf("ConfigureIdentityClaims(%q) accepted an invalid path", source)
			}
		})
	}
}

func TestRemoteJWTVerifierRefreshesUnknownKeyAndKeepsOverlap(t *testing.T) {
	t.Parallel()
	firstPrivate, firstPublic := testJWKPair(t, "first")
	secondPrivate, secondPublic := testJWKPair(t, "second")
	var mu sync.RWMutex
	active := firstPublic
	var fetches atomic.Int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		mu.RLock()
		selected := active
		mu.RUnlock()
		set := jwk.NewSet()
		if err := set.AddKey(selected); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Cache-Control", "max-age=300")
		if err := json.NewEncoder(writer).Encode(set); err != nil {
			t.Error(err)
		}
	}))
	defer jwksServer.Close()

	verifier, err := NewRemoteJWTVerifier(context.Background(), jwksServer.URL, "https://issuer.example", "cli-gateway", true)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := signTestToken(t, firstPrivate, time.Now().Add(time.Minute))
	if _, err := verifier.Verify(context.Background(), firstToken); err != nil {
		t.Fatalf("verify first token: %v", err)
	}

	mu.Lock()
	active = secondPublic
	mu.Unlock()
	secondToken := signTestToken(t, secondPrivate, time.Now().Add(time.Minute))
	if _, err := verifier.Verify(context.Background(), secondToken); err != nil {
		t.Fatalf("verify rotated token: %v", err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("JWKS fetches = %d, want 2", fetches.Load())
	}
	if _, err := verifier.Verify(context.Background(), firstToken); err != nil {
		t.Fatalf("previous key was not accepted during overlap: %v", err)
	}
}

func TestJWTVerifierClassifiesExpiredToken(t *testing.T) {
	t.Parallel()
	private, public := testJWKPair(t, "expired")
	set := jwk.NewSet()
	if err := set.AddKey(public); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewJWTVerifier(set, "https://issuer.example", "cli-gateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), signTestToken(t, private, time.Now().Add(-2*time.Minute)))
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Verify() error = %v, want ErrExpiredToken", err)
	}
}

func testJWKPair(t *testing.T, keyID string) (jwk.Key, jwk.Key) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = privateJWK.Set(jwk.KeyIDKey, keyID)
	_ = privateJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicJWK.Set(jwk.KeyIDKey, keyID)
	_ = publicJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	return privateJWK, publicJWK
}

func signTestToken(t *testing.T, private jwk.Key, expires time.Time) string {
	t.Helper()
	token, err := jwt.NewBuilder().
		Issuer("https://issuer.example").
		Audience([]string{"cli-gateway"}).
		Subject("alice").
		Expiration(expires).
		Claim("scope", "demo:read").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, private))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}
