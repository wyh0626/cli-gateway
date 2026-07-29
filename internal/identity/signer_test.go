package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestSignerCopiesOnlyVerifiedIdentityFields(t *testing.T) {
	t.Parallel()
	signer, err := NewRotatingSigner("", nil, "development")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(model.Invocation{
		Principal: model.Principal{Subject: "subject-1", Email: "alice@example.com", Name: "Alice"},
		Invoker:   model.InvokerHuman,
		TraceID:   "trace-1",
		Command:   &model.CompiledCommand{Key: "inventory.dns.apply", IdentityAudience: "inventory-cli-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedKeys, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwk.Parse(encodedKeys)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(keys), jwt.WithContext(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	email, _ := token.Get("email")
	name, _ := token.Get("name")
	if email != "alice@example.com" || name != "Alice" || token.Subject() != "subject-1" {
		t.Fatalf("unexpected signed identity: subject=%q email=%v name=%v", token.Subject(), email, name)
	}
	if _, ok := token.Get("scope"); ok {
		t.Fatal("downstream identity unexpectedly contains a gateway command scope")
	}
	if _, ok := token.Get("cmd"); ok {
		t.Fatal("downstream identity unexpectedly contains a gateway command binding")
	}
	if time.Until(token.Expiration()) > time.Minute+time.Second {
		t.Fatalf("identity lifetime too long: %v", time.Until(token.Expiration()))
	}
}

func TestRotatingSignerPublishesCurrentAndPreviousKeys(t *testing.T) {
	t.Parallel()
	current := writeTestKey(t, "current.pem")
	previous := writeTestPublicKey(t, "previous.pem")
	signer, err := NewRotatingSigner(current, []string{previous}, "production")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwk.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Len() != 2 {
		t.Fatalf("JWKS key count = %d, want 2: %s", keys.Len(), encoded)
	}
	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range document.Keys {
		if key["d"] != nil {
			t.Fatal("JWKS leaked private key material")
		}
	}
}

func writeTestPublicKey(t *testing.T, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestKey(t *testing.T, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
