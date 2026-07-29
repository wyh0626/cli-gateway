package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedAuthorizationTokenStorePersistsCiphertext(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tokens.enc")
	secret := strings.Repeat("store-secret-", 4)
	store, err := NewEncryptedFileAuthorizationTokenStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	key := store.Key("https://issuer.example", "tenant-a", "alice@example.com", "github", "config-v1")
	want := AuthorizationToken{
		AccessToken:  "access-token-must-not-appear",
		RefreshToken: "refresh-token-must-not-appear",
		ExpiresAt:    time.Now().UTC().Add(time.Hour).Round(time.Second),
		Scopes:       []string{"repo", "read:user"},
		UpdatedAt:    time.Now().UTC().Round(time.Second),
	}
	if err := store.Save(key, want); err != nil {
		t.Fatal(err)
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{
		[]byte(want.AccessToken),
		[]byte(want.RefreshToken),
		[]byte("alice@example.com"),
		[]byte("tenant-a"),
	} {
		if bytes.Contains(encoded, plaintext) {
			t.Fatalf("encrypted file contains plaintext %q", plaintext)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}

	reloaded, err := NewEncryptedFileAuthorizationTokenStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := reloaded.Load(key)
	if err != nil || !found {
		t.Fatalf("Load() = %#v, %t, %v", got, found, err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken ||
		!got.ExpiresAt.Equal(want.ExpiresAt) || !got.UpdatedAt.Equal(want.UpdatedAt) ||
		strings.Join(got.Scopes, " ") != strings.Join(want.Scopes, " ") {
		t.Fatalf("reloaded token = %#v, want %#v", got, want)
	}
}

func TestEncryptedAuthorizationTokenStoreRejectsWrongKeyAndLoosePermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tokens.enc")
	store, err := NewEncryptedFileAuthorizationTokenStore(path, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(store.Key("alice"), AuthorizationToken{RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedFileAuthorizationTokenStore(path, strings.Repeat("b", 32)); err == nil ||
		!strings.Contains(err.Error(), "could not be decrypted") {
		t.Fatalf("wrong-key error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedFileAuthorizationTokenStore(path, strings.Repeat("a", 32)); err == nil ||
		!strings.Contains(err.Error(), "permissions") {
		t.Fatalf("loose-permissions error = %v", err)
	}
}
