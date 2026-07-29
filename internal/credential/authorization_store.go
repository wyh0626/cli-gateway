package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxAuthorizationStoreBytes = 64 << 20
	authorizationStoreAAD      = "cli-gateway-downstream-oauth-store-v1"
)

// AuthorizationToken is one per-user downstream OAuth grant. Values are
// persisted only through an AuthorizationTokenStore that protects them at rest.
type AuthorizationToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthorizationTokenStore stores authorization-code tokens under opaque keys.
type AuthorizationTokenStore interface {
	Key(parts ...string) string
	Load(string) (AuthorizationToken, bool, error)
	Save(string, AuthorizationToken) error
	Delete(string) error
}

// MemoryAuthorizationTokenStore is the development and test implementation.
type MemoryAuthorizationTokenStore struct {
	mu      sync.RWMutex
	key     []byte
	records map[string]AuthorizationToken
}

// NewMemoryAuthorizationTokenStore constructs an in-memory token store.
func NewMemoryAuthorizationTokenStore(key []byte) (*MemoryAuthorizationTokenStore, error) {
	if len(key) < 32 {
		return nil, errors.New("authorization token store key must be at least 32 bytes")
	}
	return &MemoryAuthorizationTokenStore{
		key: append([]byte(nil), key...), records: make(map[string]AuthorizationToken),
	}, nil
}

// Key returns an opaque, length-delimited HMAC key.
func (s *MemoryAuthorizationTokenStore) Key(parts ...string) string {
	return authorizationStoreKey(s.key, parts...)
}

// Load returns a detached token copy.
func (s *MemoryAuthorizationTokenStore) Load(key string) (AuthorizationToken, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.records[key]
	token.Scopes = append([]string(nil), token.Scopes...)
	return token, ok, nil
}

// Save stores a detached token copy.
func (s *MemoryAuthorizationTokenStore) Save(key string, token AuthorizationToken) error {
	if key == "" || (token.AccessToken == "" && token.RefreshToken == "") {
		return errors.New("authorization token key and at least one token are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token.Scopes = append([]string(nil), token.Scopes...)
	s.records[key] = token
	return nil
}

// Delete removes one token.
func (s *MemoryAuthorizationTokenStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key)
	return nil
}

// EncryptedFileAuthorizationTokenStore is a single-process, atomically
// persisted AES-256-GCM token store for the default cli-gateway deployment model.
type EncryptedFileAuthorizationTokenStore struct {
	mu            sync.RWMutex
	path          string
	encryptionKey []byte
	bindingKey    []byte
	records       map[string]AuthorizationToken
}

type authorizationStoreEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type authorizationStorePayload struct {
	Version int                           `json:"version"`
	Records map[string]AuthorizationToken `json:"records"`
}

// NewEncryptedFileAuthorizationTokenStore loads or creates an encrypted token
// store. secret must be a high-entropy value of at least 32 bytes.
func NewEncryptedFileAuthorizationTokenStore(path, secret string) (*EncryptedFileAuthorizationTokenStore, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("authorization token store path must be absolute")
	}
	if len(secret) < 32 {
		return nil, errors.New("authorization token store secret must be at least 32 bytes")
	}
	encryptionDigest := sha256.Sum256(append([]byte("cli-gateway/oauth-store/encryption\x00"), []byte(secret)...))
	bindingDigest := sha256.Sum256(append([]byte("cli-gateway/oauth-store/binding\x00"), []byte(secret)...))
	store := &EncryptedFileAuthorizationTokenStore{
		path: path, encryptionKey: encryptionDigest[:], bindingKey: bindingDigest[:],
		records: make(map[string]AuthorizationToken),
	}
	if err := store.loadFile(); err != nil {
		return nil, err
	}
	return store, nil
}

// Key returns a stable opaque key without exposing user identifiers on disk.
func (s *EncryptedFileAuthorizationTokenStore) Key(parts ...string) string {
	return authorizationStoreKey(s.bindingKey, parts...)
}

// Load returns a detached token copy.
func (s *EncryptedFileAuthorizationTokenStore) Load(key string) (AuthorizationToken, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.records[key]
	token.Scopes = append([]string(nil), token.Scopes...)
	return token, ok, nil
}

// Save atomically rewrites the encrypted file.
func (s *EncryptedFileAuthorizationTokenStore) Save(key string, token AuthorizationToken) error {
	if key == "" || (token.AccessToken == "" && token.RefreshToken == "") {
		return errors.New("authorization token key and at least one token are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token.Scopes = append([]string(nil), token.Scopes...)
	previous, existed := s.records[key]
	s.records[key] = token
	if err := s.persistLocked(); err != nil {
		if existed {
			s.records[key] = previous
		} else {
			delete(s.records, key)
		}
		return err
	}
	return nil
}

// Delete atomically removes one record.
func (s *EncryptedFileAuthorizationTokenStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.records[key]
	if !existed {
		return nil
	}
	delete(s.records, key)
	if err := s.persistLocked(); err != nil {
		s.records[key] = previous
		return err
	}
	return nil
}

func (s *EncryptedFileAuthorizationTokenStore) loadFile() error {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open authorization token store: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat authorization token store: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("authorization token store permissions must not grant group or other access")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxAuthorizationStoreBytes+1))
	if err != nil {
		return fmt.Errorf("read authorization token store: %w", err)
	}
	if len(encoded) > maxAuthorizationStoreBytes {
		return errors.New("authorization token store exceeds 64 MiB")
	}
	var envelope authorizationStoreEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Version != 1 {
		return errors.New("authorization token store envelope is invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return errors.New("authorization token store nonce is invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return errors.New("authorization token store ciphertext is invalid")
	}
	aead, err := authorizationStoreAEAD(s.encryptionKey)
	if err != nil {
		return err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(authorizationStoreAAD))
	if err != nil {
		return errors.New("authorization token store could not be decrypted")
	}
	var payload authorizationStorePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Version != 1 || payload.Records == nil {
		return errors.New("authorization token store payload is invalid")
	}
	s.records = payload.Records
	return nil
}

func (s *EncryptedFileAuthorizationTokenStore) persistLocked() error {
	parent := filepath.Dir(s.path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create authorization token store directory: %w", err)
	}
	plaintext, err := json.Marshal(authorizationStorePayload{Version: 1, Records: s.records})
	if err != nil {
		return fmt.Errorf("encode authorization token store: %w", err)
	}
	aead, err := authorizationStoreAEAD(s.encryptionKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate authorization token store nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(authorizationStoreAAD))
	encoded, err := json.Marshal(authorizationStoreEnvelope{
		Version: 1, Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return fmt.Errorf("encode authorization token store envelope: %w", err)
	}

	temporary, err := os.CreateTemp(parent, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create authorization token store temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure authorization token store temporary file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write authorization token store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync authorization token store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close authorization token store: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace authorization token store: %w", err)
	}
	directory, err := os.Open(parent)
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func authorizationStoreAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize authorization token store cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize authorization token store AEAD: %w", err)
	}
	return aead, nil
}

func authorizationStoreKey(key []byte, parts ...string) string {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		length := len(part)
		_, _ = mac.Write([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
		_, _ = mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
