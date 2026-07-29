package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxSecretBytes = 64 << 10

// SecretResolver resolves only explicit environment and file references.
type SecretResolver interface {
	Resolve(string) (string, error)
}

// EnvironmentSecrets is the built-in secret resolver.
type EnvironmentSecrets struct{}

// Resolve implements SecretResolver.
func (EnvironmentSecrets) Resolve(reference string) (string, error) {
	kind, value, found := strings.Cut(reference, ":")
	if !found || strings.TrimSpace(value) == "" {
		return "", errors.New("invalid secret reference")
	}
	switch kind {
	case "env":
		secret, ok := os.LookupEnv(value)
		if !ok || secret == "" {
			return "", fmt.Errorf("secret environment variable %q is unavailable", value)
		}
		return secret, nil
	case "file":
		file, err := os.Open(value)
		if err != nil {
			return "", fmt.Errorf("open secret file: %w", err)
		}
		defer file.Close()
		contents, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		if len(contents) > maxSecretBytes {
			return "", errors.New("secret file exceeds 64 KiB")
		}
		secret := strings.TrimSpace(string(contents))
		if secret == "" {
			return "", errors.New("secret file is empty")
		}
		return secret, nil
	default:
		return "", errors.New("unsupported secret reference")
	}
}
