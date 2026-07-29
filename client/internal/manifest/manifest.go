// Package manifest defines and stores caller-filtered CLI manifests.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Document is the C0 manifest currently returned by cli-gateway.
type Document struct {
	SchemaVersion        int      `json:"schema_version,omitempty"`
	ServerVersion        string   `json:"server_version,omitempty"`
	MinCLIVersion        string   `json:"min_cli_version,omitempty"`
	PrincipalFingerprint string   `json:"principal_fingerprint,omitempty"`
	CLI                  CLI      `json:"cli"`
	Domains              []Domain `json:"domains"`
	ETag                 string   `json:"etag"`
}

// CLI identifies the generated root command.
type CLI struct {
	Name string `json:"name"`
}

// Domain is a dynamic root command.
type Domain struct {
	Name     string    `json:"name"`
	Commands []Command `json:"commands"`
}

// Command describes one executable leaf.
type Command struct {
	Path      []string `json:"path"`
	Summary   string   `json:"summary,omitempty"`
	Method    string   `json:"method"`
	Risk      string   `json:"risk"`
	Confirm   bool     `json:"confirm,omitempty"`
	Streaming bool     `json:"streaming,omitempty"`
	Flags     []Flag   `json:"flags,omitempty"`
}

// Flag is one locally typed argument.
type Flag struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Location    string `json:"in"`
	Required    bool   `json:"required"`
	Default     any    `json:"default,omitempty"`
	QueryName   string `json:"query_name,omitempty"`
	HeaderName  string `json:"header_name,omitempty"`
	Description string `json:"desc,omitempty"`
}

// Cached is the on-disk cache envelope.
type Cached struct {
	HTTPETag string    `json:"http_etag"`
	Fetched  time.Time `json:"fetched_at"`
	Server   string    `json:"server"`
	Document Document  `json:"manifest"`
}

var safePart = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Store isolates manifests by target, injected identity, and effective invoker.
type Store struct {
	Root     string
	Region   string
	Server   string
	Token    string
	Identity string
	Invoker  string
}

// Path returns the cache filename without exposing the token.
func (s Store) Path() string {
	region := safePart.ReplaceAllString(s.Region, "_")
	if region == "" {
		region = "unknown"
	}
	serverHash := shortHash(s.Server)
	identity := s.Identity
	if identity == "" {
		identity = s.Token
	}
	identityHash := shortHash(identity)
	invoker := safePart.ReplaceAllString(s.Invoker, "_")
	if invoker == "" {
		invoker = "human"
	}
	return filepath.Join(s.Root, region, serverHash, identityHash, invoker, "manifest.json")
}

// Remove deletes this cache variant.
func (s Store) Remove() error {
	err := os.RemoveAll(filepath.Dir(s.Path()))
	if err != nil {
		return fmt.Errorf("remove manifest cache: %w", err)
	}
	return nil
}

// Load reads one cache variant.
func (s Store) Load() (Cached, error) {
	data, err := os.ReadFile(s.Path())
	if err != nil {
		return Cached{}, err
	}
	var cached Cached
	if err := json.Unmarshal(data, &cached); err != nil {
		return Cached{}, fmt.Errorf("decode manifest cache: %w", err)
	}
	if cached.Server != s.Server {
		return Cached{}, errors.New("manifest cache server mismatch")
	}
	return cached, nil
}

// Save atomically persists one cache variant with mode 0600.
func (s Store) Save(cached Cached) error {
	path := s.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create manifest cache directory: %w", err)
	}
	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest cache: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.json")
	if err != nil {
		return fmt.Errorf("create temporary manifest cache: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect manifest cache: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write manifest cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync manifest cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close manifest cache: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace manifest cache: %w", err)
	}
	return nil
}

// Parse validates the minimum C0 contract.
func Parse(data []byte) (Document, error) {
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Document{}, errors.New("manifest must contain one JSON document")
	}
	if !namePattern.MatchString(document.CLI.Name) {
		return Document{}, errors.New("manifest has invalid cli.name")
	}
	domains := make(map[string]struct{})
	for _, domain := range document.Domains {
		if !namePattern.MatchString(domain.Name) {
			return Document{}, fmt.Errorf("manifest contains invalid domain %q", domain.Name)
		}
		if _, exists := domains[domain.Name]; exists {
			return Document{}, fmt.Errorf("manifest contains duplicate domain %q", domain.Name)
		}
		domains[domain.Name] = struct{}{}
		commands := make(map[string]struct{})
		for _, command := range domain.Commands {
			if len(command.Path) == 0 {
				return Document{}, fmt.Errorf("domain %q contains an empty command path", domain.Name)
			}
			for _, part := range command.Path {
				if !namePattern.MatchString(part) {
					return Document{}, fmt.Errorf("domain %q contains invalid command path part %q", domain.Name, part)
				}
			}
			key := strings.Join(command.Path, ".")
			if _, exists := commands[key]; exists {
				return Document{}, fmt.Errorf("domain %q contains duplicate command %q", domain.Name, key)
			}
			commands[key] = struct{}{}
			switch command.Risk {
			case "read", "write", "destroy":
			default:
				return Document{}, fmt.Errorf("command %s.%s has invalid risk %q", domain.Name, key, command.Risk)
			}
			flags := make(map[string]struct{})
			for _, flag := range command.Flags {
				if !namePattern.MatchString(flag.Name) {
					return Document{}, fmt.Errorf("command %s.%s has invalid flag %q", domain.Name, key, flag.Name)
				}
				if _, exists := flags[flag.Name]; exists {
					return Document{}, fmt.Errorf("command %s.%s has duplicate flag %q", domain.Name, key, flag.Name)
				}
				flags[flag.Name] = struct{}{}
				if err := validateFlagDefault(flag); err != nil {
					return Document{}, fmt.Errorf("command %s.%s flag %q: %w", domain.Name, key, flag.Name, err)
				}
			}
		}
	}
	return document, nil
}

func validateFlagDefault(flag Flag) error {
	switch flag.Type {
	case "string":
		if flag.Default != nil {
			if _, ok := flag.Default.(string); !ok {
				return errors.New("default is not a string")
			}
		}
	case "int":
		if flag.Default != nil {
			number, ok := flag.Default.(json.Number)
			if !ok {
				return errors.New("default is not an integer")
			}
			if _, err := strconv.Atoi(number.String()); err != nil {
				return errors.New("default is outside the integer range")
			}
		}
	case "bool":
		if flag.Default != nil {
			if _, ok := flag.Default.(bool); !ok {
				return errors.New("default is not a boolean")
			}
		}
	case "stringArray":
		if flag.Default != nil {
			items, ok := flag.Default.([]any)
			if !ok {
				return errors.New("default is not a string array")
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return errors.New("default is not a string array")
				}
			}
		}
	default:
		return fmt.Errorf("unsupported type %q", flag.Type)
	}
	return nil
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}
