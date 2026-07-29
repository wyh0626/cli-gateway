// Package branding defines the build-time identity of a white-label CLI.
package branding

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	// BuildName is intentionally a variable so release builds can override it
	// with: -X cli-gateway/client/internal/branding.BuildName=acme
	BuildName = "cg"

	// The remaining values are optional build-time overrides. Empty values are
	// derived from BuildName, keeping the common white-label build to one flag.
	BuildDisplayName    = ""
	BuildEnvPrefix      = ""
	BuildConfigDirName  = ""
	BuildCacheDirName   = ""
	BuildKeyringService = ""
	BuildUserAgent      = ""
)

var (
	namePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	envPrefixPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
	userAgentPattern = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]{1,64}$`)
)

// Config contains every value that must be isolated between branded clients.
type Config struct {
	Name           string
	DisplayName    string
	EnvPrefix      string
	ConfigDirName  string
	CacheDirName   string
	KeyringService string
	UserAgent      string
}

// Resolve validates an explicit config or the values injected into this
// package at build time, then derives safe defaults from the CLI name.
func Resolve(explicit Config) (Config, error) {
	config := explicit
	if config.Name == "" {
		config = Config{
			Name:           BuildName,
			DisplayName:    BuildDisplayName,
			EnvPrefix:      BuildEnvPrefix,
			ConfigDirName:  BuildConfigDirName,
			CacheDirName:   BuildCacheDirName,
			KeyringService: BuildKeyringService,
			UserAgent:      BuildUserAgent,
		}
	}
	config.Name = strings.TrimSpace(config.Name)
	if !namePattern.MatchString(config.Name) {
		return Config{}, fmt.Errorf("CLI name %q must match %s", config.Name, namePattern)
	}
	if config.DisplayName == "" {
		config.DisplayName = strings.ToUpper(config.Name) + " CLI Gateway client"
	}
	if config.EnvPrefix == "" {
		config.EnvPrefix = strings.ToUpper(strings.ReplaceAll(config.Name, "-", "_"))
	}
	if config.ConfigDirName == "" {
		config.ConfigDirName = config.Name
	}
	if config.CacheDirName == "" {
		config.CacheDirName = config.Name
	}
	if config.KeyringService == "" {
		config.KeyringService = config.Name + "-cli-refresh-token"
	}
	if config.UserAgent == "" {
		config.UserAgent = config.Name + "-cli"
	}
	if err := validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Env returns one namespaced environment variable, such as ACME_TOKEN.
func (c Config) Env(suffix string) string {
	return c.EnvPrefix + "_" + suffix
}

func validate(config Config) error {
	if !envPrefixPattern.MatchString(config.EnvPrefix) {
		return fmt.Errorf("CLI environment prefix %q must match %s", config.EnvPrefix, envPrefixPattern)
	}
	if !namePattern.MatchString(config.ConfigDirName) {
		return fmt.Errorf("CLI config directory name %q must match %s", config.ConfigDirName, namePattern)
	}
	if !namePattern.MatchString(config.CacheDirName) {
		return fmt.Errorf("CLI cache directory name %q must match %s", config.CacheDirName, namePattern)
	}
	if !userAgentPattern.MatchString(config.UserAgent) {
		return fmt.Errorf("CLI user agent %q is not a valid HTTP product token", config.UserAgent)
	}
	if len(config.DisplayName) > 80 || containsControl(config.DisplayName) {
		return errors.New("CLI display name must be at most 80 characters and contain no control characters")
	}
	if len(config.KeyringService) > 128 || strings.TrimSpace(config.KeyringService) == "" || containsControl(config.KeyringService) {
		return errors.New("CLI keyring service must be 1-128 characters and contain no control characters")
	}
	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
