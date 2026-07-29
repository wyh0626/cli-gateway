// Package config loads CLI regions and resolves the active cli-gateway origin.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wyh0626/cli-gateway/client/internal/branding"

	"gopkg.in/yaml.v3"
)

var regionNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

// Region is one named cli-gateway deployment.
type Region struct {
	Server      string `yaml:"server"`
	DisplayName string `yaml:"display_name,omitempty"`
	CAFile      string `yaml:"ca_file,omitempty"`
}

// File is the persisted CLI configuration.
type File struct {
	CurrentRegion string            `yaml:"current_region,omitempty"`
	Regions       map[string]Region `yaml:"regions,omitempty"`
}

// Selection is the resolved request target.
type Selection struct {
	Name   string
	Region Region
}

// Overrides contains explicit command-line and environment choices.
type Overrides struct {
	Region string
	Server string
}

// Paths contains CLI-owned filesystem paths.
type Paths struct {
	ConfigDir string
	CacheDir  string
}

// DefaultPaths resolves brand-isolated paths without creating them.
func DefaultPaths(brand branding.Config, environ map[string]string) (Paths, error) {
	configDir := strings.TrimSpace(environ[brand.Env("CONFIG_DIR")])
	if configDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve config directory: %w", err)
		}
		configDir = filepath.Join(base, brand.ConfigDirName)
	}
	cacheDir := strings.TrimSpace(environ[brand.Env("CACHE_DIR")])
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve cache directory: %w", err)
		}
		cacheDir = filepath.Join(base, brand.CacheDirName)
	}
	return Paths{ConfigDir: configDir, CacheDir: cacheDir}, nil
}

// Load reads config.yaml. A missing file is an empty configuration.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{Regions: make(map[string]Region)}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("read config: %w", err)
	}
	var cfg File
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return File{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Regions == nil {
		cfg.Regions = make(map[string]Region)
	}
	for name, region := range cfg.Regions {
		if err := ValidateRegion(name, region); err != nil {
			return File{}, err
		}
	}
	if cfg.CurrentRegion != "" {
		if _, ok := cfg.Regions[cfg.CurrentRegion]; !ok {
			return File{}, fmt.Errorf("current region %q is not configured", cfg.CurrentRegion)
		}
	}
	return cfg, nil
}

// Save writes config atomically with credentials-safe permissions.
func Save(path string, cfg File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// Resolve applies flag, environment, current-region, and single-region precedence.
func Resolve(cfg File, explicit Overrides, environ map[string]string, brand branding.Config) (Selection, error) {
	regionName := strings.TrimSpace(explicit.Region)
	if regionName == "" {
		regionName = strings.TrimSpace(environ[brand.Env("REGION")])
	}
	if regionName == "" {
		regionName = cfg.CurrentRegion
	}
	if regionName == "" && len(cfg.Regions) == 1 {
		for name := range cfg.Regions {
			regionName = name
		}
	}

	server := strings.TrimSpace(explicit.Server)
	if server == "" {
		server = strings.TrimSpace(environ[brand.Env("SERVER")])
	}
	if regionName == "" && server != "" {
		regionName = "local"
	}
	if regionName == "" {
		return Selection{}, errors.New("no region selected; use --region or configure a current region")
	}
	if !regionNamePattern.MatchString(regionName) {
		return Selection{}, fmt.Errorf("invalid region name %q", regionName)
	}
	region, exists := cfg.Regions[regionName]
	if !exists && server == "" {
		return Selection{}, fmt.Errorf("region %q is not configured", regionName)
	}
	if server != "" {
		region.Server = server
	}
	normalized, err := ValidateOrigin(region.Server)
	if err != nil {
		return Selection{}, fmt.Errorf("region %q: %w", regionName, err)
	}
	region.Server = normalized
	return Selection{Name: regionName, Region: region}, nil
}

// ValidateRegion validates a persisted region.
func ValidateRegion(name string, region Region) error {
	if !regionNamePattern.MatchString(name) {
		return fmt.Errorf("invalid region name %q", name)
	}
	if _, err := ValidateOrigin(region.Server); err != nil {
		return fmt.Errorf("region %q: %w", name, err)
	}
	return nil
}

// ValidateOrigin requires a pure HTTPS origin, except loopback HTTP for development.
func ValidateOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid server origin: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("server must be an absolute origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("server must not contain userinfo, path, query, or fragment")
	}
	host := parsed.Hostname()
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return "", errors.New("non-loopback server must use https")
		}
	default:
		return "", errors.New("server scheme must be https")
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SortedRegionNames provides deterministic config output.
func SortedRegionNames(cfg File) []string {
	names := make([]string, 0, len(cfg.Regions))
	for name := range cfg.Regions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ScanBootstrap extracts choices needed before Cobra builds dynamic commands.
func ScanBootstrap(args []string) Overrides {
	var result Overrides
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--region" && index+1 < len(args):
			index++
			result.Region = args[index]
		case strings.HasPrefix(arg, "--region="):
			result.Region = strings.TrimPrefix(arg, "--region=")
		case arg == "--server" && index+1 < len(args):
			index++
			result.Server = args[index]
		case strings.HasPrefix(arg, "--server="):
			result.Server = strings.TrimPrefix(arg, "--server=")
		}
	}
	return result
}
