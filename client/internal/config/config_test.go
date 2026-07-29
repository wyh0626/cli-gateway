package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wyh0626/cli-gateway/client/internal/branding"
)

func TestValidateOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		origin  string
		want    string
		wantErr bool
	}{
		{name: "https", origin: "https://tools.example.com/", want: "https://tools.example.com"},
		{name: "loopback IPv4", origin: "http://127.0.0.1:18082", want: "http://127.0.0.1:18082"},
		{name: "loopback IPv6", origin: "http://[::1]:18082", want: "http://[::1]:18082"},
		{name: "localhost", origin: "http://localhost:18082", want: "http://localhost:18082"},
		{name: "remote plaintext", origin: "http://tools.example.com", wantErr: true},
		{name: "path", origin: "https://tools.example.com/api", wantErr: true},
		{name: "query", origin: "https://tools.example.com?token=x", wantErr: true},
		{name: "userinfo", origin: "https://user@tools.example.com", wantErr: true},
		{name: "unsupported scheme", origin: "ftp://tools.example.com", wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateOrigin(test.origin)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ValidateOrigin(%q) succeeded, want error", test.origin)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateOrigin(%q): %v", test.origin, err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolvePrecedence(t *testing.T) {
	t.Parallel()
	cfg := File{
		CurrentRegion: "cn",
		Regions: map[string]Region{
			"cn": {Server: "https://cn.example.com"},
			"hk": {Server: "https://hk.example.com"},
		},
	}
	brand, err := branding.Resolve(branding.Config{Name: "cg"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		overrides Overrides
		env       map[string]string
		wantName  string
		wantURL   string
	}{
		{
			name: "current", wantName: "cn", wantURL: "https://cn.example.com",
		},
		{
			name: "environment", env: map[string]string{"CG_REGION": "hk"},
			wantName: "hk", wantURL: "https://hk.example.com",
		},
		{
			name: "flag", overrides: Overrides{Region: "cn"},
			env: map[string]string{"CG_REGION": "hk"}, wantName: "cn", wantURL: "https://cn.example.com",
		},
		{
			name: "server flag", overrides: Overrides{Region: "hk", Server: "https://override.example.com"},
			env: map[string]string{"CG_SERVER": "https://env.example.com"}, wantName: "hk", wantURL: "https://override.example.com",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Resolve(cfg, test.overrides, test.env, brand)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.Name != test.wantName || got.Region.Server != test.wantURL {
				t.Fatalf("got %#v, want name=%q URL=%q", got, test.wantName, test.wantURL)
			}
		})
	}
}

func TestWhiteLabelPathsAndEnvironment(t *testing.T) {
	t.Parallel()
	brand, err := branding.Resolve(branding.Config{Name: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := DefaultPaths(brand, map[string]string{
		"ACME_CONFIG_DIR": "/tmp/acme-config",
		"ACME_CACHE_DIR":  "/tmp/acme-cache",
	})
	if err != nil {
		t.Fatal(err)
	}
	if paths.ConfigDir != "/tmp/acme-config" || paths.CacheDir != "/tmp/acme-cache" {
		t.Fatalf("paths = %#v", paths)
	}
	selection, err := Resolve(File{}, Overrides{}, map[string]string{
		"ACME_SERVER": "https://gateway.example.com",
	}, brand)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Name != "local" || selection.Region.Server != "https://gateway.example.com" {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestSaveUsesPrivatePermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cg", "config.yaml")
	cfg := File{CurrentRegion: "local", Regions: map[string]Region{
		"local": {Server: "http://127.0.0.1:18082"},
	}}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.CurrentRegion != "local" {
		t.Fatalf("current region = %q", loaded.CurrentRegion)
	}
}

func TestScanBootstrap(t *testing.T) {
	t.Parallel()
	got := ScanBootstrap([]string{"demo", "get", "--server=https://override.example.com", "--region", "hk"})
	if got.Region != "hk" || got.Server != "https://override.example.com" {
		t.Fatalf("got %#v", got)
	}
}
