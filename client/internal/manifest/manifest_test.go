package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreSeparatesVariantsAndProtectsFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	base := Store{Root: root, Region: "cn", Server: "https://tools.example.com", Token: "token-a", Invoker: "human"}
	otherToken := base
	otherToken.Token = "token-b"
	otherInvoker := base
	otherInvoker.Invoker = "ai"
	if base.Path() == otherToken.Path() || base.Path() == otherInvoker.Path() {
		t.Fatalf("cache variants collided: %q %q %q", base.Path(), otherToken.Path(), otherInvoker.Path())
	}
	cached := Cached{
		HTTPETag: `"abc"`, Fetched: time.Now().UTC(), Server: base.Server,
		Document: Document{CLI: CLI{Name: "cg"}},
	}
	if err := base.Save(cached); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(base.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	loaded, err := base.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.HTTPETag != `"abc"` || loaded.Document.CLI.Name != "cg" {
		t.Fatalf("loaded = %#v", loaded)
	}
	if strings.Contains(base.Path(), "token-a") {
		t.Fatalf("cache path exposes token: %s", base.Path())
	}
	if !strings.HasPrefix(base.Path(), filepath.Clean(root)+string(os.PathSeparator)) {
		t.Fatalf("cache escaped root: %s", base.Path())
	}
}

func TestParseRejectsIncompleteManifest(t *testing.T) {
	t.Parallel()
	if _, err := Parse([]byte(`{"domains":[]}`)); err == nil {
		t.Fatal("Parse succeeded without cli.name")
	}
	if _, err := Parse([]byte(`{"cli":{"name":"cg"},"domains":[{"name":"demo","commands":[{"path":[]}]}]}`)); err == nil {
		t.Fatal("Parse succeeded with an empty command path")
	}
}
