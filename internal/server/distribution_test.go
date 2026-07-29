package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptUsesConfiguredPublicURL(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	response := httptest.NewRecorder()

	NewHandler(nil, Dependencies{PublicURL: "https://cli.example.com/"}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"gateway='https://cli.example.com'",
		"cg-${os}-${arch}",
		"SHA-256 verification failed",
		"config add-region prod",
		"Next: cg login",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("install script does not contain %q", expected)
		}
	}
	syntaxCheck := exec.Command("sh", "-n")
	syntaxCheck.Stdin = strings.NewReader(body)
	if output, err := syntaxCheck.CombinedOutput(); err != nil {
		t.Fatalf("install script syntax: %v: %s", err, output)
	}
}

func TestDownloadOnlyServesAllowlistedRegularFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cg-darwin-arm64"), []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(nil, Dependencies{DownloadDir: dir})

	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, httptest.NewRequest(http.MethodGet, "/downloads/cg-darwin-arm64", nil))
	if allowed.Code != http.StatusOK || allowed.Body.String() != "binary" {
		t.Fatalf("allowed response = %d %q", allowed.Code, allowed.Body.String())
	}

	for _, path := range []string{
		"/downloads/not-allowlisted",
		"/downloads/..%2Fmanifest.yaml",
		"/downloads/cg-linux-amd64",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
	}
}
