package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var downloadableCLIArtifacts = map[string]string{
	"cg-darwin-amd64":        "cg-darwin-amd64",
	"cg-darwin-amd64.sha256": "cg-darwin-amd64.sha256",
	"cg-darwin-arm64":        "cg-darwin-arm64",
	"cg-darwin-arm64.sha256": "cg-darwin-arm64.sha256",
	"cg-linux-amd64":         "cg-linux-amd64",
	"cg-linux-amd64.sha256":  "cg-linux-amd64.sha256",
	"cg-linux-arm64":         "cg-linux-arm64",
	"cg-linux-arm64.sha256":  "cg-linux-arm64.sha256",
}

func handleInstallScript(writer http.ResponseWriter, request *http.Request, services Dependencies) {
	publicURL := strings.TrimRight(strings.TrimSpace(services.PublicURL), "/")
	if publicURL == "" {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(writer, installScript(publicURL))
}

func handleCLIDownload(writer http.ResponseWriter, request *http.Request, services Dependencies) {
	artifact := request.PathValue("artifact")
	filename, allowed := downloadableCLIArtifacts[artifact]
	if !allowed || services.DownloadDir == "" {
		http.NotFound(writer, request)
		return
	}
	file, err := os.Open(filepath.Join(services.DownloadDir, filename))
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(writer, request)
		return
	}
	if strings.HasSuffix(filename, ".sha256") {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	}
	writer.Header().Set("Cache-Control", "public, max-age=3600, immutable")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(writer, request, filename, info.ModTime(), file)
}

func installScript(publicURL string) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu

gateway=%s
download_base="${gateway}/downloads"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "cg: unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "cg: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

artifact="cg-${os}-${arch}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

echo "Downloading ${artifact}..."
curl --proto '=https' --tlsv1.2 -fsSLo "${tmp_dir}/cg" "${download_base}/${artifact}"
curl --proto '=https' --tlsv1.2 -fsSLo "${tmp_dir}/cg.sha256" "${download_base}/${artifact}.sha256"

expected="$(awk '{print $1}' "${tmp_dir}/cg.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp_dir}/cg" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp_dir}/cg" | awk '{print $1}')"
else
  echo "cg: sha256sum or shasum is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "cg: SHA-256 verification failed" >&2; exit 1; }

install_dir="${CG_INSTALL_DIR:-/usr/local/bin}"
if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
  install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
elif command -v sudo >/dev/null 2>&1; then
  sudo mkdir -p "$install_dir"
  sudo install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
else
  install_dir="${HOME}/.local/bin"
  mkdir -p "$install_dir"
  install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
  echo "Add ${install_dir} to PATH before running cg."
fi

"${install_dir}/cg" config add-region prod "$gateway" --display-name "CG Production"
"${install_dir}/cg" config use-region prod

echo "cg installed at ${install_dir}/cg"
echo "Next: cg login"
`, shellSingleQuote(publicURL))
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
