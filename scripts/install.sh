#!/bin/sh
set -eu

repository="${CG_REPOSITORY:-wyh0626/cli-gateway}"
version="${CG_VERSION:-latest}"
install_dir="${CG_INSTALL_DIR:-/usr/local/bin}"

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
checksums="checksums-${os}-${arch}.txt"
if [ "$version" = latest ]; then
  download_base="https://github.com/${repository}/releases/latest/download"
else
  download_base="https://github.com/${repository}/releases/download/${version}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

echo "Downloading ${artifact} from ${repository}..."
curl --proto '=https' --tlsv1.2 -fsSLo "${tmp_dir}/cg" "${download_base}/${artifact}"
curl --proto '=https' --tlsv1.2 -fsSLo "${tmp_dir}/${checksums}" "${download_base}/${checksums}"

expected="$(awk -v name="$artifact" '$2 == name || $2 == "*" name { print $1; exit }' "${tmp_dir}/${checksums}")"
[ -n "$expected" ] || { echo "cg: checksum entry is missing" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp_dir}/cg" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp_dir}/cg" | awk '{print $1}')"
else
  echo "cg: sha256sum or shasum is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "cg: SHA-256 verification failed" >&2; exit 1; }

if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
  install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
elif command -v sudo >/dev/null 2>&1; then
  sudo mkdir -p "$install_dir"
  sudo install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
else
  install_dir="${HOME}/.local/bin"
  mkdir -p "$install_dir"
  install -m 0755 "${tmp_dir}/cg" "${install_dir}/cg"
  echo "Add ${install_dir} to PATH."
fi

echo "cg installed at ${install_dir}/cg"
"${install_dir}/cg" version
