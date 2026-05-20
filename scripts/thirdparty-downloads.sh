#!/usr/bin/env bash
set -euo pipefail

readonly OSQUERY_VERSION="5.23.0"
readonly UPX_VERSION="5.1.1"
readonly DOSAI_VERSION="3.0.3"

print_usage() {
  cat <<'EOF'
Usage:
  thirdparty-downloads.sh download <asset-key> <output-path>
  thirdparty-downloads.sh install-osquery <platform> <destination-path>
  thirdparty-downloads.sh install-dosai <platform> <destination-path>
  thirdparty-downloads.sh install-upx <platform> <destination-path>

Supported platforms:
  osquery: linux-amd64 linux-arm64 darwin-arm64 windows-amd64 windows-arm64
  dosai:   linux-amd64 linux-arm linux-arm64 linuxmusl-amd64 linuxmusl-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
  upx:     linux-amd64 linux-arm64
EOF
}

sha256_file() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file_path" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$file_path" | awk '{print $1}'
}

verify_sha256() {
  local file_path="$1"
  local expected_sha256="$2"
  local actual_sha256
  actual_sha256="$(sha256_file "$file_path")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    rm -f "$file_path"
    echo "SHA-256 mismatch for $file_path" >&2
    echo "Expected: $expected_sha256" >&2
    echo "Actual:   $actual_sha256" >&2
    exit 1
  fi
}

resolve_asset() {
  local asset_key="$1"
  case "$asset_key" in
    osquery-linux-amd64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.linux_x86_64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="0045739a68475760f7bc26ca493afda71cc02a8e4d29984717742d3e4c099296"
      ;;
    osquery-linux-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.linux_aarch64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="d9d4e5f6eeabda4949ae0ba6a8db424c789ec60ffef99269f479ff4b73f46e33"
      ;;
    osquery-darwin-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.macos_arm64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="968ef172e900e05bf8365974293c94dbbb0351d2fcc4c54404629036e3336cc6"
      ;;
    osquery-windows-amd64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_x86_64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="5ddb8e1c23fd870838ef4ff47c0d2e5a080f22a6944fc4870d726e7b20e962a4"
      ;;
    osquery-windows-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_arm64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="92a820a39c12f7516040b62dc8e8546469c821f505eed0b7ff1eb7e43cc4b018"
      ;;
    dosai-linux-amd64)
      asset_filename="Dosai-linux-amd64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="a905af4a5fd6b19366026899dc6e4b7ebfb7f93eb07cbac4c9be03f66926cbf8"
      ;;
    dosai-linux-arm)
      asset_filename="Dosai-linux-arm"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="5e8fe70ef25628be4c3cf5aa0de89c63a194f569036fa8a6cdec9f52dff38195"
      ;;
    dosai-linux-arm64)
      asset_filename="Dosai-linux-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="5269a6218bfd23b43c6bcd18f47efe90c5e2e7a97f20664e0d5f04fe7b331460"
      ;;
    dosai-linuxmusl-amd64)
      asset_filename="Dosai-linux-musl-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="f907e66a5de695c604436c98448c121a3e74faa3c2629851d554e5df1a99b894"
      ;;
    dosai-linuxmusl-arm64)
      asset_filename="Dosai-linux-musl-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="a92f899c6c421957bf4fd2c57265a4ca866b9240991609ff7960bb67efab96b1"
      ;;
    dosai-darwin-amd64)
      asset_filename="Dosai-osx-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="fffb132b313d99e40efdf3f571fbe445c9640195bb550f48b7e09887e987e11e"
      ;;
    dosai-darwin-arm64)
      asset_filename="Dosai-osx-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="f6c4a9f6c87ea039a9260d38308932827d6ca3e03ed6bbbd77aa740d23b20a70"
      ;;
    dosai-windows-amd64)
      asset_filename="Dosai.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="cce6298062aff7cf31f283742f07a32196bd3d1289f790a3ff6204988d5ee6f7"
      ;;
    dosai-windows-arm64)
      asset_filename="Dosai-windows-arm64.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="12662ea1fb127c9ce16a82fd1ef115274010b1668c35816e75cf5919a5129261"
      ;;
    upx-linux-amd64)
      asset_filename="upx-${UPX_VERSION}-amd64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="1ff660454227861e00772f743f66b900072116b9dc24f6ee28b97cce88a7828a"
      ;;
    upx-linux-arm64)
      asset_filename="upx-${UPX_VERSION}-arm64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="a307c2c821eeab47607ba5c232408b22ab884cca13884682508b98f7308b8443"
      ;;
    *)
      echo "Unsupported asset key: $asset_key" >&2
      exit 1
      ;;
  esac
}

download_asset() {
  local asset_key="$1"
  local output_path="$2"
  resolve_asset "$asset_key"
  mkdir -p "$(dirname "$output_path")"
  echo "Downloading ${asset_filename}" >&2
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 --silent --show-error "$asset_url" -o "$output_path"
  verify_sha256 "$output_path" "$asset_sha256"
}

copy_tree() {
  local source_path="$1"
  local destination_path="$2"
  rm -rf "$destination_path"
  mkdir -p "$(dirname "$destination_path")"
  cp -R "$source_path" "$destination_path"
}

install_osquery() {
  local platform="$1"
  local destination_path="$2"
  local asset_key="osquery-${platform}"
  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/osquery-${platform}.XXXXXX")"
  trap 'rm -rf "$tmpdir"' RETURN
  resolve_asset "$asset_key"
  local archive_path="$tmpdir/$asset_filename"
  download_asset "$asset_key" "$archive_path"
  case "$platform" in
    linux-amd64|linux-arm64)
      tar -xf "$archive_path" -C "$tmpdir"
      mkdir -p "$(dirname "$destination_path")"
      install -m 0755 "$tmpdir/opt/osquery/bin/osqueryd" "$destination_path"
      ;;
    darwin-arm64)
      tar -xf "$archive_path" -C "$tmpdir"
      copy_tree "$tmpdir/opt/osquery/lib/osquery.app" "$destination_path"
      ;;
    windows-amd64)
      unzip -q "$archive_path" -d "$tmpdir"
      mkdir -p "$(dirname "$destination_path")"
      install -m 0755 "$tmpdir/osquery-${OSQUERY_VERSION}.windows_x86_64/Program Files/osquery/osqueryi.exe" "$destination_path"
      ;;
    windows-arm64)
      unzip -q "$archive_path" -d "$tmpdir"
      mkdir -p "$(dirname "$destination_path")"
      install -m 0755 "$tmpdir/osquery-${OSQUERY_VERSION}.windows_arm64/Program Files/osquery/osqueryi.exe" "$destination_path"
      ;;
    *)
      echo "Unsupported osquery platform: $platform" >&2
      exit 1
      ;;
  esac
  trap - RETURN
  rm -rf "$tmpdir"
}

install_dosai() {
  local platform="$1"
  local destination_path="$2"
  local asset_key="dosai-${platform}"
  resolve_asset "$asset_key"
  mkdir -p "$(dirname "$destination_path")"
  download_asset "$asset_key" "$destination_path"
  chmod 0755 "$destination_path"
}

install_upx() {
  local platform="$1"
  local destination_path="$2"
  local asset_key="upx-${platform}"
  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/upx-${platform}.XXXXXX")"
  trap 'rm -rf "$tmpdir"' RETURN
  resolve_asset "$asset_key"
  local archive_path="$tmpdir/$asset_filename"
  download_asset "$asset_key" "$archive_path"
  tar -xf "$archive_path" -C "$tmpdir"
  mkdir -p "$(dirname "$destination_path")"
  case "$platform" in
    linux-amd64)
      install -m 0755 "$tmpdir/upx-${UPX_VERSION}-amd64_linux/upx" "$destination_path"
      ;;
    linux-arm64)
      install -m 0755 "$tmpdir/upx-${UPX_VERSION}-arm64_linux/upx" "$destination_path"
      ;;
    *)
      echo "Unsupported upx platform: $platform" >&2
      exit 1
      ;;
  esac
  trap - RETURN
  rm -rf "$tmpdir"
}

main() {
  if [[ $# -lt 1 ]]; then
    print_usage >&2
    exit 1
  fi

  local command="$1"
  shift

  case "$command" in
    download)
      [[ $# -eq 2 ]] || { print_usage >&2; exit 1; }
      download_asset "$1" "$2"
      ;;
    install-osquery)
      [[ $# -eq 2 ]] || { print_usage >&2; exit 1; }
      install_osquery "$1" "$2"
      ;;
    install-dosai)
      [[ $# -eq 2 ]] || { print_usage >&2; exit 1; }
      install_dosai "$1" "$2"
      ;;
    install-upx)
      [[ $# -eq 2 ]] || { print_usage >&2; exit 1; }
      install_upx "$1" "$2"
      ;;
    *)
      print_usage >&2
      exit 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
