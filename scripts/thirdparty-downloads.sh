#!/usr/bin/env bash
set -euo pipefail

readonly OSQUERY_VERSION="5.24.1"
readonly UPX_VERSION="5.2.1"
readonly DOSAI_VERSION="5.0.0"
THIRDPARTY_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly THIRDPARTY_SCRIPTS_DIR

print_usage() {
  cat <<'EOF'
Usage:
  thirdparty-downloads.sh download <asset-key> <output-path>
  thirdparty-downloads.sh install-osquery <platform> <destination-path>
  thirdparty-downloads.sh install-dosai <platform> <destination-path>
  thirdparty-downloads.sh install-upx <platform> <destination-path>
  thirdparty-downloads.sh install-zig <platform> <destination-dir> [version|latest]

Supported platforms:
  osquery: linux-amd64 linux-arm64 darwin-arm64 windows-amd64 windows-arm64
  dosai:   linux-amd64 linux-arm linux-arm64 linuxmusl-amd64 linuxmusl-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
  upx:     linux-amd64 linux-arm64
  zig:     linux-amd64 linux-arm64
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
      asset_sha256="31435ee69c43449eba612d0f3df3f2bccfe59805ab9a14fadc550bdc34814f2e"
      ;;
    osquery-linux-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.linux_aarch64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="121246c1c0f798dde5218d308f56e112d44f2b81fb28d215ebc5ed932a8c9bed"
      ;;
    osquery-darwin-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.macos_arm64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="318c722ac8a968e8bbdce2c325542e61a8bb1448dbaa374e4fe2f4048d357b3d"
      ;;
    osquery-windows-amd64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_x86_64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="a71d6d3f57b9fb051988c341fd5186c548fcf83bc94f73cc2cc0a83d702391e9"
      ;;
    osquery-windows-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_arm64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="a14a5d605298eb1eee90c9df59da341114d8b1b2014b3cfe557fa66940a83c6f"
      ;;
    dosai-linux-amd64)
      asset_filename="Dosai-linux-amd64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="c8e4d9e9d36dd3af99541a6a6fefe0c038d1298c6d7356ab61be5a89746fdd64"
      ;;
    dosai-linux-arm)
      asset_filename="Dosai-linux-arm"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="be215cb6241e4a0adc6173d0632fdc0b465b98c9c7b469a15a788244e1c32218"
      ;;
    dosai-linux-arm64)
      asset_filename="Dosai-linux-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="490fe83c3c1fe27093ebefc0aab9c7c61e24e337a020d7b38303acdfb41a5558"
      ;;
    dosai-linuxmusl-amd64)
      asset_filename="Dosai-linux-musl-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="8af8469513c968a60f38374ec1216d777b61baf622371e8d77827d1102787b60"
      ;;
    dosai-linuxmusl-arm64)
      asset_filename="Dosai-linux-musl-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="6c308088e5f0a02adb1bf275746e93ffd5f6f97745e6071e03ab06ade3f02ff8"
      ;;
    dosai-darwin-amd64)
      asset_filename="Dosai-osx-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="ea17658372e6d5897959793bad845d9549f3575f0f7231e5a847c38a7ca198dd"
      ;;
    dosai-darwin-arm64)
      asset_filename="Dosai-osx-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="98987024f37fd5e21ce7fe70c8441be3dd56eaf9fe7b1df31ad822387e4db548"
      ;;
    dosai-windows-amd64)
      asset_filename="Dosai.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="874f1be9ff820bcdbb95170293e775dd008d40921aed43df932f64b733f596a9"
      ;;
    dosai-windows-arm64)
      asset_filename="Dosai-windows-arm64.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="051bed7838c4f54c704909bd8eb51efba89d2bc712c58f213052bd72f820613b"
      ;;
    upx-linux-amd64)
      asset_filename="upx-${UPX_VERSION}-amd64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657"
      ;;
    upx-linux-arm64)
      asset_filename="upx-${UPX_VERSION}-arm64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="a72d112c5970a904a31da0b9c84f919bc16b9a311787c12245508544a78c7d36"
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
      # The upstream app is universal, and its x86_64 half never runs from an
      # arm64-only package. Each half carries its own signature, so the thinned
      # bundle still verifies.
      node "$THIRDPARTY_SCRIPTS_DIR/thin-macho.js" arm64 "$destination_path/Contents/MacOS/osqueryd"
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

fetch_zig_index() {
  local output_path="$1"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 \
    --silent --show-error "https://ziglang.org/download/index.json" -o "$output_path"
}

resolve_zig_download() {
  local index_path="$1"
  local platform="$2"
  local requested_version="${3:-latest}"
  local zig_platform=""
  case "$platform" in
    linux-amd64)
      zig_platform="x86_64-linux"
      ;;
    linux-arm64)
      zig_platform="aarch64-linux"
      ;;
    *)
      echo "Unsupported zig platform: $platform" >&2
      exit 1
      ;;
  esac

  local resolved_json
  resolved_json="$(node - "$index_path" "$zig_platform" "$requested_version" <<'EOF'
const fs = require('fs');

const [, , indexPath, platform, requestedVersion] = process.argv;
const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
const stableVersions = Object.keys(index)
  .filter((key) => /^\d+\.\d+\.\d+$/.test(key))
  .sort((left, right) => {
    const leftParts = left.split('.').map(Number);
    const rightParts = right.split('.').map(Number);
    for (let i = 0; i < Math.max(leftParts.length, rightParts.length); i += 1) {
      const diff = (rightParts[i] || 0) - (leftParts[i] || 0);
      if (diff !== 0) {
        return diff;
      }
    }
    return 0;
  });

if (stableVersions.length === 0) {
  throw new Error('No stable Zig versions found in ziglang download index');
}

const resolvedVersion =
  requestedVersion && requestedVersion !== 'latest'
    ? requestedVersion
    : stableVersions[0];
const release = index[resolvedVersion];
if (!release) {
  throw new Error(`Requested Zig version ${resolvedVersion} not found in ziglang download index`);
}
const artifact = release[platform];
if (!artifact || !artifact.tarball || !artifact.shasum) {
  throw new Error(`No Zig artifact metadata found for ${platform} in release ${resolvedVersion}`);
}

process.stdout.write(
  JSON.stringify({
    version: resolvedVersion,
    tarball: artifact.tarball,
    shasum: artifact.shasum,
    filename: artifact.tarball.split('/').pop(),
  }),
);
EOF
)"

  asset_filename="$(node -e 'const value=JSON.parse(process.argv[1]); process.stdout.write(value.filename);' "$resolved_json")"
  asset_url="$(node -e 'const value=JSON.parse(process.argv[1]); process.stdout.write(value.tarball);' "$resolved_json")"
  asset_sha256="$(node -e 'const value=JSON.parse(process.argv[1]); process.stdout.write(value.shasum);' "$resolved_json")"
}

install_zig() {
  local platform="$1"
  local destination_dir="$2"
  local requested_version="${3:-latest}"
  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/zig-${platform}.XXXXXX")"
  trap 'rm -rf "$tmpdir"' RETURN

  fetch_zig_index "$tmpdir/index.json"
  resolve_zig_download "$tmpdir/index.json" "$platform" "$requested_version"

  local archive_path="$tmpdir/$asset_filename"
  mkdir -p "$(dirname "$destination_dir")"
  echo "Downloading $asset_filename" >&2
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 \
    --silent --show-error "$asset_url" -o "$archive_path"
  verify_sha256 "$archive_path" "$asset_sha256"

  tar -xf "$archive_path" -C "$tmpdir"
  local extracted_dir
  extracted_dir="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d -name 'zig-*' | head -n 1)"
  if [[ -z "$extracted_dir" || ! -x "$extracted_dir/zig" ]]; then
    echo "Unable to find extracted Zig distribution in $tmpdir" >&2
    exit 1
  fi

  rm -rf "$destination_dir"
  mkdir -p "$destination_dir"
  cp -R "$extracted_dir"/. "$destination_dir"/
  chmod 0755 "$destination_dir/zig"

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
    install-zig)
      [[ $# -ge 2 && $# -le 3 ]] || { print_usage >&2; exit 1; }
      install_zig "$1" "$2" "${3:-latest}"
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
