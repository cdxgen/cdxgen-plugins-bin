#!/usr/bin/env bash
set -euo pipefail

readonly OSQUERY_VERSION="5.23.1"
readonly UPX_VERSION="5.2.0"
readonly DOSAI_VERSION="4.0.0"

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
      asset_sha256="0f37a478a1dbda24b67c81551e32d734b392c5a2f5deb156bf1c41ca204cfa67"
      ;;
    osquery-linux-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.linux_aarch64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="9ae763820166f75f19970b5147b1930a308865a923ab127f4b8bbaea7b69962a"
      ;;
    osquery-darwin-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}_1.macos_arm64.tar.gz"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="5484f0b62e05a7b2fa9d6e43f038915ea2b7ce063d59bd671ede0cf8dd0552da"
      ;;
    osquery-windows-amd64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_x86_64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b"
      ;;
    osquery-windows-arm64)
      asset_filename="osquery-${OSQUERY_VERSION}.windows_arm64.zip"
      asset_url="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/${asset_filename}"
      asset_sha256="0913d05cc3fc92dd9253c945caacde10a776408f267cc1cc853a05de24dba900"
      ;;
    dosai-linux-amd64)
      asset_filename="Dosai-linux-amd64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="304f9d41cc1585a774c057a89220318bb8c9dcef1f674bef6ee5dbf4002af68f"
      ;;
    dosai-linux-arm)
      asset_filename="Dosai-linux-arm"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="cbb9f586071e2a604764e19e531e5bc9afda2077cabb21eb02b7a41cbfc13762"
      ;;
    dosai-linux-arm64)
      asset_filename="Dosai-linux-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="0437847f402e97ba9815412504bfab2bf5a6d3783f5a48fd41a59e8bf46147bf"
      ;;
    dosai-linuxmusl-amd64)
      asset_filename="Dosai-linux-musl-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="ec5df05fc29f5a51d14355bdc6e678b2d2ea370a1de984bb524d4100dc8772e3"
      ;;
    dosai-linuxmusl-arm64)
      asset_filename="Dosai-linux-musl-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="14ab375efb5ed053f9c8d0172bbe42c72e8684dcaf85ab58cde41594fa0352f3"
      ;;
    dosai-darwin-amd64)
      asset_filename="Dosai-osx-x64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="f2cb59de739321bfbe847d97a0b814c874f293e4d9d048cdac85e6cff19423e0"
      ;;
    dosai-darwin-arm64)
      asset_filename="Dosai-osx-arm64"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="8d1736f03316d4d52a197143d8ca70011173ae6266ddb0ad4bb487fd784d4cb6"
      ;;
    dosai-windows-amd64)
      asset_filename="Dosai.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="8d4ed9585068cf2df6975e75fa981c39ea35a597e6b79572137dfa0dab28d31d"
      ;;
    dosai-windows-arm64)
      asset_filename="Dosai-windows-arm64.exe"
      asset_url="https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/${asset_filename}"
      asset_sha256="3e5f4c3d4bae4e25953018944b1c17a24b4818ef68e84e95b6f55cc86e8df00c"
      ;;
    upx-linux-amd64)
      asset_filename="upx-${UPX_VERSION}-amd64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1"
      ;;
    upx-linux-arm64)
      asset_filename="upx-${UPX_VERSION}-arm64_linux.tar.xz"
      asset_url="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${asset_filename}"
      asset_sha256="55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c"
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
