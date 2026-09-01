#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$script_dir/thirdparty-downloads.sh"

asset_filename=""
asset_url=""
asset_sha256=""

resolve_asset dosai-linux-amd64
[[ "$asset_filename" == "Dosai-linux-amd64" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai-linux-amd64" ]]
[[ "$asset_sha256" == "304f9d41cc1585a774c057a89220318bb8c9dcef1f674bef6ee5dbf4002af68f" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "8d4ed9585068cf2df6975e75fa981c39ea35a597e6b79572137dfa0dab28d31d" ]]

zig_index_fixture="$(mktemp "${TMPDIR:-/tmp}/zig-index.XXXXXX.json")"
trap 'rm -f "$zig_index_fixture"' EXIT
cat > "$zig_index_fixture" <<'EOF'
{
  "master": {
	"x86_64-linux": {
	  "tarball": "https://ziglang.org/builds/zig-x86_64-linux-master.tar.xz",
	  "shasum": "master"
	}
  },
  "0.14.1": {
	"x86_64-linux": {
	  "tarball": "https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz",
	  "shasum": "1111111111111111111111111111111111111111111111111111111111111111"
	}
  },
  "0.15.0": {
	"x86_64-linux": {
	  "tarball": "https://ziglang.org/download/0.15.0/zig-x86_64-linux-0.15.0.tar.xz",
	  "shasum": "2222222222222222222222222222222222222222222222222222222222222222"
	},
	"aarch64-linux": {
	  "tarball": "https://ziglang.org/download/0.15.0/zig-aarch64-linux-0.15.0.tar.xz",
	  "shasum": "3333333333333333333333333333333333333333333333333333333333333333"
	}
  }
}
EOF

resolve_zig_download "$zig_index_fixture" linux-amd64 latest
[[ "$asset_filename" == "zig-x86_64-linux-0.15.0.tar.xz" ]]
[[ "$asset_url" == "https://ziglang.org/download/0.15.0/zig-x86_64-linux-0.15.0.tar.xz" ]]
[[ "$asset_sha256" == "2222222222222222222222222222222222222222222222222222222222222222" ]]

resolve_zig_download "$zig_index_fixture" linux-arm64 0.15.0
[[ "$asset_filename" == "zig-aarch64-linux-0.15.0.tar.xz" ]]
[[ "$asset_url" == "https://ziglang.org/download/0.15.0/zig-aarch64-linux-0.15.0.tar.xz" ]]
[[ "$asset_sha256" == "3333333333333333333333333333333333333333333333333333333333333333" ]]

echo "thirdparty-downloads helper test passed"
