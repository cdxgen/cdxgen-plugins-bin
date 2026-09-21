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
[[ "$asset_sha256" == "466060fc222ce0050e853da9e4d5e602a82e5fdab4e6f27f6c7d3494145740fa" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "c804961ed46675a43718553bee5cbf1b74dbe90c318658b6df75f6aedc6aa36c" ]]

# Every pinned dosai platform resolves, and a hash that no longer matches
# the pinned release is caught before it ships: the assertions below each
# name the hash re-derived from the v${DOSAI_VERSION} release assets, so a
# future bump that forgets to re-derive one platform fails right here.
resolve_asset dosai-linux-arm
[[ "$asset_filename" == "Dosai-linux-arm" ]]
[[ "$asset_sha256" == "d2e4aa7814301a6e9ccba5e77197f3b2def3f970f119d39a5020f08de10df5e5" ]]

resolve_asset dosai-linux-arm64
[[ "$asset_filename" == "Dosai-linux-arm64" ]]
[[ "$asset_sha256" == "a40f45b5400e96d431042be015d340e5293688c43c17518247fd3ed6a36d60be" ]]

resolve_asset dosai-linuxmusl-amd64
[[ "$asset_filename" == "Dosai-linux-musl-x64" ]]
[[ "$asset_sha256" == "8eaee321818822ee24f2efa9ee4e08bf57dad5554169788c50fa5ed3a9354ce6" ]]

resolve_asset dosai-linuxmusl-arm64
[[ "$asset_filename" == "Dosai-linux-musl-arm64" ]]
[[ "$asset_sha256" == "1220c14cefa61cd00b04c8d9a2370a059dea6947388f85a98d1cb92ed95616c5" ]]

resolve_asset dosai-darwin-amd64
[[ "$asset_filename" == "Dosai-osx-x64" ]]
[[ "$asset_sha256" == "aca98b6c4fb7a64adc8414e1a7dadefdcaf38ffaf7313d5a30f9e8983f4ce3b6" ]]

resolve_asset dosai-darwin-arm64
[[ "$asset_filename" == "Dosai-osx-arm64" ]]
[[ "$asset_sha256" == "74a218d259e2d2a9956f0fa569cef06d07f6a4c5c50ad13ebd6b03fad37dcf12" ]]

resolve_asset dosai-windows-arm64
[[ "$asset_filename" == "Dosai-windows-arm64.exe" ]]
[[ "$asset_sha256" == "29ef0541210a99e91571085bf258e7f7f113cba6268d0b79c7fb07e69a4961cd" ]]

resolve_asset upx-linux-amd64
[[ "$asset_filename" == "upx-${UPX_VERSION}-amd64_linux.tar.xz" ]]
[[ "$asset_url" == "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" ]]
[[ "$asset_sha256" == "402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657" ]]

resolve_asset upx-linux-arm64
[[ "$asset_filename" == "upx-${UPX_VERSION}-arm64_linux.tar.xz" ]]
[[ "$asset_sha256" == "a72d112c5970a904a31da0b9c84f919bc16b9a311787c12245508544a78c7d36" ]]

# verify_sha256 is the gate the download path rides on; prove it fails a
# wrong hash rather than trusting the assertions above to cover it. It runs
# in a subshell because it exits on mismatch — the exit is the behaviour
# under test, and it must not take the test script with it.
wrong_hash_fixture="$(mktemp "${TMPDIR:-/tmp}/wrong-hash.XXXXXX")"
echo "not the pinned asset" > "$wrong_hash_fixture"
if (verify_sha256 "$wrong_hash_fixture" "0000000000000000000000000000000000000000000000000000000000000000") 2>/dev/null; then
  echo "verify_sha256 accepted a wrong hash" >&2
  exit 1
fi
[[ ! -f "$wrong_hash_fixture" ]]

zig_index_fixture="$(mktemp "${TMPDIR:-/tmp}/zig-index.XXXXXX.json")"
trap 'rm -f "$zig_index_fixture" "$wrong_hash_fixture"' EXIT
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
