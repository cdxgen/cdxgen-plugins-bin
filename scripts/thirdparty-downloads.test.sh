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
[[ "$asset_sha256" == "1d094e03ccb35e93d527cea406ed2d96a8a2efcfe090893ba5ecd76f23cb59e3" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "d98981dfe6d4bb5417ee6dcece4a7807a6ba9216cfad5574eca3dd21e269a88f" ]]

# Every pinned dosai platform resolves, and a hash that no longer matches
# the pinned release is caught before it ships: the assertions below each
# name the hash re-derived from the v${DOSAI_VERSION} release assets, so a
# future bump that forgets to re-derive one platform fails right here.
resolve_asset dosai-linux-arm
[[ "$asset_filename" == "Dosai-linux-arm" ]]
[[ "$asset_sha256" == "56536fc97ae348651620b862ffd4aef28393356b6db1ca7943e50220b9ad4bc0" ]]

resolve_asset dosai-linux-arm64
[[ "$asset_filename" == "Dosai-linux-arm64" ]]
[[ "$asset_sha256" == "5e9aab386a59c78c7888246ca67c9930e0a9914426c268ba50654500b0edc2d4" ]]

resolve_asset dosai-linuxmusl-amd64
[[ "$asset_filename" == "Dosai-linux-musl-x64" ]]
[[ "$asset_sha256" == "7e1b257876669bd7647d46a8276dfe6ff93ecbbe59933b286a701f46923afce6" ]]

resolve_asset dosai-linuxmusl-arm64
[[ "$asset_filename" == "Dosai-linux-musl-arm64" ]]
[[ "$asset_sha256" == "afb24c8da2841c4df269ec1eae4d2d48dfc4ebf51822b19f129e9ac7b27ca3ed" ]]

resolve_asset dosai-darwin-amd64
[[ "$asset_filename" == "Dosai-osx-x64" ]]
[[ "$asset_sha256" == "f41cadcf6e2430b54031edecb77498f6d059a32bf538f6f70701d88886ce300c" ]]

resolve_asset dosai-darwin-arm64
[[ "$asset_filename" == "Dosai-osx-arm64" ]]
[[ "$asset_sha256" == "2a899ba735d8886ce3815f3d44292cc1e25cc2274c47aa0519f3860c2ed2fc25" ]]

resolve_asset dosai-windows-arm64
[[ "$asset_filename" == "Dosai-windows-arm64.exe" ]]
[[ "$asset_sha256" == "062e58caebc66dc4424acdfe87859476654b154a8e3497921ae4e2ab80314285" ]]

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

# build.ps1 downloads the same releases for the Windows CI build. Its pins
# once fell behind these (dosai 4.0.0, upx 5.2.0), so that job tested an
# older dosai than the packages shipped.
ps1_value() {
  sed -n "s/^\\\$$1 = \"\\(.*\\)\"\$/\\1/p" "$script_dir/../build.ps1"
}
expect_ps1() {
  local actual
  actual="$(ps1_value "$1")"
  if [[ "$actual" != "$2" ]]; then
    echo "build.ps1 sets \$$1 to '$actual', expected '$2' as in thirdparty-downloads.sh" >&2
    exit 1
  fi
}
expect_ps1 upxVersion "$UPX_VERSION"
expect_ps1 osqueryVersion "$OSQUERY_VERSION"
expect_ps1 dosaiVersion "$DOSAI_VERSION"
resolve_asset osquery-windows-amd64
expect_ps1 osqueryArchiveSha256 "$asset_sha256"
resolve_asset dosai-windows-amd64
expect_ps1 dosaiArchiveSha256 "$asset_sha256"

echo "thirdparty-downloads helper test passed"
