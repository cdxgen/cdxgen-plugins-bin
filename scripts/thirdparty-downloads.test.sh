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
[[ "$asset_sha256" == "8963ea7bdb61fed81697ed2a85e6f567d111a2e36f767b8c213f3583196b249d" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "34fbbe401a6d62d127516ff1c1e145923a494698e788c0f0c2088e22a391aabc" ]]

echo "thirdparty-downloads helper test passed"
