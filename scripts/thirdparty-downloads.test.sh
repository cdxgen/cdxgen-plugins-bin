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
[[ "$asset_sha256" == "a905af4a5fd6b19366026899dc6e4b7ebfb7f93eb07cbac4c9be03f66926cbf8" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "cce6298062aff7cf31f283742f07a32196bd3d1289f790a3ff6204988d5ee6f7" ]]

echo "thirdparty-downloads helper test passed"
