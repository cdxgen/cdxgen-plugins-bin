#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$script_dir/thirdparty-downloads.sh"

resolve_asset dosai-linux-amd64
[[ "$asset_filename" == "Dosai-linux-amd64" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai-linux-amd64" ]]
[[ "$asset_sha256" == "04ea140d2ebac353458d3f67f5874ca95442b43600b4d9e0aeafa6b051715d41" ]]

resolve_asset dosai-windows-amd64
[[ "$asset_filename" == "Dosai.exe" ]]
[[ "$asset_url" == "https://github.com/owasp-dep-scan/dosai/releases/download/v${DOSAI_VERSION}/Dosai.exe" ]]
[[ "$asset_sha256" == "4a7ae864f37e77088981eb6c1967f067612d4c5191e204eeb871225a9cd1e103" ]]

echo "thirdparty-downloads helper test passed"
