#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/stage-built-plugins.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

source_dir="$tmpdir/source/trivy"
destination_dir="$tmpdir/destination/trivy"
mkdir -p "$source_dir" "$destination_dir"

printf 'binary-content' > "$source_dir/-dangerous-linux-amd64"
printf 'sbom-content' > "$source_dir/sbom-trivy.cdx.json"
printf 'ignore-me' > "$source_dir/not-for-this-platform"

bash "$helper_script" "$source_dir" "$destination_dir" "linux-amd64"

[[ -f "$destination_dir/-dangerous-linux-amd64" ]]
[[ -f "$destination_dir/sbom-trivy.cdx.json" ]]
[[ ! -f "$destination_dir/not-for-this-platform" ]]
cmp "$source_dir/-dangerous-linux-amd64" "$destination_dir/-dangerous-linux-amd64"
cmp "$source_dir/sbom-trivy.cdx.json" "$destination_dir/sbom-trivy.cdx.json"

hash_only_source="$tmpdir/source/hash-only"
hash_only_dest="$tmpdir/destination/hash-only"
mkdir -p "$hash_only_source" "$hash_only_dest"
printf 'hash-sidecar' > "$hash_only_source/trivy-linux-amd64.sha256"
warning_output="$(bash "$helper_script" "$hash_only_source" "$hash_only_dest" "linux-amd64" 2>&1 >/dev/null)"
[[ "$warning_output" == *"Warning: No files found for hash-only"* ]]

echo "stage-built-plugins helper test passed"
