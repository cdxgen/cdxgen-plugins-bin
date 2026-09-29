#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/check-plugin-coverage.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# A linux-amd64 package with every built plugin, plus sourcekitten staged the
# way oras pulls it: without an execute bit.
package_dir="$tmpdir/linux-amd64"
for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs; do
  mkdir -p "$package_dir/plugins/$plugin"
  printf 'binary' > "$package_dir/plugins/$plugin/$plugin-linux-amd64"
  printf 'hash' > "$package_dir/plugins/$plugin/$plugin-linux-amd64.sha256"
  printf '{}' > "$package_dir/plugins/$plugin/sbom-$plugin-postbuild.cdx.json"
  chmod +x "$package_dir/plugins/$plugin/$plugin-linux-amd64"
done
mkdir -p "$package_dir/plugins/sourcekitten"
printf 'binary' > "$package_dir/plugins/sourcekitten/sourcekitten"
chmod 0644 "$package_dir/plugins/sourcekitten/sourcekitten"
printf '# comment\n' > "$package_dir/plugins/.npmignore"

set +e
error_output="$(bash "$helper_script" "$package_dir" 2>&1 >/dev/null)"
error_status=$?
set -e
[[ "$error_status" -ne 0 ]]
[[ "$error_output" == *"Error: linux-amd64 ships plugins/sourcekitten/sourcekitten without an execute bit"* ]]
[[ "$error_output" != *"sbom-"* ]]
[[ "$error_output" != *".sha256"* ]]

chmod +x "$package_dir/plugins/sourcekitten/sourcekitten"
bash "$helper_script" "$package_dir" >/dev/null 2>&1

# Windows does not use the bit.
windows_dir="$tmpdir/windows-amd64"
for plugin in trivy trustinspector golem rusi cdxui cdxrs; do
  mkdir -p "$windows_dir/plugins/$plugin"
  printf 'binary' > "$windows_dir/plugins/$plugin/$plugin-windows-amd64.exe"
  chmod 0644 "$windows_dir/plugins/$plugin/$plugin-windows-amd64.exe"
done
bash "$helper_script" "$windows_dir" >/dev/null 2>&1

echo "check-plugin-coverage test passed"
