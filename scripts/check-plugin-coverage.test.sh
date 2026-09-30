#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/check-plugin-coverage.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# A linux-amd64 package with every built plugin, one of them staged the way
# oras and the download steps write files: without an execute bit.
package_dir="$tmpdir/linux-amd64"
for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs; do
  mkdir -p "$package_dir/plugins/$plugin"
  printf 'binary' > "$package_dir/plugins/$plugin/$plugin-linux-amd64"
  printf 'hash' > "$package_dir/plugins/$plugin/$plugin-linux-amd64.sha256"
  printf '{}' > "$package_dir/plugins/$plugin/sbom-$plugin-postbuild.cdx.json"
  chmod +x "$package_dir/plugins/$plugin/$plugin-linux-amd64"
done
chmod 0644 "$package_dir/plugins/golem/golem-linux-amd64"
printf '# comment\n' > "$package_dir/plugins/.npmignore"

set +e
error_output="$(bash "$helper_script" "$package_dir" 2>&1 >/dev/null)"
error_status=$?
set -e
[[ "$error_status" -ne 0 ]]
[[ "$error_output" == *"Error: linux-amd64 ships plugins/golem/golem-linux-amd64 without an execute bit"* ]]
[[ "$error_output" != *"sbom-"* ]]
[[ "$error_output" != *".sha256"* ]]

chmod +x "$package_dir/plugins/golem/golem-linux-amd64"
bash "$helper_script" "$package_dir" >/dev/null 2>&1

# sourcekitten is macOS-only; a Linux package that ships it fails.
mkdir -p "$package_dir/plugins/sourcekitten"
printf 'binary' > "$package_dir/plugins/sourcekitten/sourcekitten"
chmod +x "$package_dir/plugins/sourcekitten/sourcekitten"
set +e
error_output="$(bash "$helper_script" "$package_dir" 2>&1 >/dev/null)"
error_status=$?
set -e
[[ "$error_status" -ne 0 ]]
[[ "$error_output" == *"Error: linux-amd64 ships sourcekitten, which is built for macOS only"* ]]
rm -rf "$package_dir/plugins/sourcekitten"
# An empty directory left by a clean step is not a shipped binary.
mkdir -p "$package_dir/plugins/sourcekitten"
bash "$helper_script" "$package_dir" >/dev/null 2>&1

# macOS packages keep sourcekitten.
darwin_dir="$tmpdir/darwin-arm64"
for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs sourcekitten; do
  mkdir -p "$darwin_dir/plugins/$plugin"
  printf 'binary' > "$darwin_dir/plugins/$plugin/$plugin-darwin-arm64"
  chmod +x "$darwin_dir/plugins/$plugin/$plugin-darwin-arm64"
done
bash "$helper_script" "$darwin_dir" >/dev/null 2>&1

# Windows does not use the bit.
windows_dir="$tmpdir/windows-amd64"
for plugin in trivy trustinspector golem rusi cdxui cdxrs; do
  mkdir -p "$windows_dir/plugins/$plugin"
  printf 'binary' > "$windows_dir/plugins/$plugin/$plugin-windows-amd64.exe"
  chmod 0644 "$windows_dir/plugins/$plugin/$plugin-windows-amd64.exe"
done
bash "$helper_script" "$windows_dir" >/dev/null 2>&1

echo "check-plugin-coverage test passed"
