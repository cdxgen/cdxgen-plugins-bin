#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/check-plugin-coverage.sh"
#shellcheck source=plugin-platform-support.sh
source "$script_dir/plugin-platform-support.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Writes an executable stand-in for <plugin> under the name cdxgen runs on
# <target>, with its sidecar and SBOM.
stage_binary() {
  local package_dir="$1" plugin="$2" target="$3" binary_name
  binary_name="$(plugin_binary_name "$plugin" "$target")"
  mkdir -p "$(dirname "$package_dir/plugins/$plugin/$binary_name")"
  printf 'binary' > "$package_dir/plugins/$plugin/$binary_name"
  printf 'hash' > "$package_dir/plugins/$plugin/$binary_name.sha256"
  printf '{}' > "$package_dir/plugins/$plugin/sbom-$plugin-postbuild.cdx.json"
  chmod +x "$package_dir/plugins/$plugin/$binary_name"
}

# The manifest comes from the real metadata generator, so these cases also
# hold generate-metadata.js to the names cdxgen runs.
generate_metadata() {
  node "$script_dir/generate-metadata.js" "$1/plugins" >/dev/null 2>&1
}

expect_failure() {
  local package_dir="$1" message="$2" error_output error_status
  set +e
  error_output="$(bash "$helper_script" "$package_dir" 2>&1 >/dev/null)"
  error_status=$?
  set -e
  [[ "$error_status" -ne 0 ]]
  [[ "$error_output" == *"$message"* ]]
}

# A linux-amd64 package with every built and downloaded plugin, one of them
# staged the way oras and the download steps write files: without an execute
# bit.
package_dir="$tmpdir/linux-amd64"
for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs dosai osquery; do
  stage_binary "$package_dir" "$plugin" linux-amd64
done
chmod 0644 "$package_dir/plugins/golem/golem-linux-amd64"
printf '# comment\n' > "$package_dir/plugins/.npmignore"
generate_metadata "$package_dir"

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
expect_failure "$package_dir" "Error: linux-amd64 ships sourcekitten, which is built for macOS only"
rm -rf "$package_dir/plugins/sourcekitten"
# An empty directory left by a clean step is not a shipped binary.
mkdir -p "$package_dir/plugins/sourcekitten"
bash "$helper_script" "$package_dir" >/dev/null 2>&1

# A built plugin under a name cdxgen does not run is missing.
mv "$package_dir/plugins/trivy/trivy-cdxgen-linux-amd64" "$package_dir/plugins/trivy/trivy-linux-amd64"
expect_failure "$package_dir" "Error: linux-amd64 is missing a trivy binary (cdxgen runs plugins/trivy/trivy-cdxgen-linux-amd64)"
mv "$package_dir/plugins/trivy/trivy-linux-amd64" "$package_dir/plugins/trivy/trivy-cdxgen-linux-amd64"

# A downloaded plugin that upstream publishes for the platform is required.
rm -rf "$package_dir/plugins/osquery"
expect_failure "$package_dir" "Error: linux-amd64 is missing a osquery binary (cdxgen runs plugins/osquery/osqueryi-linux-amd64)"
stage_binary "$package_dir" osquery linux-amd64

# A package without a manifest never ran generate-metadata.js.
rm "$package_dir/plugins/plugins-manifest.json"
expect_failure "$package_dir" "Error: linux-amd64 has no plugins/plugins-manifest.json"
generate_metadata "$package_dir"
bash "$helper_script" "$package_dir" >/dev/null 2>&1

# The musl packages shipped dosai as plugins/dosai/dosai, which cdxgen, asking
# for dosai-linuxmusl-<arch> on a musl host, never found.
for arch in amd64 arm64; do
  musl_dir="$tmpdir/linuxmusl-$arch"
  for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs; do
    if ! plugin_platform_exemption "$plugin" "linuxmusl-$arch" >/dev/null; then
      stage_binary "$musl_dir" "$plugin" "linuxmusl-$arch"
    fi
  done
  mkdir -p "$musl_dir/plugins/dosai"
  printf 'binary' > "$musl_dir/plugins/dosai/dosai"
  printf 'hash' > "$musl_dir/plugins/dosai/dosai.sha256"
  chmod +x "$musl_dir/plugins/dosai/dosai"
  generate_metadata "$musl_dir"
  expect_failure "$musl_dir" "Error: linuxmusl-$arch is missing a dosai binary (cdxgen runs plugins/dosai/dosai-linuxmusl-$arch)"
  expect_failure "$musl_dir" "Error: linuxmusl-$arch's manifest records dosai at plugins/dosai/dosai, not plugins/dosai/dosai-linuxmusl-$arch"

  rm -rf "$musl_dir/plugins/dosai"
  stage_binary "$musl_dir" dosai "linuxmusl-$arch"
  generate_metadata "$musl_dir"
  bash "$helper_script" "$musl_dir" >/dev/null 2>&1
  [[ "$(node -p 'require(process.argv[1]).plugins.find((p) => p.name === "dosai").binaryPath' \
    "$musl_dir/plugins/plugins-manifest.json")" == "plugins/dosai/dosai-linuxmusl-$arch" ]]
done

# macOS packages keep sourcekitten, and cdxgen runs osquery from inside its app
# bundle.
darwin_dir="$tmpdir/darwin-arm64"
for plugin in trivy trustinspector golem rusi kosi cdxui cdxrs sourcekitten dosai osquery; do
  stage_binary "$darwin_dir" "$plugin" darwin-arm64
done
generate_metadata "$darwin_dir"
bash "$helper_script" "$darwin_dir" >/dev/null 2>&1

# Windows does not use the bit, and cdxgen runs the .exe name.
windows_dir="$tmpdir/windows-amd64"
for plugin in trivy trustinspector golem rusi cdxui cdxrs dosai osquery; do
  stage_binary "$windows_dir" "$plugin" windows-amd64
  chmod 0644 "$windows_dir/plugins/$plugin/$(plugin_binary_name "$plugin" windows-amd64)"
done
generate_metadata "$windows_dir"
bash "$helper_script" "$windows_dir" >/dev/null 2>&1

# ppc64 binaries carry cdxgen's linux-ppc64le name, and upstream publishes
# neither dosai nor osquery there.
ppc64_dir="$tmpdir/ppc64"
for plugin in trivy trustinspector golem; do
  stage_binary "$ppc64_dir" "$plugin" linux-ppc64le
done
generate_metadata "$ppc64_dir"
bash "$helper_script" "$ppc64_dir" >/dev/null 2>&1

echo "check-plugin-coverage test passed"
