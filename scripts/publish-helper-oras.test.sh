#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/publish-helper-oras.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fake_bin_dir="$tmpdir/bin"
mkdir -p "$fake_bin_dir"
log_file="$tmpdir/oras.log"
cat > "$fake_bin_dir/oras" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$log_file"
EOF
chmod +x "$fake_bin_dir/oras"

export PATH="$fake_bin_dir:$PATH"

tool_dir="$tmpdir/plugins/golem"
mkdir -p "$tool_dir"
printf 'binary-content' > "$tool_dir/golem-linuxmusl-amd64"
printf 'deadbeef\n' > "$tool_dir/golem-linuxmusl-amd64.sha256"
printf '{"bomFormat":"CycloneDX"}\n' > "$tool_dir/sbom-golem-postbuild.cdx.json"
printf 'windows-binary' > "$tool_dir/golem-windows-amd64.exe"
printf 'beadfeed\n' > "$tool_dir/golem-windows-amd64.exe.sha256"

bash "$helper_script" ghcr.io/cdxgen/cdxgen-plugins-bin "$tool_dir" 'golem-*'

log_contents="$(cat "$log_file")"

[[ "$log_contents" == *"--artifact-type application/vnd.cdxgen.plugins.helper.v1"* ]]
[[ "$log_contents" == *"ghcr.io/cdxgen/cdxgen-plugins-bin:golem-linuxmusl-amd64"* ]]
[[ "$log_contents" == *"$tool_dir/golem-linuxmusl-amd64:application/octet-stream"* ]]
[[ "$log_contents" == *"$tool_dir/golem-linuxmusl-amd64.sha256:text/plain"* ]]
[[ "$log_contents" == *"$tool_dir/sbom-golem-postbuild.cdx.json:application/vnd.cyclonedx+json"* ]]
[[ "$log_contents" == *"ghcr.io/cdxgen/cdxgen-plugins-bin:golem-windows-amd64"* ]]
[[ "$log_contents" == *"$tool_dir/golem-windows-amd64.exe:application/octet-stream"* ]]

echo "publish-helper-oras helper test passed"
