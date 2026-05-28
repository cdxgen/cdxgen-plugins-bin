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

first_call="$(sed -n '1p' "$log_file")"
second_call="$(sed -n '2p' "$log_file")"

[[ "$first_call" == *"ghcr.io/cdxgen/cdxgen-plugins-bin:golem-linuxmusl-amd64"* ]]
[[ "$first_call" == *"$tool_dir/golem-linuxmusl-amd64:application/vnd.cdxgen.plugins.layer.v1+tar"* ]]
[[ "$first_call" == *"$tool_dir/golem-linuxmusl-amd64.sha256:application/vnd.cdxgen.plugins.layer.v1+tar"* ]]
[[ "$first_call" == *"$tool_dir/sbom-golem-postbuild.cdx.json:sbom/cyclonedx+json"* ]]
[[ "$second_call" == *"ghcr.io/cdxgen/cdxgen-plugins-bin:golem-windows-amd64"* ]]
[[ "$second_call" == *"$tool_dir/golem-windows-amd64.exe:application/vnd.cdxgen.plugins.layer.v1+tar"* ]]

echo "publish-helper-oras helper test passed"
