#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/plugins/trivy"
cp "$repo_root/package.json" "$tmpdir/package.json"
cp "$repo_root/index.js" "$tmpdir/index.js"
cp "$repo_root/README.md" "$tmpdir/README.md"
cp "$repo_root/LICENSE" "$tmpdir/LICENSE"
cp "$repo_root/plugins/.npmignore" "$tmpdir/plugins/.npmignore"
cp "$repo_root/plugins/.gitkeep" "$tmpdir/plugins/.gitkeep"

printf 'binary-content' > "$tmpdir/plugins/trivy/trivy-cdxgen-linux-amd64"
printf 'deadbeef\n' > "$tmpdir/plugins/trivy/trivy-cdxgen-linux-amd64.sha256"
printf '{"bomFormat":"CycloneDX"}\n' > "$tmpdir/plugins/trivy/sbom-trivy-postbuild.cdx.json"

pushd "$tmpdir" >/dev/null
pack_output="$(npm pack --dry-run --json)"
popd >/dev/null

PACK_OUTPUT="$pack_output" node <<'EOF'
const payload = JSON.parse(process.env.PACK_OUTPUT);
if (!Array.isArray(payload) || payload.length !== 1) {
  throw new Error(`Unexpected npm pack payload: ${process.env.PACK_OUTPUT}`);
}

const [{ files, unpackedSize }] = payload;
const paths = files.map((entry) => entry.path);
const unexpectedPluginFiles = paths.filter(
  (filePath) => filePath.startsWith("plugins/") && !["plugins/.gitkeep", "plugins/.npmignore"].includes(filePath),
);
if (unexpectedPluginFiles.length > 0) {
  throw new Error(`Root package unexpectedly included plugin payload files: ${unexpectedPluginFiles.join(", ")}`);
}
if (unpackedSize > 131072) {
  throw new Error(`Root package unpacked size is unexpectedly large: ${unpackedSize}`);
}
EOF

echo "root package publish test passed"
