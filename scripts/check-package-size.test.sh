#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/check-package-size.sh"
repo_root="$(cd "$script_dir/.." && pwd)"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/package"
cp "$repo_root/package.json" "$tmpdir/package/package.json"
cp "$repo_root/index.js" "$tmpdir/package/index.js"
cp "$repo_root/README.md" "$tmpdir/package/README.md"
cp "$repo_root/LICENSE" "$tmpdir/package/LICENSE"
mkdir -p "$tmpdir/package/plugins"
printf '' > "$tmpdir/package/plugins/.gitkeep"
printf 'plugins/.gitkeep
' > "$tmpdir/package/plugins/.npmignore"

bash "$helper_script" "$tmpdir/package"

if NPM_PACKAGE_MAX_PACKED_BYTES=1 bash "$helper_script" "$tmpdir/package" >/dev/null 2>&1; then
  echo "check-package-size.sh unexpectedly passed with an impossibly small packed limit" >&2
  exit 1
fi

echo "check-package-size helper test passed"
