#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_MAX_PACKED_BYTES=$((250 * 1024 * 1024))
readonly DEFAULT_MAX_UNPACKED_BYTES=$((250 * 1024 * 1024))

check_package_dir() {
  local package_dir="$1"
  local packed_limit="${NPM_PACKAGE_MAX_PACKED_BYTES:-$DEFAULT_MAX_PACKED_BYTES}"
  local unpacked_limit="${NPM_PACKAGE_MAX_UNPACKED_BYTES:-$DEFAULT_MAX_UNPACKED_BYTES}"
  local pack_output
  local pack_tmpdir

  if [[ ! -d "$package_dir" ]]; then
    echo "Package directory not found: $package_dir" >&2
    exit 1
  fi

  pack_tmpdir="$(mktemp -d)"
  trap 'rm -rf "$pack_tmpdir"' RETURN
  pushd "$package_dir" >/dev/null
  pack_output="$(npm pack --json --pack-destination "$pack_tmpdir")"
  popd >/dev/null

  PACK_OUTPUT="$pack_output" \
  PACKAGE_DIR="$package_dir" \
  PACK_TMPDIR="$pack_tmpdir" \
  PACKED_LIMIT="$packed_limit" \
  UNPACKED_LIMIT="$unpacked_limit" \
  node <<'EOF'
const fs = require('node:fs');
const path = require('node:path');

const payload = JSON.parse(process.env.PACK_OUTPUT);
if (!Array.isArray(payload) || payload.length !== 1) {
  throw new Error(`Unexpected npm pack payload for ${process.env.PACKAGE_DIR}: ${process.env.PACK_OUTPUT}`);
}

const [{ filename, packageSize = 0, unpackedSize = 0 }] = payload;
const packedLimit = Number(process.env.PACKED_LIMIT);
const unpackedLimit = Number(process.env.UNPACKED_LIMIT);
const packedSize = packageSize > 0
  ? packageSize
  : fs.statSync(path.join(process.env.PACK_TMPDIR, filename)).size;

if (packedSize > packedLimit) {
  throw new Error(
    `Packed npm artifact ${filename} for ${process.env.PACKAGE_DIR} is ${packedSize} bytes, exceeding ${packedLimit}`,
  );
}
if (unpackedSize > unpackedLimit) {
  throw new Error(
    `Unpacked npm artifact ${filename} for ${process.env.PACKAGE_DIR} is ${unpackedSize} bytes, exceeding ${unpackedLimit}`,
  );
}

console.log(
  `npm package size ok for ${process.env.PACKAGE_DIR}: packed=${packedSize} unpacked=${unpackedSize}`,
);
EOF
  trap - RETURN
  rm -rf "$pack_tmpdir"
}

main() {
  if [[ $# -eq 0 ]]; then
    check_package_dir "."
    return
  fi

  local package_dir
  for package_dir in "$@"; do
    check_package_dir "$package_dir"
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
