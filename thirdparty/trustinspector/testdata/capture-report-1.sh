#!/usr/bin/env bash
# Capture the report-1 baseline fixture: testdata/generated/report-1-rootfs.json
#
#   testdata/capture-report-1.sh [commit]
#
# Builds trustinspector exactly as it was BEFORE the report-2 change (default
# commit: 6f3b0533, the last report-1 main), runs `rootfs` on a tiny rootfs
# holding committed testdata/generated/demo-bundle.pem, and writes the JSON to
# testdata/generated/report-1-rootfs.json.
#
# This fixture pins the report-1 field semantics that consumers depend on.
# Do NOT regenerate it from the current source: the current source emits
# report-2. Requires a checkout with the full git history.
set -euo pipefail

COMMIT=${1:-6f3b0533}
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(git -C "$HERE/../../.." rev-parse --show-toplevel)"
OUT="$HERE/generated/report-1-rootfs.json"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

mkdir -p "$SCRATCH/src/thirdparty/trustinspector" "$SCRATCH/rootfs/etc/ssl/certs"
for f in main.go go.mod go.sum; do
  git -C "$REPO" show "$COMMIT:thirdparty/trustinspector/$f" \
    > "$SCRATCH/src/thirdparty/trustinspector/$f"
done
cp "$HERE/generated/demo-bundle.pem" "$SCRATCH/rootfs/etc/ssl/certs/demo-bundle.pem"

(cd "$SCRATCH/src/thirdparty/trustinspector" && go build -o "$SCRATCH/trustinspector-report1" .)
"$SCRATCH/trustinspector-report1" rootfs "$SCRATCH/rootfs" > "$OUT"
python3 - "$OUT" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["schema"] == "trustinspector/report-1", data["schema"]
certs = [m for m in data["materials"] if m["kind"] == "certificate"]
assert len(certs) == 3, [m["name"] for m in certs]
print(f"captured {len(certs)} report-1 certificate materials")
PY
echo "wrote $OUT"
