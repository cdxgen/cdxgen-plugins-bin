#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_script="$script_dir/assert-trivy-cdxgen-sbom.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/good.json" <<'JSON'
{
  "components": [
    {
      "type": "operating-system",
      "name": "alpine"
    },
    {
      "type": "library",
      "name": "github.com/example/demo",
      "purl": "pkg:golang/github.com/example/demo@v1.0.0",
      "properties": [
        {
          "name": "aquasecurity:trivy:PkgType",
          "value": "gobinary"
        }
      ]
    }
  ]
}
JSON

bash "$helper_script" "$tmpdir/good.json" "good-fixture"

cat > "$tmpdir/missing-os.json" <<'JSON'
{
  "components": [
    {
      "type": "library",
      "name": "github.com/example/demo",
      "properties": [
        {
          "name": "aquasecurity:trivy:PkgType",
          "value": "gobinary"
        }
      ]
    }
  ]
}
JSON

if bash "$helper_script" "$tmpdir/missing-os.json" "missing-os" >"$tmpdir/missing-os.stdout" 2>"$tmpdir/missing-os.stderr"; then
  echo "expected missing-os fixture to fail" >&2
  exit 1
fi
grep -F "did not contain any operating-system components" "$tmpdir/missing-os.stderr" >/dev/null

cat > "$tmpdir/missing-go.json" <<'JSON'
{
  "components": [
    {
      "type": "operating-system",
      "name": "debian"
    },
    {
      "type": "library",
      "name": "github.com/example/demo",
      "purl": "pkg:golang/github.com/example/demo@v1.0.0",
      "properties": [
        {
          "name": "aquasecurity:trivy:PkgType",
          "value": "gomod"
        }
      ]
    }
  ]
}
JSON

if bash "$helper_script" "$tmpdir/missing-go.json" "missing-go" >"$tmpdir/missing-go.stdout" 2>"$tmpdir/missing-go.stderr"; then
  echo "expected missing-go fixture to fail" >&2
  exit 1
fi
grep -F "did not contain any Go binary components" "$tmpdir/missing-go.stderr" >/dev/null

echo "trivy-cdxgen SBOM assertion helper test passed"
