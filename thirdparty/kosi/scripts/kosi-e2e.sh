#!/bin/bash
# The P11 end-to-end gate for kosi (thirdparty/kosi/docs/KOSI.md, P11):
# cdxgen/evinse consumes the kosi report for the COMMITTED Kotlin sample
# project and the BOM carries occurrence, callstack, reachability, data-flow
# and crypto-flow evidence plus services[]; CDXGEN_KOSI_DISABLE=1 produces a
# valid BOM without kosi (the silent-fallback discipline from cdxrs).
#
# Half 1 (always runs): the REPORT contract — the exact fields evinse reads
# must exist and be well-formed on the sample. No node_modules needed.
# Half 2 (needs CDXGEN_DIR): the full evinse path against a cdxgen checkout
# carrying the kosi evinser arm. Without it the script says so and exits 0;
# set KOSI_E2E_REQUIRE_CDGEN=1 to fail instead (CI, after the arm lands).
#
# Usage:
#   scripts/kosi-e2e.sh                        # report contract
#   CDXGEN_DIR=~/work/cdxgen/cdxgen scripts/kosi-e2e.sh
set -euo pipefail

kosi_repo="$(cd "$(dirname "$0")/.." && pwd)"
sample="$kosi_repo/examples/kotlin-sample-app"
jar="${KOSI_JAR:-$kosi_repo/modules/kosi-cli/build/dist/kosi-all.jar}"
work="${KOSI_E2E_DIR:-$(mktemp -d /tmp/kosi-e2e-XXXX)}"
mkdir -p "$work"

if [ ! -f "$jar" ]; then
  echo "kosi-e2e: no fat jar at $jar; building it (./gradlew :kosi-cli:kosiFatJar)"
  (cd "$kosi_repo" && ./gradlew --no-daemon :kosi-cli:kosiFatJar -q)
fi

run_kosi() {
  local mode="$1" out="$2"
  java -Djava.awt.headless=true -Xmx4g -jar "$jar" analyze \
    --backend resolved --dataflow "$mode" --deps --endpoint-sources \
    --classpath-file "$sample/classpath.txt" \
    --dir "$sample" --out "$out" 2>/dev/null
}

echo "== half 1: the kosi report contract on $sample"
run_kosi all "$work/report-all.json"
run_kosi reachable "$work/report-reachable.json"

python3 - "$work/report-all.json" "$work/report-reachable.json" <<'PYEOF'
import json, sys

all_report, reachable_report = (json.load(open(path)) for path in sys.argv[1:3])
problems = []

def check(condition, message):
    if not condition:
        problems.append(message)

# occurrence evidence: usages with resolved purls and source positions
usages = all_report.get("usages", [])
check(any(u.get("purl") and u.get("position") for u in usages),
      "no usage carries a purl and a position (occurrence evidence empty)")

# data-flow + callstack evidence: slices with connected traces
slices = (all_report.get("dataFlow") or {}).get("slices", [])
check(len(slices) >= 3, f"expected >= 3 slices on the sample, got {len(slices)}")
for slice in slices:
    check(slice.get("ruleId") and slice.get("severity"),
          f"slice {slice.get('id')} lacks rule identity")
    check(slice.get("sourceId") in (slice.get("nodeIds") or []),
          f"slice {slice.get('id')} trace does not start at its source")
    check(slice.get("sinkId") in (slice.get("nodeIds") or []),
          f"slice {slice.get('id')} trace does not end at its sink")

# the cross-dependency half: bytecode-origin slices into the dependency jar
cross = [s for s in slices if s.get("crossesDependency")]
check(any("bytecode" in (s.get("origins") or []) for s in cross),
      "no cross-dependency slice carries a bytecode origin")

# reachability evidence: the reachable pass flags slices from the roots
rslices = (reachable_report.get("dataFlow") or {}).get("slices", [])
check(any(s.get("reachableFromRoots") for s in rslices),
      "no slice is reachableFromRoots in the reachable pass")

# crypto-flow evidence: a material-to-crypto-asset slice and the material
crypto = all_report.get("crypto") or {}
check(any(s.get("sourceCategory") == "hardcoded-secret" and s.get("sinkCategory") == "crypto-asset"
          for s in slices), "no crypto-flow slice (hardcoded-secret -> crypto-asset)")
check(len(crypto.get("materials", [])) >= 1, "no crypto material on the sample")

# services evidence: the outbound JDBC service with its resolution
services = all_report.get("services", [])
check(any(s.get("protocol") == "jdbc" and s.get("resolution") == "literal"
          for s in services), "the outbound JDBC service row is missing")

if problems:
    for problem in problems:
        print("kosi-e2e FAIL:", problem)
    sys.exit(1)
print("kosi-e2e: report contract holds "
      f"({len(slices)} slices, {len(cross)} cross-dependency, {len(services)} service(s))")
PYEOF

echo "== half 2: cdxgen/evinse consumes the report"
cdxgen_dir="${CDXGEN_DIR:-}"
if [ -z "$cdxgen_dir" ] || [ ! -f "$cdxgen_dir/bin/evinse.js" ]; then
  message="CDXGEN_DIR is not set or has no bin/evinse.js; the evinse half needs a cdxgen checkout carrying the kosi evinser arm"
  if [ "${KOSI_E2E_REQUIRE_CDGEN:-0}" = "1" ]; then
    echo "kosi-e2e FAIL: $message" >&2
    exit 1
  fi
  echo "kosi-e2e: SKIP — $message"
  echo "kosi-e2e: the cdxgen integration is UNVERIFIED by this run. The arm lives"
  echo "  on the cdxgen branch feat/kosi-evinse-tmp, which is not pushed — so this"
  echo "  half runs on one machine only and CI cannot gate it yet."
  exit 0
fi

sample_abs="$(cd "$sample" && pwd)"
(cd "$cdxgen_dir" && node bin/cdxgen.js --type java -o "$work/bom.json" "$sample_abs" >/dev/null 2>&1)
(cd "$cdxgen_dir" && KOSI_CMD="$jar" node bin/evinse.js -l kotlin \
   --input "$work/bom.json" -o "$work/bom.evinse.json" "$sample_abs" >/dev/null 2>&1)
(cd "$cdxgen_dir" && CDXGEN_KOSI_DISABLE=1 KOSI_CMD="$jar" node bin/evinse.js -l kotlin \
   --input "$work/bom.json" -o "$work/bom.disabled.json" "$sample_abs" >/dev/null 2>&1)

python3 - "$work/bom.evinse.json" "$work/bom.disabled.json" <<'PYEOF'
import json, sys

evinse, disabled = (json.load(open(path)) for path in sys.argv[1:3])
problems = []

def check(condition, message):
    if not condition:
        problems.append(message)

def bom_evidence_kinds(bom):
    kinds = {}
    for component in [bom.get("metadata", {}).get("component")] + bom.get("components", []):
        if not component:
            continue
        for kind in component.get("evidence") or {}:
            kinds[kind] = kinds.get(kind, 0) + 1
    return kinds

def bom_kosi_artifacts(bom):
    kinds = {}
    components = [bom.get("metadata", {}).get("component")] + bom.get("components", [])
    for component in components:
        if not component:
            continue
        for prop in component.get("properties") or []:
            if prop["name"].startswith("cdx:kosi:"):
                kinds["props"] = kinds.get("props", 0) + 1
    for service in bom.get("services") or []:
        if any(p["name"].startswith("cdx:kosi:") for p in service.get("properties") or []):
            kinds["services"] = kinds.get("services", 0) + 1
    if (bom.get("metadata", {}).get("component") or {}).get("purl", "").startswith("pkg:generic/"):
        kinds["workspace-anchor"] = 1
    return kinds

kinds = bom_evidence_kinds(evinse)
kosi_artifacts = bom_kosi_artifacts(evinse)
all_components = [evinse.get("metadata", {}).get("component")] + evinse.get("components", [])
for kind in ("occurrences", "callstack"):
    check(kind in kinds, f"no {kind} evidence in the evinse BOM")
check(kosi_artifacts.get("props", 0) > 0, "no cdx:kosi properties in the evinse BOM (data-flow/reachability)")
check(any(p["name"] == "cdx:kosi:reachableFromRoots"
          for c in all_components
          for p in c.get("properties") or [] if c),
      "no reachability evidence (cdx:kosi:reachableFromRoots)")
check(any(p["name"] == "cdx:kosi:cryptoFlow"
          for c in all_components
          for p in c.get("properties") or [] if c),
      "no crypto-flow evidence (cdx:kosi:cryptoFlow)")
check(any(c.get("type") == "cryptographic-asset" for c in evinse.get("components", [])),
      "no cryptographic-asset component in the evinse BOM")
check(len(evinse.get("services", [])) >= 1, "no services[] row in the evinse BOM")

disabled_kinds = bom_kosi_artifacts(disabled)
check(disabled.get("bomFormat") == "CycloneDX" and disabled.get("components"),
      "CDXGEN_KOSI_DISABLE=1 did not produce a valid BOM")
check(not disabled_kinds, f"the disabled run still carries kosi artifacts: {disabled_kinds}")

if problems:
    for problem in problems:
        print("kosi-e2e FAIL:", problem)
    sys.exit(1)
print("kosi-e2e: evinse carries occurrence/callstack/reachability/data-flow/crypto-flow "
      f"evidence + services[] ({sorted(kinds)}); CDXGEN_KOSI_DISABLE=1 falls back silently")
PYEOF
echo "kosi-e2e: PASS"