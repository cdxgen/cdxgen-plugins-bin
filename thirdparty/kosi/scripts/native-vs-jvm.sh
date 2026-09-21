#!/usr/bin/env bash
# The native-vs-JVM half of the determinism proof, scripted for the same
# reason the two-run sweep is: R53 reached the P3 gate because this
# comparison was done by hand, `analyze` writes nothing when it fails, and
# `cmp` therefore compared the previous fixture's report with itself while
# the image could not analyse an `object` at all. Prose telling a reviewer to
# "cmp the outputs per fixture" is how that happens again.
#
# Outputs are deleted before every run, exit codes are checked, sizes are
# asserted, and both graph-bearing slots are covered — a slot nobody runs is
# a code path the image never registers.
#
# TWO THINGS ARE NORMALISED AWAY, and only these two: `tool.commit` (the
# image bakes in its build commit) and the whole `runtime` section (which
# records the substrate on purpose — `jvmVersion` and `nativeImage` MUST
# differ between the two sides). Everything else is analysis, and analysis
# that depends on the substrate is the defect this script exists to find.
#
# THE NATIVE SIDE RUNS WITH `JAVA_HOME` UNSET, deliberately. That is the
# condition the shipped binary actually meets: cdxgen invokes it from
# whatever shell the user has, and an image has no `java.home` of its own, so
# a JDK it cannot find is a JDK it does not use. A sweep that exports
# `JAVA_HOME` first is a sweep of a configuration nobody ships. Set
# `KOSI_NVJ_KEEP_ENV=1` to compare under an inherited environment instead.
#
# Usage: scripts/native-vs-jvm.sh <native-binary> <fat-jar>
#   scripts/native-vs-jvm.sh build/kosi-darwin-arm64 modules/kosi-cli/build/dist/kosi-all.jar
#
# Environment:
#   KOSI_NVJ_FIXTURES  space-separated fixture slugs; default every fixture.
#                      `scripts/native-subset.txt` holds the CI subset.
#   KOSI_NVJ_COMPARE   `full` (default) compares the whole normalised report;
#                      `stats` compares the `stats` section only, which is
#                      where a resolution gap shows and is cheap enough to
#                      run per-image-build.
#   KOSI_NVJ_KEEP_ENV  1 to leave the native side's environment alone.
set -uo pipefail

NATIVE="${1:?usage: native-vs-jvm.sh <native-binary> <fat-jar>}"
JAR="${2:?usage: native-vs-jvm.sh <native-binary> <fat-jar>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPARE="${KOSI_NVJ_COMPARE:-full}"

case "$COMPARE" in
  full|stats) ;;
  *) echo "KOSI_NVJ_COMPARE must be 'full' or 'stats', got '$COMPARE'" >&2; exit 2;;
esac

if [ -n "${KOSI_NVJ_FIXTURES:-}" ]; then
  dirs=()
  for slug in $KOSI_NVJ_FIXTURES; do
    if [ ! -d "$ROOT/fixtures/$slug" ]; then
      echo "no such fixture: $slug" >&2; exit 2
    fi
    dirs+=("$ROOT/fixtures/$slug/")
  done
else
  dirs=("$ROOT"/fixtures/*/)
fi

if [ "${KOSI_NVJ_KEEP_ENV:-0}" = 1 ]; then
  native_env=(env)
else
  native_env=(env -u JAVA_HOME)
fi

# Normalise a report to the comparable part. Reads the report on stdin.
normalize() {
  python3 -c '
import json, sys
report = json.load(sys.stdin)
report.pop("runtime", None)
tool = report.get("tool")
if isinstance(tool, dict):
    tool.pop("commit", None)
if sys.argv[1] == "stats":
    report = {"stats": report.get("stats")}
json.dump(report, sys.stdout, indent=1, sort_keys=True)
' "$COMPARE"
}

same=0
differ=0
failed=0
printf '%-28s %-9s %8s %10s\n' "fixture" "slot" "bytes" "verdict"
for dir in "${dirs[@]}"; do
  slug=$(basename "$dir")
  case "$slug" in .corpus-cache) continue;; esac
  for slot in resolved exported deps; do
    if [ "$slot" = exported ]; then
      set -- --backend resolved --roots exported
    elif [ "$slot" = deps ]; then
      # P9: the tier's lowering + metadata machinery, over the one fixture
      # whose committed helper jar makes the run deterministic.
      if [ ! -f "$dir/libs/dep-helper.jar" ]; then continue; fi
      set -- --backend resolved --deps --classpath "$dir/libs/dep-helper.jar"
    else
      set -- --backend resolved
    fi
    n=$(mktemp); j=$(mktemp)
    rm -f "$n" "$j"
    if ! "${native_env[@]}" "$NATIVE" analyze "$@" --dir "$dir" --out "$n" > /dev/null 2>&1; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" - "NATIVE FAILED"; failed=$((failed+1)); continue
    fi
    if ! java -jar "$JAR" analyze "$@" --dir "$dir" --out "$j" > /dev/null 2>&1; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" - "JVM FAILED"; failed=$((failed+1)); continue
    fi
    if [ ! -s "$n" ] || [ ! -s "$j" ]; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" 0 "EMPTY"; failed=$((failed+1)); continue
    fi
    if ! normalize < "$n" > "$n.x" || ! normalize < "$j" > "$j.x"; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" - "UNREADABLE"; failed=$((failed+1)); continue
    fi
    if cmp -s "$n.x" "$j.x"; then
      verdict=identical; same=$((same+1))
    else
      verdict=DIFFER; differ=$((differ+1))
      # A verdict nobody can act on sends the next reader back to the
      # binary; the first few differing lines usually name the section.
      diff "$j.x" "$n.x" | head -20 | sed 's/^/    /'
    fi
    printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" "$(wc -c < "$n.x" | tr -d ' ')" "$verdict"
    rm -f "$n" "$j" "$n.x" "$j.x"
  done
done
echo "native vs JVM ($COMPARE): $same identical, $differ differ, $failed failed"
[ "$differ" -eq 0 ] && [ "$failed" -eq 0 ]
