#!/usr/bin/env bash
# The native-vs-JVM half of the determinism proof, scripted for the same
# reason the two-run sweep is: R53 reached the P3 gate because this
# comparison was done by hand, `analyze` writes nothing when it fails, and
# `cmp` therefore compared the previous fixture's report with itself while
# the image could not analyse an `object` at all. Prose telling a reviewer to
# "cmp the outputs per fixture" is how that happens again.
#
# Outputs are deleted before every run, exit codes are checked, sizes are
# asserted, tool.commit is normalised (the image bakes in its build commit),
# and both graph-bearing slots are covered — a slot nobody runs is a code
# path the image never registers.
#
# Usage: scripts/native-vs-jvm.sh <native-binary> <fat-jar>
#   scripts/native-vs-jvm.sh build/kosi-darwin-arm64 modules/kosi-cli/build/dist/kosi-all.jar
set -uo pipefail

NATIVE="${1:?usage: native-vs-jvm.sh <native-binary> <fat-jar>}"
JAR="${2:?usage: native-vs-jvm.sh <native-binary> <fat-jar>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

same=0
differ=0
failed=0
printf '%-28s %-9s %8s %10s\n' "fixture" "slot" "bytes" "verdict"
for dir in "$ROOT"/fixtures/*/; do
  slug=$(basename "$dir")
  case "$slug" in .corpus-cache) continue;; esac
  for slot in resolved exported; do
    if [ "$slot" = exported ]; then
      set -- --backend resolved --roots exported
    else
      set -- --backend resolved
    fi
    n=$(mktemp); j=$(mktemp)
    rm -f "$n" "$j"
    if ! "$NATIVE" analyze "$@" --dir "$dir" --out "$n" > /dev/null 2>&1; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" - "NATIVE FAILED"; failed=$((failed+1)); continue
    fi
    if ! java -jar "$JAR" analyze "$@" --dir "$dir" --out "$j" > /dev/null 2>&1; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" - "JVM FAILED"; failed=$((failed+1)); continue
    fi
    if [ ! -s "$n" ] || [ ! -s "$j" ]; then
      printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" 0 "EMPTY"; failed=$((failed+1)); continue
    fi
    sed -E 's/"commit":"[^"]*"/"commit":"X"/g' "$n" > "$n.x"
    sed -E 's/"commit":"[^"]*"/"commit":"X"/g' "$j" > "$j.x"
    if cmp -s "$n.x" "$j.x"; then
      verdict=identical; same=$((same+1))
    else
      verdict=DIFFER; differ=$((differ+1))
    fi
    printf '%-28s %-9s %8s %10s\n' "$slug" "$slot" "$(wc -c < "$n.x" | tr -d ' ')" "$verdict"
    rm -f "$n" "$j" "$n.x" "$j.x"
  done
done
echo "native vs JVM: $same identical, $differ differ, $failed failed"
[ "$differ" -eq 0 ] && [ "$failed" -eq 0 ]
