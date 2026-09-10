#!/usr/bin/env bash
# docs/BUILD.md determinism recipe, scripted: two runs per fixture, JVM and
# native, with the R53 hardening — outputs DELETED before every run, exit
# codes checked, sizes asserted, tool.commit normalised, and the per-fixture
# counts printed so a comparison over reused paths cannot pass silently.
#
# Usage: scripts/determinism-sweep.sh <binary> [label]
#   <binary>  kosi-all.jar via java? pass "--jar path" instead. Examples:
#   scripts/determinism-sweep.sh --jar modules/kosi-cli/build/dist/kosi-all.jar JVM
#   scripts/determinism-sweep.sh build/kosi-darwin-arm64 native
set -euo pipefail

BIN=""
if [ "$1" = "--jar" ]; then
  BIN="java -jar $2"
  shift 2
else
  BIN="$1"
  shift
fi
LABEL="${1:-sweep}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fails=0
checked=0
# Both graph-bearing slots, not just `resolved`. R53's lesson generalises: a
# slot the sweep never runs is a code path the sweep proves nothing about,
# and `exported` is exactly the slot whose missing reflection entry killed
# the P3 image while its own comparison reported 30 of 30 identical.
SLOTS="resolved exported"
printf '%-28s %-9s %8s %8s %8s %9s\n' "fixture" "slot" "slices" "nodes" "edges" "match"
for dir in "$ROOT"/fixtures/*/; do
 slug=$(basename "$dir")
 case "$slug" in .corpus-cache) continue;; esac
 for slot in $SLOTS; do
  case "$slot" in
    exported) slot_args="--backend resolved --roots exported";;
    *)        slot_args="--backend resolved";;
  esac
  a=$(mktemp); b=$(mktemp)
  rm -f "$a" "$b"
  if ! $BIN analyze $slot_args --dir "$dir" --out "$a" > /dev/null 2>&1; then
    printf '%-28s %-9s RUN FAILED (exit nonzero, no output demanded)\n' "$slug" "$slot"; fails=$((fails+1)); continue
  fi
  if ! $BIN analyze $slot_args --dir "$dir" --out "$b" > /dev/null 2>&1; then
    printf '%-28s %-9s RUN FAILED (second)\n' "$slug" "$slot"; fails=$((fails+1)); continue
  fi
  if [ ! -s "$a" ] || [ ! -s "$b" ]; then
    printf '%-28s %-9s EMPTY OUTPUT\n' "$slug" "$slot"; fails=$((fails+1)); continue
  fi
  # tool.commit differs between a JVM jar and an image build; normalise it.
  sed -E 's/"commit":"[^"]*"/"commit":"X"/g' "$a" > "$a.n"
  sed -E 's/"commit":"[^"]*"/"commit":"X"/g' "$b" > "$b.n"
  counts=$(python3 -c "
import json,sys
r=json.load(open('$a'))
df=r.get('dataFlow') or {}
cg=r.get('callGraph') or {'stats':{}}
print(df.get('stats',{}).get('sliceCount',0), len(cg.get('nodes',[])), len(cg.get('edges',[])))
")
  if cmp -s "$a.n" "$b.n"; then match=identical; else match=DIFFER; fails=$((fails+1)); fi
  printf '%-28s %-9s %8s %8s %8s %9s\n' "$slug" "$slot" $(echo $counts) "$match"
  checked=$((checked+1))
  rm -f "$a" "$b" "$a.n" "$b.n"
 done
done
echo "$LABEL: $checked fixture/slot pair(s) checked, $fails failure(s)"
[ "$fails" -eq 0 ]
