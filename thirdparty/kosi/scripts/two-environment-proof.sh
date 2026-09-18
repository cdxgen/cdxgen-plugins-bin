#!/usr/bin/env bash
# P18 §1: the two-environment proof, as a script instead of a claim.
#
# The P17 review found R108 by running `golden` on a second machine — a
# one-off no gate repeated. R104's and R105's proofs had both been
# one-environment proofs of cross-environment properties ("it passes with
# the cache removed — on my machine"), and the second one shipped a NEW
# environment dependence while claiming to remove the old. The rule this
# script enforces: a property about two environments is PROVEN in two
# environments.
#
# What it varies, all at the same commit, with the same kosi jar:
#   - CHECKOUT LOCATION: two git worktrees at <commit> (default HEAD), so
#     the analysed trees sit at different absolute paths;
#   - GRADLE CACHE STATE: leg A runs with the machine's caches exactly as
#     the runner left them; leg B runs with HOME and user.home pointed at
#     an empty directory — the offline resolver reads user.home/.gradle and
#     user.home/.m2, so leg B resolves against nothing.
# Then it compares the golden digests the two legs produce, pair by pair,
# and each leg against the CHECKED-IN goldens at that commit.
#
# A difference between the legs is an environment dependence in the report:
# exit 1, naming the pairs. "No difference" is the result that certifies the
# report contract ("two machines analysing the same tree compare equal") —
# on a machine whose Gradle cache is already empty, the cache axis is not
# exercised (the script prints a note); run it on the corpus machine for the
# warm-vs-scrubbed contrast.
#
# Usage: scripts/two-environment-proof.sh [<commit>]
# Requires: git, a JDK for ./gradlew and the jar, and a Gradle BUILD cache
# warm enough to build the fat jar offline (the analysis itself never needs
# the network).
set -euo pipefail

COMMIT="${1:-HEAD}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/java}"
JAVA_BIN="${JAVA_BIN:-java}"

cd "$REPO_ROOT"
if [ -n "$(git status --porcelain)" ]; then
  # The proof compares a COMMIT, and a dirty tree is neither. This works
  # from a kosi-only clone and from thirdparty/kosi inside the plugins
  # repo (a worktree then carries the whole plugins repo; kosi keeps its
  # relative position inside it).
  echo "two-environment-proof: working tree is dirty — commit or stash first" >&2
  exit 1
fi
KOSI_PREFIX="$(git rev-parse --show-prefix)"
COMMIT_SHA="$(git rev-parse "$COMMIT")"
PROOF="$(mktemp -d "${TMPDIR:-/tmp}/kosi-two-env.XXXXXX")"
WORKTREE_A="$PROOF/checkout-a"
WORKTREE_B="$PROOF/checkout-b"
HOME_B="$PROOF/home-b"
KOSI_A="$WORKTREE_A/$KOSI_PREFIX"
KOSI_B="$WORKTREE_B/$KOSI_PREFIX"

cleanup() {
  git worktree remove --force "$WORKTREE_A" >/dev/null 2>&1 || true
  git worktree remove --force "$WORKTREE_B" >/dev/null 2>&1 || true
  rm -rf "$PROOF"
}
trap cleanup EXIT

echo "two-environment-proof: commit $COMMIT_SHA"
git worktree add --detach --quiet "$WORKTREE_A" "$COMMIT_SHA"
git worktree add --detach --quiet "$WORKTREE_B" "$COMMIT_SHA"

# One jar, built once from the same commit: the property under test is about
# the analysis and its inputs, and the jar is the instrument, not the
# variable. Built in worktree A so the machine's Gradle BUILD cache applies;
# offline first, network as the fallback for a machine whose build cache is
# cold (the ANALYSIS never needs the network either way).
echo "two-environment-proof: building the fat jar (worktree A)"
if ! ( cd "$KOSI_A" && ./gradlew --offline -q :kosi-cli:kosiFatJar ) >/dev/null 2>&1; then
  echo "two-environment-proof: offline build failed, retrying with network" >&2
  ( cd "$KOSI_A" && ./gradlew -q :kosi-cli:kosiFatJar ) >/dev/null
fi
JAR="$KOSI_A/modules/kosi-cli/build/dist/kosi-all.jar"
test -s "$JAR"

if [ -d "$HOME/.gradle/caches/modules-2" ]; then
  echo "two-environment-proof: leg A cache = the machine's (warm/partial as it is)"
else
  echo "two-environment-proof: NOTE the machine has no Gradle modules-2 cache — the cache axis is NOT exercised, only the checkout-location axis is" >&2
fi

run_leg() { # $1 = kosi checkout dir, $2 = goldens out dir, $3... = java invocation env
  local checkout="$1" goldens="$2"; shift 2
  mkdir -p "$goldens"
  "$@" -jar "$JAR" golden --repo-root "$checkout" --goldens "$goldens" --update-goldens \
    > "$goldens.log" 2>&1 || {
      echo "two-environment-proof: golden FAILED in $checkout:" >&2
      grep -v "^WARNING" "$goldens.log" >&2 || true
      exit 1
    }
  grep -v "^WARNING" "$goldens.log" | tail -1
}

echo "two-environment-proof: leg A — $KOSI_A, machine caches"
run_leg "$KOSI_A" "$PROOF/goldens-a" "$JAVA_BIN"

mkdir -p "$HOME_B"
echo "two-environment-proof: leg B — $KOSI_B, HOME and user.home scrubbed to $HOME_B"
run_leg "$KOSI_B" "$PROOF/goldens-b" env "HOME=$HOME_B" "$JAVA_BIN" "-Duser.home=$HOME_B"

fails=0
# Digest files are one JSON line each; a raw diff dumps both whole lines.
# Name the FILE and the SECTIONS that differ instead — investigation starts
# there, not in a wall of hashes.
section_diff() { # $1 = left digest file, $2 = right digest file
  python3 - "$1" "$2" <<'PY'
import json, sys
def sections(p):
    return {d["section"]: d["digest"] for d in json.load(open(p))["digests"]}
a, b = sections(sys.argv[1]), sections(sys.argv[2])
diff = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
print(", ".join(diff) if diff else "(combined digest only)")
PY
}
report_diff() { # $1 = left dir, $2 = right dir, $3 = diff file, $4 = headline
  local left="$1" right="$2" diff_file="$3" headline="$4"
  if ! diff -rq "$left" "$right" > "$diff_file"; then
    echo "two-environment-proof: FAIL — $headline:" >&2
    sed 's/^/  /' "$diff_file" >&2
    echo "two-environment-proof: sections that differ, per file:" >&2
    grep -E ' differ$' "$diff_file" | sed -E 's/^Files (.*) and (.*) differ$/\1|\2/' | while IFS='|' read -r l r; do
      printf '  %s: %s\n' "$(basename "$l")" "$(section_diff "$l" "$r")"
    done
    return 1
  fi
  return 0
}

if ! report_diff "$PROOF/goldens-a" "$PROOF/goldens-b" "$PROOF/legs.diff" \
     "the two environments produced different digests"; then
  fails=$((fails + 1))
else
  echo "two-environment-proof: legs agree ($(ls "$PROOF/goldens-a" | wc -l | tr -d ' ') digest files)"
fi
if ! report_diff "$PROOF/goldens-a" "$KOSI_A/goldens" "$PROOF/pin.diff" \
     "both legs disagree with the CHECKED-IN goldens at $COMMIT_SHA"; then
  fails=$((fails + 1))
else
  echo "two-environment-proof: both legs match the checked-in goldens"
fi

if [ "$fails" -gt 0 ]; then
  echo "two-environment-proof: $fails failure(s)" >&2
  exit 1
fi
echo "two-environment-proof: PASS — same commit, two checkouts, two cache states, identical digests"
