#!/usr/bin/env bash
# corpus-changed.sh — the P20 §5 middle tier: corpusChanged.
#
# corpusFull is the most expensive thing anyone runs in this repo (a warmed
# cache, one machine, ~50 minutes), and by P20 it had become the default
# answer to every question. It should be the phase-CLOSING answer to one
# question. This script computes and runs the MIDDLE tier on evidence:
#
#   1. the bundled tiers ALWAYS (fixtures + vuln — the corpusQuick
#      population plus the bundled vulnerable service), because 79 of 89
#      bundled fixtures' goldens have moved at least once in this repo's
#      history and every one of those movements was caught by the bundled
#      tiers' gates;
#   2. the vuln-repo floors ALWAYS (androgoat / insecureshop / tsp — the
#      findings ratchet's anchors; tsp is the resolved-tier sentinel whose
#      ratio has been exactly 1.0 since P14);
#   3. any REPO row whose declared `capabilities` intersect a capability
#      token that appears in the changed files' NAMES or DIFF CONTENT.
#      The token vocabulary is read FROM corpus.toml, so the mapping is
#      data-driven and self-maintaining: a repo declaring "coroutines"
#      runs when the diff mentions coroutines, a repo declaring
#      "endpoints" runs when the endpoints pack or detector changes.
#      Engine-wide areas (kosi-flow, kosi-graph, kosi-front, the packs)
#      mention no specific capability — their changes are caught by the
#      content tokens of the change itself, and by the sentinels above.
#
# Usage:
#   scripts/corpus-changed.sh [base-ref]        # compute AND run
#   KOSI_CORPUS_CHANGED_DRY_RUN=1 scripts/corpus-changed.sh [base-ref]
#
# base-ref defaults to origin/feat/kosi-part2 (the phase branch point).
#
# What this tier deliberately does NOT see (the standing gates cover it):
#   - cross-environment and cache effects   -> scripts/two-environment-proof.sh
#   - digest drift on the bundled fixtures  -> ./gradlew golden
#   - pack-symbol rotness and inert entries -> the two liveness sweeps
#   - everything else                        -> corpusFull, ONCE per phase,
#     whose result is what the phase report quotes.
#
# Repo rows need the corpus warm (`warm-corpus-classpath.sh --tier <name>`);
# an unwarmed repo is a skipped row (--skip-missing-repos), named, never a
# silent zero.

set -o pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
base="${1:-origin/feat/kosi-part2}"
cd "$repo_root"

if ! git rev-parse --verify "$base" >/dev/null 2>&1; then
  echo "corpus-changed: base ref '$base' not found; pass one explicitly" >&2
  exit 2
fi

merge_base="$(git merge-base HEAD "$base")"
changed="$(git diff --name-only "$merge_base" HEAD; git diff --name-only)"
if [ -z "$changed" ]; then
  echo "corpus-changed: no changes against $merge_base"
fi

# ---- the capability vocabulary, read from the manifest ---------------------
cap_tokens="$(grep -oE '"[a-z0-9_-]+"' corpus.toml | tr -d '"' | sort -u | grep -vE '^(fixtures|fixtures\[\])$' || true)"
if [ -z "$cap_tokens" ]; then
  echo "corpus-changed: no capability tokens found in corpus.toml" >&2
  exit 2
fi

# ---- which tokens does the change mention? ---------------------------------
token_hits=""
for token in $cap_tokens; do
  # Name match: a changed path or the corpus manifest itself names it.
  if printf '%s\n' $changed | grep -qE "(^|[-/_.])${token}([-/_.]|\$)" 2>/dev/null; then
    token_hits="$token_hits $token"
    continue
  fi
  # Content match: the diff of the changed sources mentions it (a framework
  # id, a transport, a tier name — whatever a repo declared as its
  # capability).
  if git diff "$merge_base" HEAD -- . 2>/dev/null | grep -qE "(^|[^a-z0-9_-])${token}([^a-z0-9_-]|\$)"; then
    token_hits="$token_hits $token"
  fi
done

echo "corpus-changed: base $merge_base, $(printf '%s\n' $changed | grep -c . ) changed file(s)"
echo "corpus-changed: capability tokens touched:${token_hits:- none}"

# ---- repo rows whose capabilities intersect --------------------------------
# slug + capabilities per repo-tier entry, awk'd out of the manifest.
matched_slugs="$(python3 - "$repo_root/corpus.toml" $token_hits <<'PY'
import re, sys
manifest, tokens = sys.argv[1], set(sys.argv[2:])
text = open(manifest).read()
repo_tiers = {"vuln-repo", "small", "medium", "android", "kmp", "hybrid"}
for block in re.findall(r"\[\[fixtures\]\]\n((?:(?!\[\[).)*)", text, re.S):
    slug = re.search(r'slug = "([^"]+)"', block)
    tier = re.search(r'tier = "([^"]+)"', block)
    caps = re.search(r'capabilities = \[([^\]]*)\]', block)
    if not (slug and tier) or tier.group(1) not in repo_tiers:
        continue
    declared = set(re.findall(r'"([^"]+)"', caps.group(1))) if caps else set()
    if declared & tokens:
        print(slug.group(1))
PY
)"

# The sentinels run always: the three vuln floors (tsp among them) are the
# pinned anchors whose every movement the tracker has had to account by name.
sentinels="$(python3 - "$repo_root/corpus.toml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
for block in re.findall(r"\[\[fixtures\]\]\n((?:(?!\[\[).)*)", text, re.S):
    slug = re.search(r'slug = "([^"]+)"', block)
    tier = re.search(r'tier = "([^"]+)"', block)
    if slug and tier and tier.group(1) == "vuln-repo":
        print(slug.group(1))
PY
)"

all_slugs="$(printf '%s\n%s\n' "$matched_slugs" "$sentinels" | sort -u | grep -v '^$' || true)"
echo "corpus-changed: repo rows selected: $all_slugs"

if [ "${KOSI_CORPUS_CHANGED_DRY_RUN:-0}" = "1" ]; then
  echo "corpus-changed: dry run — the invocation would be:"
  echo "  ./gradlew corpusQuick   # the bundled tiers, unchanged"
  echo "  ./gradlew kosiRepoRows -Pkosi.only=$(printf '%s,' $all_slugs | sed 's/,$//')"
  exit 0
fi

# Run: bundled tiers via corpusQuick, then the selected repo rows. The repo
# rows run in their own bench invocation so a cold cache on one repo is a
# skipped row, not a dead matrix.
set -e
./gradlew corpusQuick
if [ -n "$all_slugs" ]; then
  only_csv="$(printf '%s,' $all_slugs | sed 's/,$//')"
  ./gradlew -Pkosi.repo-tiers="vuln-repo,small,medium,android,kmp,hybrid" kosiRepoRows -Pkosi.only="$only_csv"
fi
echo "corpus-changed: PASS"
