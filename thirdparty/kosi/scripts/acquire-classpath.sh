#!/usr/bin/env bash
# Acquire a classpath for ONE project directory, trying several strategies
# in order and reporting WHICH ONE FIRED (P28 §1):
#
#   gradle  the project's own `./gradlew dependencies` reports, per
#           subproject, all configurations (Android variants included: the
#           report prints every variant-specific configuration). EXECUTES
#           the target build tooling; old AGP/JDK mismatches fail here
#           honestly and the next strategy runs.
#   maven   `mvn -q dependency:build-classpath` -> jar paths from the
#           local repository. EXECUTES the target build tooling.
#   file    a classpath.txt / Eclipse .classpath already in the tree.
#   jars    a libs/ directory of vendored jars.
#   cache   NO BUILD AT ALL: `group:artifact:version` coordinates read as
#           TEXT from the build files (Gradle literals, version catalogs,
#           pom <dependency> blocks). kosi's own resolver then matches them
#           against ~/.gradle/caches/modules-2 and ~/.m2/repository — with
#           all of its multiplatform/AAR/module-metadata rules — and
#           publishes what attached and what is missing in
#           stats.classpath. Partial by nature: only what this machine
#           already downloaded.
#
# The winning strategy writes <dir>/classpath.txt (jar paths and/or
# coordinates, `#` comments allowed — the exact grammar kosi's
# `--classpath-file` flag and its discovered-file strategy accept), with a
# `# strategy:` provenance header. `kosi analyze` picks the file up
# automatically via the `file` acquisition strategy.
#
# This is the operator-side step warm-corpus-classpath.sh performs for
# pinned corpus repos, generalised to any directory. kosi itself never
# executes the analysed build (THREAT_MODEL.md); this script is run by a
# person who decided to.
#
# Usage: scripts/acquire-classpath.sh [--strategy auto|gradle|maven|file|jars|cache]
#                                      [--pull] [--framework-jar <jar>] <dir>...
#
#   --strategy       force one strategy (default: auto, the order above)
#   --pull           after the winning strategy fires, ALSO resolve its
#                    coordinates' transitive closures into the local caches
#                    via the shared synthetic Gradle build
#                    (scripts/scratch-resolve; downloads), then merge the
#                    resolved closure into the file
#   --framework-jar  append a platform jar (e.g. robolectric's android-all)
#                    to the produced file — Android sources extend
#                    android.* classes and resolve as broken without it
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch_build="$repo_root/scripts/scratch-resolve/build.gradle.kts"
strategy="auto"
pull=0
framework_jar=""
dirs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --strategy) strategy="${2:?}"; shift 2 ;;
    --pull) pull=1; shift ;;
    --framework-jar) framework_jar="${2:?}"; shift 2 ;;
    -*) echo "unknown flag $1" >&2; exit 2 ;;
    *) dirs+=("$1"); shift ;;
  esac
done
[ ${#dirs[@]} -ge 1 ] || { echo "usage: acquire-classpath.sh [--strategy ...] [--pull] <dir>..." >&2; exit 2; }
case "$strategy" in
  auto|gradle|maven|file|jars|cache) ;;
  *) echo "unknown strategy '$strategy' (auto|gradle|maven|file|jars|cache)" >&2; exit 2 ;;
esac

# Same JDK-21 preference as warm-corpus-classpath.sh: pinned repos bundle
# wrappers old enough to reject newer JDK class files.
java_major() { "$1/bin/java" -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+).*/\1/'; }
if [ -z "${JAVA_HOME:-}" ] || [ "$(java_major "${JAVA_HOME:-/nonexistent}")" -ge 22 ] 2>/dev/null; then
  for candidate in "$HOME/.sdkman/candidates/java/"*; do
    if [ -x "$candidate/bin/java" ] && [ "$(java_major "$candidate")" = "21" ]; then
      export JAVA_HOME="$candidate"
      export PATH="$candidate/bin:$PATH"
      break
    fi
  done
fi

coord_re='^[` +->]*[a-zA-Z0-9][a-zA-Z0-9._-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*:[a-zA-Z0-9][a-zA-Z0-9._-]+([@a-zA-Z0-9._-]*)?$'
tree_line='^[-+\\| ]*--- [a-zA-Z]'

# ---- strategy arms -----------------------------------------------------------

# gradle: the project's own dependency reports, every subproject, default +
# test configurations.
gradle_report() {
  local dir="$1" out="$2"
  [ -x "$dir/gradlew" ] || return 1
  # A WALL-CLOCK budget over the whole arm: a per-call timeout alone lets a
  # broken multi-project build eat N x 3 x timeout (measured: mifos-mobile,
  # ~20 subprojects whose dependency reports hang). Over budget the arm
  # reports what it collected so far — possibly nothing, which is the next
  # strategy's input.
  local budget="${KOSI_ACQUIRE_GRADLE_BUDGET:-180}"
  local started
  started=$(date +%s)
  over_budget() { [ $(( $(date +%s) - started )) -ge "$budget" ]; }
  (cd "$dir" && timeout "${KOSI_ACQUIRE_GRADLE_TIMEOUT:-120}" ./gradlew -q projects --console=plain 2>/dev/null || true) \
    | { grep -oE "Project '(:[^']*)'" || true; } \
    | sed -E "s/Project '([^']*)'/\1/" | sed 's/^$/:/' >"$dir/.acq-projects"
  local projects=()
  while IFS= read -r p; do projects+=("$p"); done <"$dir/.acq-projects"
  rm -f "$dir/.acq-projects"
  [ ${#projects[@]} -eq 0 ] && projects=(":")
  : >"$out"
  for p in "${projects[@]}"; do
    over_budget && { echo "    (gradle budget spent at project $p)" >&2; break; }
    for extra in "" "--configuration testCompileClasspath" "--configuration testRuntimeClasspath"; do
      (cd "$dir" && timeout "${KOSI_ACQUIRE_GRADLE_TIMEOUT:-120}" ./gradlew -q "$p:dependencies" $extra --console=plain 2>/dev/null || true) \
        | { grep -E "$tree_line" || true; } \
        | sed -E 's/^[-+\\| ]*--- //; s/ \(.*\)$//; s/ -> /:/g' \
        | { grep -E "$coord_re" || true; } \
        >>"$out" || true
    done
  done
  [ -s "$out" ]
}

# maven: dependency:build-classpath writes one long platform path string;
# split it into jar lines. Executes the target build.
maven_report() {
  local dir="$1" out="$2"
  [ -f "$dir/pom.xml" ] || return 1
  command -v mvn >/dev/null 2>&1 || return 1
  local tmp
  tmp="$(mktemp)"
  (cd "$dir" && timeout "${KOSI_ACQUIRE_MAVEN_TIMEOUT:-120}" mvn -q -B dependency:build-classpath -Dmdep.outputFile="$tmp" \
     -Dmdep.includeScope=test >/dev/null 2>&1) || { rm -f "$tmp"; return 1; }
  [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
  tr ':' '\n' <"$tmp" | grep -E '\.jar$' | sort -u >"$out"
  rm -f "$tmp"
  [ -s "$out" ]
}

# file: a classpath file already in the tree.
present_file() {
  local dir="$1" out="$2"
  if [ -s "$dir/classpath.txt" ]; then
    grep -vE '^\s*(#|$)' "$dir/classpath.txt" >"$out"
  elif [ -f "$dir/.classpath" ]; then
    sed -nE 's/.*<classpathentry[^>]*kind="lib"[^>]*path="([^"]+)"[^>]*>.*/\1/p' "$dir/.classpath" >"$out"
    sed -nE 's/.*<classpathentry[^>]*path="([^"]+)"[^>]*kind="lib"[^>]*>.*/\1/p' "$dir/.classpath" >>"$out" 2>/dev/null || true
  fi
  [ -s "$out" ]
}

# jars: vendored jars in libs/ directories (root and one level deep).
jar_directory() {
  local dir="$1" out="$2"
  find "$dir" -maxdepth 2 -type d -name libs 2>/dev/null | LC_ALL=C sort | while read -r libs; do
    find "$libs" -maxdepth 1 -name '*.jar' 2>/dev/null | LC_ALL=C sort
  done | grep -vE '(-sources|-javadoc)\.jar$' >"$out"
  [ -s "$out" ]
}

# cache: REPORT-ONLY. Coordinates as text, no build — but it deliberately
# writes NO classpath.txt: kosi's own offline scan (the `cache` acquisition
# strategy) parses build files with the real grammar (version catalogs in
# both forms, pom blocks, KMP/AAR/module-metadata locators) and attaches
# strictly more than a shell-side grep can list. A file written here would
# SHADOW that scan at analysis time (kosi's file strategy outranks cache),
# which is worse than not writing one — measured on kotlinx.serialization:
# the shell grep lists 5 coordinates, kosi's scan attaches 21 jars.
cache_text() {
  local dir="$1" out="$2"
  local count
  count="$(textual_coordinate_count "$dir")"
  [ "${count:-0}" -ge 1 ] || return 1
  echo "deferred-to-kosi ($count text-declared coordinate(s); kosi's cache strategy attaches them at analysis time)" >"$out"
  return 0
}

textual_coordinate_count() {
  local dir="$1"
  local kotlin_ver
  kotlin_ver=$(grep -rhoE "ext[.]kotlin_version *= *['\"][^'\"]+" "$dir" --include=build.gradle 2>/dev/null \
    | sed -n '1p' | sed -E "s/.*['\"]//" || true)
  {
    find "$dir" \( -name '*.gradle' -o -name '*.gradle.kts' -o -name '*.versions.toml' \) \
      -not -path '*/.git/*' 2>/dev/null | LC_ALL=C sort | while read -r f; do
      grep -hoE '["'\''][a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[^"'\'']+["'\'']' "$f" 2>/dev/null \
        | sed -E 's/^["'\'']//; s/["'\'']$//' || true
    done
  } | grep -vE 'project[(]|fileTree|files[(]|\$\{|^[:]+' \
    | sed -E "s/[$][{]?kotlin_version[}]?/${kotlin_ver:-UNKNOWN}/" \
    | grep -cE "$coord_re" || true
}

# pull: the warm machinery's synthetic resolution — every coordinate's
# transitive closure into the local caches, leniently, then the resolved
# closure is merged into the coordinate list (a direct-only list leaves the
# transitive tree unattached; see warm-corpus-classpath.sh).
pull_closures() {
  local dir="$1" out="$2"
  [ -f "$scratch_build" ] || { echo "  scratch build missing: $scratch_build" >&2; return 1; }
  local scratch="$dir/_acquire_resolve"
  mkdir -p "$scratch"
  grep -E "$coord_re" "$out" >"$scratch/coords.txt"
  [ -s "$scratch/coords.txt" ] || { rm -rf "$scratch"; return 0; }
  cp "$scratch_build" "$scratch/build.gradle.kts"
  echo 'rootProject.name = "kosi-acquire-scratch"' >"$scratch/settings.gradle.kts"
  (cd "$repo_root" && ./gradlew -p "$scratch" -q resolveAll --console=plain >"$scratch/resolve.log" 2>&1 || true)
  if grep -qE "^downloaded [1-9]" "$scratch/resolve.log"; then
    { grep -E "^resolved " "$scratch/resolve.log" | sed -E 's/^resolved //'; cat "$out"; } | LC_ALL=C sort -u >"$out.new"
    mv "$out.new" "$out"
  else
    echo "  closure resolution downloaded nothing (see $scratch/resolve.log)" >&2
  fi
  rm -rf "$scratch"
}

# One version per group:artifact, the highest, per Gradle's own conflict
# resolution over a merged classpath — the same rule (and the same awk) as
# warm-corpus-classpath.sh's bound_coordinates, applied to a per-project
# dependency report that carries many versions of the same library.
bound_versions() {
  local out="$1"
  { grep -vE "$coord_re" "$out" || true; } >"$out.keep"
  { grep -E "$coord_re" "$out" || true; } | awk -F: '
      function segcmp(a, b,   na, nb, ap, bp, ad, bd) {
        if (a == b) return 0
        na = a ~ /^[0-9]+$/
        nb = b ~ /^[0-9]+$/
        if (na && nb) {
          if ((a + 0) != (b + 0)) return (a + 0) > (b + 0) ? 1 : -1
          return 0
        }
        if (a == "") return nb ? 0 : 1
        if (b == "") return na ? 0 : -1
        if (na) return 1
        if (nb) return -1
        ap = a; sub(/[0-9]+$/, "", ap)
        bp = b; sub(/[0-9]+$/, "", bp)
        if (ap != bp) return ap > bp ? 1 : -1
        ad = a; sub(/^[^0-9]*/, "", ad)
        bd = b; sub(/^[^0-9]*/, "", bd)
        if ((ad + 0) != (bd + 0)) return (ad + 0) > (bd + 0) ? 1 : -1
        return 0
      }
      function vercmp(a, b,   ai, bi, i, n, m, r) {
        n = split(a, ai, "."); m = split(b, bi, ".")
        for (i = 1; i <= n || i <= m; i++) {
          r = segcmp(ai[i], bi[i])
          if (r != 0) return r
        }
        return 0
      }
      { key = $1 ":" $2
        if (!(key in best) || vercmp($3, best[key]) > 0) best[key] = $3 }
      END { for (k in best) print k ":" best[k] }
    ' | LC_ALL=C sort >"$out.coords"
  cat "$out.keep" "$out.coords" >"$out.bounded"
  rm -f "$out.keep" "$out.coords"
  mv "$out.bounded" "$out"
}

# ---- per-directory driver ------------------------------------------------------

try_strategy() {
  local name="$1" dir="$2" out="$3"
  case "$name" in
    gradle) gradle_report "$dir" "$out" ;;
    maven)  maven_report "$dir" "$out" ;;
    file)   present_file "$dir" "$out" ;;
    jars)   jar_directory "$dir" "$out" ;;
    cache)  cache_text "$dir" "$out" ;;
  esac
}

failed=""
for dir in "${dirs[@]}"; do
  [ -d "$dir" ] || { echo "$dir: not a directory" >&2; failed="$failed $dir"; continue; }
  name="$(basename "$dir")"
  work="$(mktemp -d)"
  fired=""
  if [ "$strategy" = "auto" ]; then
    for s in gradle maven file jars cache; do
      if try_strategy "$s" "$dir" "$work/$s.txt"; then fired="$s"; break; fi
      echo "  $name: $s did not fire"
    done
  else
    if try_strategy "$strategy" "$dir" "$work/$strategy.txt"; then fired="$strategy"; fi
  fi
  if [ -z "$fired" ]; then
    echo "$name: NO strategy fired (strategy=$strategy); kosi's own cache scan will run at analysis time and say what it attached"
    rm -rf "$work"
    continue
  fi
  # cache is REPORT-ONLY (see cache_text): no file, ever — a written file
  # would shadow kosi's richer in-tool scan.
  if [ "$fired" = "cache" ]; then
    echo "$name: strategy=cache ($(cat "$work/cache.txt"))"
    rm -rf "$work"
    continue
  fi
  list="$work/$fired.txt"
  if [ "$fired" = "gradle" ]; then
    # One version per group:artifact, the highest (the same deterministic
    # cut warm-corpus-classpath.sh applies to a merged report).
    bound_versions "$list"
  fi
  if [ "$pull" = 1 ]; then
    pull_closures "$dir" "$list" || true
    [ "$fired" = "gradle" ] && bound_versions "$list"
  fi
  {
    echo "# acquired by strategy=$fired via scripts/acquire-classpath.sh; edit freely, delete to re-acquire"
    [ -n "$framework_jar" ] && [ -f "$framework_jar" ] && echo "$framework_jar"
    cat "$list"
  } | LC_ALL=C sort -u >"$dir/classpath.txt"
  entries="$(grep -cvE '^\s*(#|$)' "$dir/classpath.txt")"
  echo "$name: strategy=$fired entries=$entries -> $dir/classpath.txt"
  rm -rf "$work"
done
[ -n "$failed" ] && { echo "FAILED:$failed" >&2; exit 1; }
exit 0
