#!/usr/bin/env bash
# Generates .corpus-cache/<slug>/classpath.txt for a pinned corpus repo: the
# build-produced classpath file behind corpus.toml's `classpath_file` entries
# (02-ARCHITECTURE.md §3, acquisition order 2). The file lists resolved
# dependency coordinates (`group:artifact:version`, one per line), which kosi
# locates in the local Gradle/Maven caches.
#
# This script EXECUTES build tooling (Gradle dependency reports + a synthetic
# resolution project) — it is a developer/CI-side cache-warming step and is
# never run by kosi at analysis time. kosi only reads the produced file;
# without it, offline resolution runs and every gap is diagnosed as
# classpath-partial.
#
# Usage: scripts/warm-corpus-classpath.sh <slug> [more slugs...]
#        scripts/warm-corpus-classpath.sh --tier <tier-name>
#
# `--tier vuln-repo` is how the vulnerable-repo tier's classpaths get
# warmed (P14): the slugs come from corpus.toml, so a repo added to the
# tier is warmed the moment it is pinned. A warm that produces no
# coordinate list and no downloads FAILS the script (exit 1) — R73's
# silent-warning shape is how four phases measured zero against empty
# classpaths without noticing, and the P14 finding floors are measured
# against exactly these classpaths.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="$repo_root/.corpus-cache"

slugs=()
tier_repos=""
if [ "${1:-}" = "--tier" ]; then
  tier="${2:?usage: warm-corpus-classpath.sh --tier <tier>}"
  # slug<TAB>repo<TAB>sha<TAB>tier: the manifest's repo entries carry their
  # own pins, so --tier can also FETCH a cache that is not on disk yet (the
  # CI corpus job warms before it benches; the bench itself fetches too, but
  # only when it runs).
  # Records flush at the NEXT table (or EOF): a table's repo/sha lines can
  # follow its tier line, so emitting at the tier line itself would see an
  # empty repo (measured: `--tier small` found nothing).
  tier_repos=$(awk '
    function flush() { if (slug != "" && repo != "") print slug "\t" repo "\t" sha "\t" tier }
    /^\[\[fixtures\]\]/ { flush(); slug=""; repo=""; sha=""; tier="" }
    /^slug *=/ { gsub(/[" ]/, "", $3); slug=$3 }
    /^repo *=/ { gsub(/[" ]/, "", $3); repo=$3 }
    /^sha *=/  { gsub(/[" ]/, "", $3); sha=$3 }
    /^tier *=/ { gsub(/[" ]/, "", $3); tier=$3 }
    END { flush() }
  ' "$repo_root/corpus.toml")
  while IFS=$'\t' read -r slug repo sha entry_tier; do
    [ "$entry_tier" = "$tier" ] || continue
    cache="$cache_root/$slug"
    if [ ! -d "$cache" ] && [ -n "$repo" ]; then
      echo "fetching $slug @ $sha"
      mkdir -p "$cache_root"
      git clone --quiet "$repo" "$cache"
      git -C "$cache" checkout --quiet --force "$sha"
    fi
    slugs+=("$slug")
  done <<<"$tier_repos"
  if [ ${#slugs[@]} -eq 0 ]; then
    echo "no corpus.toml entry carries tier '$tier'" >&2
    exit 1
  fi
else
  slugs=("$@")
fi

# Pinned repos bundle Gradle wrappers old enough to reject very new JDK
# class files; run them on 21 when one is installed.
java_major() {
  "$1/bin/java" -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+).*/\1/'
}
if [ -z "${JAVA_HOME:-}" ] || [ "$(java_major "${JAVA_HOME:-/nonexistent}")" -ge 22 ] 2>/dev/null; then
  for candidate in "$HOME/.sdkman/candidates/java/"*; do
    if [ -x "$candidate/bin/java" ] && [ "$(java_major "$candidate")" = "21" ]; then
      export JAVA_HOME="$candidate"
      export PATH="$candidate/bin:$PATH"
      break
    fi
  done
fi

tree_line='^[-+\\| ]*--- [a-zA-Z]'
# Coordinates WITH a version only: version-less lines are unresolvable by
# definition and would pollute the missing list.
coord_re='^[` +->]*[a-zA-Z0-9][a-zA-Z0-9._-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*:[a-zA-Z0-9][a-zA-Z0-9._-]+([@a-zA-Z0-9._-]*)?$'

# 3 (shared). Pull the ARTIFACTS (jars AND AARs) into the shared cache: a
# synthetic scratch build resolves every coordinate leniently, one detached
# configuration per coordinate, so one bad line never fails the batch and AAR
# variant matching never blocks the rest. No target-project build and no
# Android SDK needed. (Developer-side execution; see the threat-model note
# above.)
pull_artifacts() {
  local dir="$1" out="$2"
  local scratch="$dir/_resolve"
  mkdir -p "$scratch"
  cp "$out" "$scratch/coords.txt"
  cat >"$scratch/build.gradle.kts" <<'SCRATCH'
// Kotlin requires imports BEFORE any other statement: with this line under
// `plugins {}` the script failed to COMPILE, resolveAll never ran, and the
// `|| true` plus the `grep -E "downloaded"` filter swallowed it silently —
// so every repo warmed its coordinate list and downloaded NOTHING. That is
// the "no warm classpath" cause behind pinned repos measuring zero.
import org.gradle.api.attributes.Attribute
import org.gradle.api.artifacts.ResolvedDependency

plugins { base }
repositories { google(); mavenCentral() }

val coords = File(rootProject.projectDir, "coords.txt").readLines()
    .map { it.trim() }.filter { it.isNotEmpty() && it.split(":").size >= 3 }

// The RESOLVED transitive closure, printed so the caller can list it: the
// textual fallback arm extracts a build file's DIRECT declarations, and a
// direct-only classpath leaves the transitive tree (appcompat without
// fragment/core, ktor without kotlinx) unattached — InsecureShop's
// activities then degrade with MISSING_DEPENDENCY_SUPERCLASS and its
// finding floor measures zero against a warm-looking classpath (P14).
fun ResolvedDependency.walk(seen: MutableSet<String>) {
    val id = "$moduleGroup:$moduleName:$moduleVersion"
    if (seen.add(id)) children.forEach { it.walk(seen) }
}

tasks.register("resolveAll") { doLast {
    var ok = 0
    var failed = 0
    val androidJvm = Attribute.of("org.jetbrains.kotlin.platform.type", String::class.java)
    val libraryElements = Attribute.of("org.gradle.libraryelements", String::class.java)
    val category = Attribute.of("org.gradle.category", String::class.java)
    fun resolve(c: String, aar: Boolean) {
        val dep = configurations.detachedConfiguration(dependencies.create(c))
        dep.isTransitive = true
        if (aar) dep.attributes {
            attribute(androidJvm, "androidJvm")
            attribute(libraryElements, "aar")
            attribute(category, "library")
        }
        val seen = linkedSetOf<String>()
        dep.resolvedConfiguration.firstLevelModuleDependencies.forEach { it.walk(seen) }
        seen.forEach { println("resolved $it") }
    }
    for (c in coords) {
        try {
            resolve(c, aar = false); ok++
        } catch (t: Throwable) {
            // AndroidX multiplatform artifacts publish AAR variants a plain
            // JVM consumer cannot match; retry with AAR variant attributes.
            try {
                resolve(c, aar = true); ok++
            } catch (t2: Throwable) { failed++ }
        }
    }
    println("downloaded $ok, failed $failed")
} }
SCRATCH
  echo 'rootProject.name = "kosi-resolve-scratch"' >"$scratch/settings.gradle.kts"
  # The resolve is allowed to have per-coordinate failures — that is the
  # point of the detached configurations — but the TASK not running at all
  # is a warming failure, and it used to be indistinguishable from silence.
  local log="$scratch/resolve.log"
  (cd "$repo_root" && ./gradlew -p "$scratch" -q resolveAll --console=plain >"$log" 2>&1 || true)
  if grep -qE "^downloaded [1-9]" "$log"; then
    grep -E "^downloaded [0-9]+" "$log"
    # Merge the RESOLVED transitive closure into the coordinate list: a
    # direct-only list attaches only the direct jars (see the scratch
    # script's comment above).
    grep -E "^resolved " "$log" | sed -E 's/^resolved //' | sort -u >"$out.new"
    cat "$out" | grep -v "android-all.jar" >>"$out.new"
    sort -u "$out.new" -o "$out.new"
    mv "$out.new" "$out"
    echo "  coordinate list now $(wc -l <"$out" | tr -d ' ') entries (directs + resolved transitives)"
  else
    # `downloaded 0, failed 0` means the coordinate list itself was empty —
    # the report arm produced nothing and the warming did not happen. R73
    # let this pass with a WARNING; P14 fails it, because the vuln tier's
    # finding floors are measured against these classpaths.
    echo "  ERROR: artifact resolution downloaded nothing for $slug" >&2
    echo "  Last lines of $log:" >&2
    tail -5 "$log" >&2
    rm -rf "$scratch"
    exit 1
  fi
  rm -rf "$scratch"
}

# The TEXTUAL fallback (P14): old Android builds (AGP 3.x wants a JDK 8 no
# modern machine ships) and wrapper-less builds cannot run their dependency
# reports, and the declarations in their build files are still plain
# group:artifact:version literals — with the Kotlin version riding one
# variable. The scratch resolver above pulls each coordinate's TRANSITIVE
# closure into the cache, so the direct list is enough to warm a classpath
# kosi's locator can use.
textual_coordinates() {
  local dir="$1"
  local kotlin_ver
  # `|| true` inside the substitution: a project without an ext.kotlin_version
  # (every Kotlin DSL build) makes the grep fail, and under `set -e` an
  # assignment whose substitution fails kills the script before the
  # extraction arms even run (measured on the Ktor app).
  kotlin_ver=$(grep -rhoE "ext[.]kotlin_version *= *['\"][^'\"]+" "$dir" --include=build.gradle 2>/dev/null \
    | head -1 | sed -E "s/.*['\"]//" || true)
  find "$dir" \( -name '*.gradle' -o -name '*.gradle.kts' \) 2>/dev/null | LC_ALL=C sort | while read -r f; do
    # `|| true` per arm: a build file exercises one syntax or the other, and
    # under `set -e -o pipefail` the first non-matching grep would otherwise
    # kill the subshell before the other arm runs (measured: the Kotlin DSL
    # arm never executed for a .kts-only project).
    grep -hoE "(implementation|api|compile|classpath|testImplementation|androidTestImplementation)[[:space:]]+['\"][^'\"]+['\"]" "$f" 2>/dev/null \
      | sed -E "s/.*[[:space:]]['\"]//; s/['\"]\$//" || true
    grep -hoE "(implementation|api|testImplementation|androidTestImplementation)\(['\"][^'\"]+['\"]\)" "$f" 2>/dev/null \
      | sed -E "s/.*\(['\"]//; s/['\"]\)\$//" || true
  done | grep -vE 'project[(]|fileTree|files[(]' \
    | sed -E "s/[$][{]?kotlin_version[}]?/${kotlin_ver:-UNKNOWN}/" \
    | grep -E "$coord_re" || true
}

for slug in "${slugs[@]}"; do
  dir="$cache_root/$slug"
  if [ ! -d "$dir" ]; then
    echo "no cache for '$slug'; run the bench once to fetch it (kosi bench --tier <its tier>)" >&2
    exit 1
  fi
  out="$dir/classpath.txt"
  echo "warming $slug -> $out (JAVA_HOME=${JAVA_HOME:-default})"

  if [ -x "$dir/gradlew" ]; then
    # 1+2. Wrappered single/multi-project build: dependency reports per
    # project, default + test configurations.
    (cd "$dir" && ./gradlew -q projects --console=plain 2>/dev/null || true) \
      | { grep -oE "Project '(:[^']*)'" || true; } \
      | sed -E "s/Project '([^']*)'/\1/" \
      | sed 's/^$/:/' >"$dir/projects.txt"
    projects=()
    while IFS= read -r p; do projects+=("$p"); done <"$dir/projects.txt"
    [ ${#projects[@]} -eq 0 ] && projects=(":")
    : >"$out"
    for p in "${projects[@]}"; do
      for extra in "" "--configuration testCompileClasspath" "--configuration testRuntimeClasspath"; do
        (cd "$dir" && ./gradlew -q "$p:dependencies" $extra --console=plain 2>/dev/null || true) \
          | { grep -E "$tree_line" || true; } \
          | sed -E 's/^[-+\\| ]*--- //; s/ \(.*\)$//; s/ -> /:/g' \
          | { grep -E "$coord_re" || true; } \
          >>"$out" || true
      done
    done
    sort -u "$out" -o "$out"
    echo "$(wc -l <"$out" | tr -d ' ') coordinate(s)"
    rm -f "$dir/projects.txt"
  elif [ ! -f "$dir/settings.gradle.kts" ] && [ ! -f "$dir/settings.gradle" ]; then
    # A collection of independent builds (ktor-samples): warm each child
    # project that has its own build file, merging one coordinates file.
    : >"$out"
    for child in "$dir"/*/; do
      if [ -f "$child/build.gradle.kts" ] || [ -f "$child/build.gradle" ]; then
        (cd "$repo_root" && ./gradlew -p "$child" -q --continue dependencies \
            --console=plain 2>/dev/null || true) \
          | { grep -E "$tree_line" || true; } \
          | sed -E 's/^[-+\\| ]*--- //; s/ \(.*\)$//; s/ -> /:/g' \
          | { grep -E "$coord_re" || true; } \
          >>"$out" || true
      fi
    done
    sort -u "$out" -o "$out"
    echo "$(wc -l <"$out" | tr -d ' ') coordinate(s)"
  else
    # Wrapper-less single build (none of the pinned repos hit this today).
    : >"$out"
    (cd "$dir" && "$repo_root/gradlew" -p "$dir" -q projects --console=plain 2>/dev/null || true) \
      | { grep -oE "Project '(:[^']*)'" || true; } \
      | sed -E "s/Project '([^']*)'/\1/" \
      | sed 's/^$/:/' >"$dir/projects.txt"
    projects=()
    while IFS= read -r p; do projects+=("$p"); done <"$dir/projects.txt"
    [ ${#projects[@]} -eq 0 ] && projects=(":")
    for p in "${projects[@]}"; do
      (cd "$dir" && "$repo_root/gradlew" -p "$dir" -q "$p:dependencies" --console=plain 2>/dev/null || true) \
        | { grep -E "$tree_line" || true; } \
        | sed -E 's/^[-+\\| ]*--- //; s/ \(.*\)$//; s/ -> /:/g' \
        | { grep -E "$coord_re" || true; } \
        >>"$out" || true
    done
    sort -u "$out" -o "$out"
    echo "$(wc -l <"$out" | tr -d ' ') coordinate(s)"
    rm -f "$dir/projects.txt"
  fi

  # The report arms above run the project's own build tooling; old Android
  # and wrapper-less builds cannot (P14), and their declarations are still
  # plain literals — so an empty list falls back to reading them as text
  # (kosi's own philosophy for build files: parse, never execute).
  if [ ! -s "$out" ]; then
    echo "  dependency report produced nothing; falling back to textual extraction" >&2
    textual_coordinates "$dir" | sort -u >"$out"
    echo "$(wc -l <"$out" | tr -d ' ') coordinate(s) (textual)"
  fi
  if [ ! -s "$out" ]; then
    echo "  ERROR: $slug produced no coordinates from either arm — the finding" >&2
    echo "  floors would measure against an empty classpath" >&2
    exit 1
  fi

  pull_artifacts "$dir" "$out"

  # Android framework classes (android.*): AndroidX/Android code extends and
  # calls them; without them every Android repo resolves as broken. The
  # Robolectric android-all jar is the full framework on Maven Central.
  framework_jar="$cache_root/android-all.jar"
  if [ ! -s "$framework_jar" ]; then
    curl -sL --max-time 300 -o "$framework_jar.part" \
      "https://repo1.maven.org/maven2/org/robolectric/android-all/14-robolectric-10818077/android-all-14-robolectric-10818077.jar" \
      && mv "$framework_jar.part" "$framework_jar" || rm -f "$framework_jar.part"
  fi
  if [ -s "$framework_jar" ]; then
    echo "$framework_jar" >>"$out"
    sort -u "$out" -o "$out"
  fi
done
echo "done"
