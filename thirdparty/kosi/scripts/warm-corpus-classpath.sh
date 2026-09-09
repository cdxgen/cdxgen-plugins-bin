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
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="$repo_root/.corpus-cache"

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
plugins { base }
repositories { google(); mavenCentral() }
import org.gradle.api.attributes.Attribute

val coords = File(rootProject.projectDir, "coords.txt").readLines()
    .map { it.trim() }.filter { it.isNotEmpty() && it.split(":").size >= 3 }
tasks.register("resolveAll") { doLast {
    var ok = 0
    var failed = 0
    val androidJvm = Attribute.of("org.jetbrains.kotlin.platform.type", String::class.java)
    val libraryElements = Attribute.of("org.gradle.libraryelements", String::class.java)
    val category = Attribute.of("org.gradle.category", String::class.java)
    for (c in coords) {
        val dep = configurations.detachedConfiguration(dependencies.create(c))
        dep.isTransitive = true
        try {
            dep.files; ok++
        } catch (t: Throwable) {
            // AndroidX multiplatform artifacts publish AAR variants a plain
            // JVM consumer cannot match; retry with AAR variant attributes.
            try {
                val dep2 = configurations.detachedConfiguration(dependencies.create(c))
                dep2.isTransitive = true
                dep2.attributes {
                    attribute(androidJvm, "androidJvm")
                    attribute(libraryElements, "aar")
                    attribute(category, "library")
                }
                dep2.files
                ok++
            } catch (t2: Throwable) { failed++ }
        }
    }
    println("downloaded $ok, failed $failed")
} }
SCRATCH
  echo 'rootProject.name = "kosi-resolve-scratch"' >"$scratch/settings.gradle.kts"
  (cd "$repo_root" && ./gradlew -p "$scratch" -q resolveAll --console=plain 2>&1 | { grep -E "downloaded" || true; } || true)
  rm -rf "$scratch"
}

for slug in "${@:?usage: warm-corpus-classpath.sh <slug> [more slugs...]}"; do
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
