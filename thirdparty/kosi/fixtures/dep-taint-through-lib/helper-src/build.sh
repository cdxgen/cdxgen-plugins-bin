#!/usr/bin/env bash
# Rebuilds libs/dep-helper.jar from this directory. The jar is COMMITTED, so
# this script runs only when the helper's source changes; it needs nothing
# but a JDK and five jars from kosi's own Gradle build cache — no network,
# no Gradle execution of any project. Resolve them once:
#
#   KOSI_KOTLINC_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-compiler-embeddable -name 'kotlin-compiler-embeddable-2.4.10.jar' | head -1)
#   KOSI_STDLIB_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib -name 'kotlin-stdlib-2.4.0.jar' | head -1)
#   KOSI_REFLECT_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-reflect/2.4.0 -name '*.jar' | head -1)
#   KOSI_COROUTINES_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.10.1 -name '*.jar' | head -1)
#   KOSI_ANNOTATIONS_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains/annotations/13.0 -name '*.jar' | head -1)
#   ./helper-src/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for v in KOSI_KOTLINC_JAR KOSI_STDLIB_JAR KOSI_REFLECT_JAR KOSI_COROUTINES_JAR KOSI_ANNOTATIONS_JAR; do
  test -n "${!v:-}" || { echo "set $v (see the header of this script)" >&2; exit 2; }
done
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
java -cp "$KOSI_STDLIB_JAR:$KOSI_REFLECT_JAR:$KOSI_COROUTINES_JAR:$KOSI_ANNOTATIONS_JAR:$KOSI_KOTLINC_JAR" \
  org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -classpath "$KOSI_STDLIB_JAR" \
  -jvm-target 21 -nowarn \
  -d "$OUT" "$HERE"/*.kt 2>&1 | grep -vE "WARNING|warning:" || true
test -f "$OUT/dev/kosi/helper/Db.class"
mkdir -p "$HERE/../libs"
jar --create --file "$HERE/../libs/dep-helper.jar" -C "$OUT" .
echo "wrote $HERE/../libs/dep-helper.jar"
