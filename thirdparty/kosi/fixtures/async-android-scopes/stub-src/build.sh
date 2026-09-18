#!/usr/bin/env bash
# Rebuilds libs/androidx-scope-stubs.jar from this directory (the
# dep-taint-through-lib/helper-src pattern). The jar is COMMITTED, so this
# runs only when the stubs change; it needs nothing but a JDK and three
# jars from kosi's own Gradle build cache — no network, no Gradle execution:
#
#   KOSI_KOTLINC_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-compiler-embeddable -name 'kotlin-compiler-embeddable-2.4.10.jar' | head -1)
#   KOSI_STDLIB_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.4.0 -name 'kotlin-stdlib-2.4.0.jar' | head -1)
#   KOSI_REFLECT_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-reflect/2.4.0 -name '*.jar' | head -1)
#   KOSI_ANNOTATIONS_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.jetbrains/annotations -name '*.jar' | head -1)
#   KOSI_COROUTINES_JAR=../shared-libs/kotlinx-coroutines-core-jvm-1.8.0.jar
#   ./stub-src/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for v in KOSI_KOTLINC_JAR KOSI_STDLIB_JAR KOSI_REFLECT_JAR KOSI_ANNOTATIONS_JAR KOSI_COROUTINES_JAR; do
  test -n "${!v:-}" || { echo "set $v (see the header of this script)" >&2; exit 2; }
done
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
java -cp "$KOSI_STDLIB_JAR:$KOSI_REFLECT_JAR:$KOSI_ANNOTATIONS_JAR:$KOSI_COROUTINES_JAR:$KOSI_KOTLINC_JAR" \
  org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -classpath "$KOSI_STDLIB_JAR:$KOSI_COROUTINES_JAR" \
  -jvm-target 21 -nowarn \
  -d "$OUT" "$HERE" 2>&1 | grep -vE "WARNING|warning:" || true
test -f "$OUT/androidx/lifecycle/LifecycleStubsKt.class"
mkdir -p "$HERE/../libs"
jar --create --file "$HERE/../libs/androidx-scope-stubs.jar" -C "$OUT" .
echo "wrote $HERE/../libs/androidx-scope-stubs.jar"
