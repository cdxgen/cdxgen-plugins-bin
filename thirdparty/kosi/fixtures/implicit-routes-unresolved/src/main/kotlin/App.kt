// No handler, no repository, no actuator anywhere: this fixture pins the
// dependency-marker contract from both sides.
//
//  - The PRESENT marker is bound to a committed jar whose file name does
//    not contain the marker, so only the COORDINATE arm of the marker set
//    can publish its tree. That arm rendered the literal string
//    `${it.group}:${it.artifact}` since — dead, and invisible because
//    every Gradle-cache jar's file name carries the artifact name anyway.
//  - The ABSENT marker (actuator at a version no cache holds) must publish
//    nothing: the resolver's missing[] list was fed into the marker set,
//    which concluded presence from absence — how implicit-routes' wants
//    kept passing on machines whose cache was cold.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The absent coordinate is named loudly — a pin that resolves nothing must
// be visible, not silent (the empty-classpath contract).
// kosi:want diagnostic code=classpath-partial known-fail=syntax:2
//
// The present marker's tree, published through the coordinate arm only.
// kosi:want endpoint framework=springdoc path=/v3/api-docs mode=resolved
//
// The absent marker's tree, published nowhere.
// kosi:want-not endpoint framework=spring-actuator path=/actuator/health
// kosi:want-not endpoint framework=spring-actuator path=/ops/health
package fixtures.implicitroutesunresolved

fun main() {
    println("no routes here")
}
