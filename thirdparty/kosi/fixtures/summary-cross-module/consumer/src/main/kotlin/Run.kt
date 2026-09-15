// The SINK lives in the consumer module: the slice's two ends sit in
// different modules (crossesModule) with different purls
// (crossesDependency) — this fixture is what makes the P5
// `dependency-crossing-flows` gate a real count instead of
// NOT_EVALUATED (R55's zero becomes a measured nonzero).
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec known-fail=syntax:1
package fixtures.summary.crossmodule.consumer

import fixtures.summary.crossmodule.producer.rawInput

fun run(raw: String) {
    ProcessBuilder(raw)
}

fun main() {
    run(rawInput())
}
