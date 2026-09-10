// A mutually recursive pair carrying taint to a sink. The SCC fixpoint must
// CONVERGE (recursion is convergence, not a bail-out), report the flow, and
// hit no cap — the fixpoint-cap gate reads this fixture.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~runClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~runDeep known-fail=syntax:1
package fixtures.summary.recursive

fun ping(depth: Int, raw: String) {
    if (depth > 0) {
        pong(depth - 1, raw)
    } else {
        ProcessBuilder(raw)
    }
}

fun pong(depth: Int, raw: String) {
    ping(depth, raw)
}

fun runDeep() {
    ping(3, readLine() ?: "")
}

fun runClean() {
    ping(3, "safe")
}
