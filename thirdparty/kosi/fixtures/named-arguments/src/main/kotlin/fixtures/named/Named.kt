// Named and reordered arguments — the position a value ends up in.
//
// Kotlin lets a call name its arguments and write them in any order. The
// lowering emitted them in SOURCE order, so `run(second = "b", third = raw,
// first = "a")` put the tainted value on the callee's `second` while the sink
// reads `third`. That is not one defect but two, and this fixture pins both
// halves, because the same mis-binding that LOSES a flow FABRICATES one when
// the positions happen to line up the other way:
//
//   - `viaNamedReordered` is the miss: the taint really does reach the sink,
//     and source order bound it to a parameter the callee never sinks.
//   - `viaNamedElsewhere` is the false positive: the taint goes to a
//     parameter the callee IGNORES, and source order put it in the sunk
//     position. It reported before the fix. A want-not has no `known-fail`
//     protection by design, so if this line ever reports again the engine has
//     a false positive, not the fixture a problem.
//
// Defaults matter for the same reason: an omitted middle parameter shifts
// every parameter after it, so the call site pads the position rather than
// closing the gap.
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaNamedReordered known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDefaultSkipped known-fail=syntax:1
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaNamedElsewhere
// kosi:want-not diagnostic code=parse-error
package fixtures.named

private fun run3(first: String, second: String, third: String) {
    Runtime.getRuntime().exec(third)
}

private fun withDefault(first: String = "a", second: String = "b", third: String) {
    Runtime.getRuntime().exec(third)
}

fun viaNamedReordered() {
    val raw = readLine() ?: ""
    run3(second = "b", third = raw, first = "a")
}

// The negative: the taint is named onto `second`, which nothing sinks — but
// it is WRITTEN third, so source order put it exactly where `third` goes and
// the engine reported a flow that does not exist.
fun viaNamedElsewhere() {
    val raw = readLine() ?: ""
    run3(third = "c", first = "a", second = raw)
}

// Both leading parameters take their defaults; the written argument is the
// LAST parameter, and it has to land there rather than in position 0.
fun viaDefaultSkipped() {
    val raw = readLine() ?: ""
    withDefault(third = raw)
}
