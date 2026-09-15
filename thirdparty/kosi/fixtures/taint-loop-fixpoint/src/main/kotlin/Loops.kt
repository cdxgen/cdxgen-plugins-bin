// Negative half first: the same loop shape over clean parts reports nothing.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanLoop
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the taint is deposited into `carried` at the END of the loop
// body and read by the sink at the TOP. A single linear pass sees the sink
// with a clean `carried` and misses the flow; the worklist must re-run the
// body from the back-edge join before the sink is tainted (rusi's fixed
// iteration cap silently lost exactly this shape, which is why a cap that is
// hit is a diagnostic and 0 hits is a gate). The marker is scoped to the
// syntax tier, which still has no flow engine (docs/KOSI.md defect 1).
// kosi:want flow source=untrusted-input sink=process-exec fn=~twoRotations known-fail=syntax:1
package fixtures.loops

fun twoRotations() {
    val line = readLine() ?: return
    var carried = ""
    for (part in line.split(",")) {
        ProcessBuilder(carried)
        carried = part
    }
}

fun cleanLoop() {
    var carried = ""
    for (part in listOf("a", "b")) {
        ProcessBuilder(carried)
        carried = part
    }
}
