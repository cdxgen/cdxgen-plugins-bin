// The INTERPROCEDURAL clean-sibling negative (P5) — the engine-level twin of
// P4's field-sensitivity fixture, written before any positive summary code.
// A partly-tainted OBJECT crosses a call boundary; one callee sinks the
// TAINTED field (the slice), the other sinks the CLEAN SIBLING field and
// must stay silent. An engine that collapses access paths at the boundary
// (or taints "whatever object the callee touched") reports on the negative
// and fails. Proven at engine level by
// TaintEngineTest.anInterproceduralCleanSiblingStaysClean, which reruns this
// shape with access paths collapsed and demands the slice appear.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~runLabel known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~runCommand known-fail=syntax:1
package fixtures.summary.cleansibling

class Job {
    var command: String = ""
    var label: String = "build"
}

fun sinkCommand(job: Job) {
    ProcessBuilder(job.command)
}

fun sinkLabel(job: Job) {
    ProcessBuilder(job.label)
}

fun runCommand() {
    val job = Job()
    job.command = readLine() ?: ""
    sinkCommand(job)
}

// The same tainted object crosses to a callee that reads the CLEAN sibling.
fun runLabel() {
    val job = Job()
    job.command = readLine() ?: ""
    sinkLabel(job)
}
