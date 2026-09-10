// Negative half first: identical scope-function shapes over clean values.
// A receiver rule that taints "whatever a scope function touches" fails
// these; only the receivers that actually hold taint may flow.
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~letClean
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~applyClean
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~withClean
// kosi:want-not diagnostic code=parse-error
//
// Positive half: let carries its receiver into the lambda parameter;
// apply/with make the receiver's TAINTED FIELD visible as `this` members.
// Both positives carry the syntax-tier flow marker (docs/KOSI.md defect 1).
// kosi:want flow source=untrusted-input sink=log-injection count=2 known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~withCarries known-fail=syntax:1
package fixtures.scopes

class Job {
    var command: String = ""
    var label: String = "build"
}

fun letCarries() {
    val input = readLine() ?: return
    input.let { println("cmd=$it") }
}

fun letClean() {
    val flag = "build"
    flag.let { println("flag=$it") }
}

fun applyCarries(): Job {
    val job = Job()
    job.command = readLine() ?: ""
    return job.apply { println("dispatch ${command}") }
}

fun applyClean(): Job {
    val job = Job()
    return job.apply { println("label ${label}") }
}

fun withCarries() {
    val job = Job()
    job.command = readLine() ?: ""
    with(job) { ProcessBuilder(command) }
}

fun withClean() {
    val job = Job()
    with(job) { ProcessBuilder(label) }
}
