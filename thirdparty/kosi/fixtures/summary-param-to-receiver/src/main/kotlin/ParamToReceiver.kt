// The param-to-RECEIVER effect case: the callee stores a parameter's taint
// into ITS OWN RECEIVER (a member), field-sensitively. The negative half
// writes a different member — and the caller sinks only the untouched one.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~execLabelStage known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~execCommandStage known-fail=syntax:1
package fixtures.summary.paramtoreceiver

class Job {
    var command: String = ""
    var label: String = "build"

    fun stageCommand(raw: String) {
        command = raw
    }

    fun stageLabel(raw: String) {
        label = raw
    }
}

fun execCommandStage() {
    val job = Job()
    job.stageCommand(readLine() ?: "")
    ProcessBuilder(job.command)
}

fun execLabelStage() {
    val job = Job()
    job.stageLabel(readLine() ?: "")
    ProcessBuilder(job.command)
}
