// Dispatch decides which summaries a call site JOINS. ExecTask sinks;
// LogTask does not. Each call site constructs its receiver IN PLACE, so the
// site's receiver type is known by construction: under the default modes
// (rta/vta) execLog's site narrows to LogTask.run's summary and must NOT
// report, while execExec's site narrows to ExecTask.run and must. Under
// `cha` no narrowing happens and execLog over-approximates to a slice —
// that mode difference is pinned at engine level by TaintEngineTest (the
// corpus slots run the default mode). A dispatch site that only sees the
// receiver as a FUNCTION PARAMETER cannot narrow context-insensitively and
// joins both; that limit is shared with the P3 graph and stays named.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~execLog known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~execExec known-fail=syntax:1
package fixtures.summary.virtual

interface Task {
    fun run(command: String)
}

class LogTask : Task {
    override fun run(command: String) {
        println(command.length)
    }
}

class ExecTask : Task {
    override fun run(command: String) {
        ProcessBuilder(command)
    }
}

fun execExec() {
    val task: Task = ExecTask()
    task.run(readLine() ?: "")
}

fun execLog() {
    val task: Task = LogTask()
    task.run(readLine() ?: "")
}
