// Higher-order: the callee invokes a function-valued parameter; the taint
// travels through the lambda's CAPTURE into the sink inside the extracted
// body. The negative half is the clean lambda: the same callee, the same
// sink shape, no captured taint — "anything inside a lambda is tainted"
// fails here.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~execClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~execCaptured known-fail=syntax:1
package fixtures.summary.higherorder

fun withBlock(block: (String) -> Unit) {
    block("safe")
}

fun execCaptured() {
    val raw = readLine() ?: ""
    withBlock { marker ->
        ProcessBuilder(marker + raw)
    }
}

fun execClean() {
    withBlock { marker ->
        ProcessBuilder(marker)
    }
}
