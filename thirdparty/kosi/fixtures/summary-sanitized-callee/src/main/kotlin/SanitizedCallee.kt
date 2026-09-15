// Negative half first: taint crosses a callee that SANITIZES it, and the
// sanitized result reaches the sink — nothing may report. A summary engine
// that propagates "whatever the callee returns" without executing the
// callee's own sanitizer entry fails this.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~runSanitized known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the SAME call shape through a callee that only PASSES the
// value through — the flow is real.
// kosi:want flow source=untrusted-input sink=process-exec fn=~runPassthrough known-fail=syntax:1
package fixtures.summary.sanitized

import java.security.MessageDigest

// The pack's sanitizer entry (MessageDigest.digest clears untrusted-input)
// fires INSIDE this callee; the summary must respect it.
fun sanitize(raw: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
    return digest.contentToString()
}

// `plus` is a pack passthrough; the summary carries the parameter's taint
// to the return.
fun passthrough(raw: String): String = raw + "!"

fun runSanitized() {
    val raw = readLine() ?: ""
    ProcessBuilder(sanitize(raw))
}

fun runPassthrough() {
    val raw = readLine() ?: ""
    ProcessBuilder(passthrough(raw))
}
