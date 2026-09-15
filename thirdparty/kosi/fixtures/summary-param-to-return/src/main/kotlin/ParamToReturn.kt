// The plain param-to-return case: the callee returns its parameter (through
// a pack passthrough, `plus`), and the caller sinks the result. This is the
// shape command-exec and old-language-version were fixture-patched around in
// P4 (deviation 1) — here it is as a summary, properly scoped.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~execConstant known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~execWrapped known-fail=syntax:1
package fixtures.summary.paramtoreturn

fun wrap(raw: String): String = "cmd=" + raw

fun constant(raw: String): String = "cmd=clean"

fun execWrapped() {
    val raw = readLine() ?: ""
    ProcessBuilder(wrap(raw))
}

// The callee DROPS its parameter; a summary that says "every parameter
// reaches the return" reports here and is wrong.
fun execConstant() {
    val raw = readLine() ?: ""
    ProcessBuilder(constant(raw))
}
