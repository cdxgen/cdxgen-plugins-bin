// — the same helper called twice.
//
// Summaries are bottom-up and CONTEXT-INSENSITIVE (k=0): one summary per
// function, joined over every call site. The question this fixture asks, at
// depth rather than in one frame, is what that costs: a helper that reaches
// a sink is called three ways — with untrusted input, with a constant, and
// with a sanitized value — and exactly ONE finding is correct.
//
// A k=0 engine gets this right when the taint state at each call site is
// what decides, and wrong when the summary itself has to remember which
// caller it was computed for. The measurement, not the assumption, is what
// records.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~entryConstant
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~entrySanitized
// kosi:want flow source=untrusted-input sink=log-injection fn=~entryTainted known-fail=syntax:1
package fixtures.context

import java.util.UUID

// The shared helper: three callers, one summary.
private fun render(message: String) {
    println("audit: " + message)
}

private fun relay(message: String) = render(message)

private fun sanitize(raw: String): String = UUID.fromString(raw.trim()).toString()

fun entryTainted() {
    val raw = readLine() ?: ""
    relay(raw)
}

fun entryConstant() {
    relay("a fixed audit line")
}

fun entrySanitized() {
    val raw = readLine() ?: ""
    relay(sanitize(raw))
}
