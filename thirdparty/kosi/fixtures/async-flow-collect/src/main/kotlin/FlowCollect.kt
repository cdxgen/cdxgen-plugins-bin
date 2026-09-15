// The P6 gate's named case: taint survives flow { emit(t) } .map { } .collect { }.
// Negatives first: the clean chain reports nothing, and a SANITIZING map
// body sanitizes everything downstream of it.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~flowClean known-fail=syntax:1
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~flowSanitized known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~flowSink known-fail=syntax:1
package fixtures.async.flowcollect

import kotlinx.coroutines.flow.*

fun flowSink() {
    val raw = readLine() ?: ""
    flow { emit(raw) }
        .map { it }
        .collect { value ->
            ProcessBuilder(value)
        }
}

fun flowClean() {
    flow { emit("safe") }
        .map { it }
        .collect { value ->
            ProcessBuilder(value)
        }
}

fun flowSanitized() {
    val raw = readLine() ?: ""
    flow { emit(raw) }
        .map { value -> sanitize(value) }
        .collect { value ->
            ProcessBuilder(value)
        }
}

// The pack's sanitizer entry (MessageDigest.digest clears untrusted-input);
// the map body routes the element through it, so everything downstream of
// the operator sees the sanitized value.
private fun sanitize(raw: String): String =
    java.security.MessageDigest.getInstance("SHA-256").digest(raw.toByteArray()).contentToString()
