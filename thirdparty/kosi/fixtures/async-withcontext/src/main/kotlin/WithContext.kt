// Taint crossing withContext(Dispatchers.IO) {}: the dispatcher moves the
// execution, not the data. Negative half: a clean value crosses the same
// boundary.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~contextClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~contextSink known-fail=syntax:1
package fixtures.async.withcontext

import kotlinx.coroutines.*

fun contextSink() {
    runBlocking {
        val raw = readLine() ?: ""
        withContext(Dispatchers.IO) {
            ProcessBuilder(raw)
        }
    }
}

fun contextClean() {
    runBlocking {
        withContext(Dispatchers.IO) {
            ProcessBuilder("safe")
        }
    }
}
