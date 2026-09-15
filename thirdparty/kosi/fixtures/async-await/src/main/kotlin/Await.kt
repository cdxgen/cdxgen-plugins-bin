// async { t }.await() is a passthrough from the lambda's value to the await
// result. Negative half: the async body produces a clean value.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~awaitClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~awaitSink known-fail=syntax:1
package fixtures.async.await

import kotlinx.coroutines.*

fun awaitSink() {
    runBlocking {
        val raw = readLine() ?: ""
        val deferred = async { raw }
        ProcessBuilder(deferred.await())
    }
}

fun awaitClean() {
    runBlocking {
        val deferred = async { "safe" }
        ProcessBuilder(deferred.await())
    }
}
