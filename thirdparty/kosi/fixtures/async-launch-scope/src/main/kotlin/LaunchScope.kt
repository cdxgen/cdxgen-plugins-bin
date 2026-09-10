// Taint captured by a launch {} body that sinks it. Negative half: the
// lambda sinks something else (a clean capture).
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~launchClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~launchSink known-fail=syntax:1
package fixtures.async.launch

import kotlinx.coroutines.*

fun launchSink() {
    runBlocking {
        val raw = readLine() ?: ""
        launch {
            ProcessBuilder(raw)
        }
    }
}

fun launchClean() {
    runBlocking {
        val name = "safe"
        launch {
            ProcessBuilder(name)
        }
    }
}
