// MutableStateFlow(tainted) observed by collect: the constructor's argument
// is the state, and every collector sees it. Negative half: a clean state.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~stateClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~stateSink known-fail=syntax:1
package fixtures.async.stateflow

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

fun stateSink() {
    runBlocking {
        val state = MutableStateFlow(readLine() ?: "")
        state.collect { value ->
            ProcessBuilder(value)
        }
    }
}

fun stateClean() {
    runBlocking {
        val state = MutableStateFlow("safe")
        state.collect { value ->
            ProcessBuilder(value)
        }
    }
}
