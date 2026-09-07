// Negative half first.
// kosi:want-not usage name=runBlocking
// kosi:want-not diagnostic code=parse-error
//
// Positive half: suspend functions and structured concurrency calls must be
// visible as usage evidence even before resolution exists.
// kosi:want declaration name=fetch kind=function
// kosi:want declaration name=main kind=function
// kosi:want usage name=withContext
// kosi:want usage name=~.launch
// kosi:want usage name=~.async
package fixtures.pipeline

import kotlinx.coroutines.withContext

suspend fun fetch(url: String): String = withContext(kotlinx.coroutines.Dispatchers.IO) {
    "body-of-$url"
}

fun main(scope: kotlinx.coroutines.CoroutineScope) {
    scope.launch { fetch("https://example.invalid") }
    scope.async { fetch("https://example.invalid/2") }
}
