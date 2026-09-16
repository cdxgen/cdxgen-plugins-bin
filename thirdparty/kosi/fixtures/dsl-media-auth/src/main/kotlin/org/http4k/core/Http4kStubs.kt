// Minimal http4k core surface for the honest-empty half: `"/path" bind
// GET to { .. }` has NO media or auth declaration site — the pack's own
// comment says so, and this fixture pins that the empties are real.
package org.http4k.core

object Method {
    val GET = "GET"
    val POST = "POST"
}

class Request private constructor(val uri: String) {
    companion object {
        fun get(uri: String): Request = Request(uri)
    }
    fun query(name: String): String? = null
}

class Response private constructor(val status: Int, val body: String) {
    companion object {
        fun ok(body: String): Response = Response(200, body)
    }
}

fun interface HttpHandler {
    fun invoke(request: Request): Response
}

