// ktor-http 3.x by shape: HttpMethod's verbs are companion properties.
package io.ktor.http

class HttpMethod(val value: String) {
    companion object {
        val Get = HttpMethod("GET")
        val Post = HttpMethod("POST")
        val Put = HttpMethod("PUT")
        val Patch = HttpMethod("PATCH")
        val Delete = HttpMethod("DELETE")
        val Head = HttpMethod("HEAD")
        val Options = HttpMethod("OPTIONS")
    }
}
