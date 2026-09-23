// ktor-http 1.6 by shape: the verbs are companion properties.
package io.ktor.http

class HttpMethod(val value: String) {
    companion object {
        val Get = HttpMethod("GET")
        val Post = HttpMethod("POST")
    }
}
