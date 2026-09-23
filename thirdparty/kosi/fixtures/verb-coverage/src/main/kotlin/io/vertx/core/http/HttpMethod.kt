// vertx-core by shape: HttpMethod's verbs are static fields.
package io.vertx.core.http

class HttpMethod(val name: String) {
    companion object {
        @JvmField val GET = HttpMethod("GET")
        @JvmField val POST = HttpMethod("POST")
    }
}
