package io.vertx.core.http

class HttpMethod(val name: String) {
    companion object {
        @JvmField val POST = HttpMethod("POST")
    }
}
