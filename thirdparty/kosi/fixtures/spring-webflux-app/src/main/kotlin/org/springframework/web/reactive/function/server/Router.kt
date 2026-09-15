package org.springframework.web.reactive.function.server

class ServerRequest
class ServerResponse

class RouterFunctionDsl {
    fun GET(path: String, body: (ServerRequest) -> ServerResponse): Unit = Unit
    fun POST(path: String, body: (ServerRequest) -> ServerResponse): Unit = Unit
    fun path(prefix: String, block: RouterFunctionDsl.() -> Unit): Unit = Unit
}

fun coRouter(block: RouterFunctionDsl.() -> Unit): Unit = Unit
