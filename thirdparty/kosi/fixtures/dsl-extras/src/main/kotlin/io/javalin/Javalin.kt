package io.javalin

import io.javalin.http.Handler
import io.javalin.http.HandlerType

class Javalin {
    fun ws(path: String, ws: (Any) -> Unit): Javalin = this
    fun sse(path: String, client: (Any) -> Unit): Javalin = this
    fun addHttpHandler(type: HandlerType, path: String, handler: Handler): Javalin = this
}
