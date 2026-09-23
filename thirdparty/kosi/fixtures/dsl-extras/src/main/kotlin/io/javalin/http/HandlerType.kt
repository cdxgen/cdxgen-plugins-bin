package io.javalin.http

enum class HandlerType { GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS }

fun interface Handler {
    fun handle(ctx: Any)
}
