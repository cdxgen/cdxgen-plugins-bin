package io.javalin.http

class Context
fun interface Handler {
    fun handle(ctx: Context)
}
