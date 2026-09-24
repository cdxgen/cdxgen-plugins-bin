package io.javalin.http

class Context {
    fun result(text: String): Context = this
}

fun interface Handler {
    fun handle(ctx: Context)
}
