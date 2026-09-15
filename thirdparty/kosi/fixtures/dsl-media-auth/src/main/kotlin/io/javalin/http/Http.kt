package io.javalin.http

fun interface Handler {
    fun handle(ctx: Context)
}

class Context {
    fun pathParam(name: String): String = ""
    fun queryParam(name: String): String = ""
}
