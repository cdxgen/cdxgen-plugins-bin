// javalin 6 by shape: the app's verb builders.
package io.javalin

fun interface Handler {
    fun handle(ctx: Any)
}

class Javalin {
    fun head(path: String, handler: Handler): Javalin = this
    fun options(path: String, handler: Handler): Javalin = this
}
