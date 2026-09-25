// javalin 6.x by shape: the verb methods take a path and a Handler.
package io.javalin

import io.javalin.http.Handler

class Javalin {
    fun get(path: String, handler: Handler): Javalin = this
    fun post(path: String, handler: Handler): Javalin = this

    companion object {
        fun create(): Javalin = Javalin()
    }
}
