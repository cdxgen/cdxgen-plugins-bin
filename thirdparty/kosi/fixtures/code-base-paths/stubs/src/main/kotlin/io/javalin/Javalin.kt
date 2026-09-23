// javalin by shape, both generations of the context path: 3.x/4.x
// `config.contextPath`, 6.x `config.router.contextPath`.
package io.javalin

import io.javalin.config.JavalinConfig
import io.javalin.http.Handler

class Javalin {
    fun get(path: String, handler: Handler): Javalin = this
    fun post(path: String, handler: Handler): Javalin = this

    companion object {
        @JvmStatic fun create(config: (JavalinConfig) -> Unit): Javalin = Javalin()
    }
}
