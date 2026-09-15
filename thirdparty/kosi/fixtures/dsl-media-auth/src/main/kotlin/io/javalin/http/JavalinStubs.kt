// Minimal Javalin surface: the route builder's vararg RouteRole tail is the
// auth requirement; the handler sits BEFORE the roles.
package io.javalin

import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.security.RouteRole

class Javalin {
    fun get(path: String, handler: Handler, vararg roles: RouteRole): Javalin = this
    fun post(path: String, handler: Handler, vararg roles: RouteRole): Javalin = this
}
