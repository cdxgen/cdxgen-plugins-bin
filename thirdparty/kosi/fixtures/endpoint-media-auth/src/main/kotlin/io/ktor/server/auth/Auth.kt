// Ktor's authentication wrapper: a nesting DSL call. The routes inside
// `authenticate("basic") { .. }` require the named provider — collects
// it from the enclosing call chain, the same links the route prefixes use.
package io.ktor.server.auth

import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext

class AuthenticationProvider

fun Route.authenticate(
    provider: String? = null,
    build: suspend RoutingContext.() -> Unit,
): Unit = Unit
