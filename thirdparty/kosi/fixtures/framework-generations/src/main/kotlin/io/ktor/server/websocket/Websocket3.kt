// Ktor 3's websocket route builder at the 3.x package.
package io.ktor.server.websocket

import io.ktor.server.routing.Route

fun Route.webSocket(path: String, body: suspend io.ktor.server.routing.RoutingContext.() -> Unit): Unit = Unit
