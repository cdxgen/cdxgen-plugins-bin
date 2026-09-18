// Ktor 1.x's websocket route builder at its 1.x package.
package io.ktor.websocket

import io.ktor.routing.Route1

fun Route1.webSocket(path: String, body: suspend Route1.() -> Unit): Unit = Unit
