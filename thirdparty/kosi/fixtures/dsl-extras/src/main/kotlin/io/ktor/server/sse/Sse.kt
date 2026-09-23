package io.ktor.server.sse

import io.ktor.server.routing.Route

class ServerSSESession
fun Route.sse(path: String, handler: suspend ServerSSESession.() -> Unit) {}
