package io.ktor.server.routing

class Route

fun Route.get(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit

class RoutingContext
