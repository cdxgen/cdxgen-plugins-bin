package io.ktor.server.routing

class Route

fun Route.get(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.post(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.route(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.routing(block: Route.() -> Unit): Unit = Unit
