package io.ktor.server.routing

import io.ktor.server.application.ApplicationCall

class Route {
    val call: ApplicationCall get() = throw UnsupportedOperationException()
}

fun Route.get(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.post(path: String, body: Route.() -> Unit): Unit = Unit
/** The pathless verb builder: the route's path is the enclosing prefix. */
fun Route.get(body: Route.() -> Unit): Unit = Unit
fun Route.route(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.routing(block: Route.() -> Unit): Unit = Unit
