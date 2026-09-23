// ktor-server-core 3.x by shape (RoutingBuilder.kt / Routing.kt): route
// with and without a method, the method selector, handle, the verbs.
package io.ktor.server.routing

import io.ktor.http.HttpMethod
import io.ktor.server.application.Application

open class Route
class Routing : Route()
class RoutingContext

fun Application.routing(configuration: Routing.() -> Unit): Routing = Routing()
fun Route.route(path: String, build: Route.() -> Unit): Route = this
fun Route.route(path: String, method: HttpMethod, build: Route.() -> Unit): Route = this
fun Route.method(method: HttpMethod, body: Route.() -> Unit): Route = this
fun Route.handle(body: suspend RoutingContext.() -> Unit) {}
fun Route.get(path: String, body: suspend RoutingContext.() -> Unit): Route = this
fun Route.post(path: String, body: suspend RoutingContext.() -> Unit): Route = this
