package io.ktor.server.routing

class RoutingContext
interface Route {
    fun handle(body: suspend RoutingContext.() -> Unit)
}
class Routing : Route {
    override fun handle(body: suspend RoutingContext.() -> Unit) {}
}
fun routing(configuration: Routing.() -> Unit): Routing = Routing()
fun Route.route(path: String, build: Route.() -> Unit): Route = this
fun Route.route(path: Regex, build: Route.() -> Unit): Route = this
fun Route.header(name: String, value: String, build: Route.() -> Unit): Route = this
fun Route.param(name: String, build: Route.() -> Unit): Route = this
fun Route.get(path: String, body: suspend RoutingContext.() -> Unit): Route = this
