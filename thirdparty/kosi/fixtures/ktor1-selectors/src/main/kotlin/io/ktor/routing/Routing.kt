// ktor-server-core 1.6 by shape: handle is a MEMBER of io.ktor.routing.Route
// (it became an extension in 2.x); method/route are extensions.
package io.ktor.routing

import io.ktor.http.HttpMethod

open class Route {
    fun handle(handler: suspend Route.() -> Unit) {}
}
class Routing : Route()

fun routing(configuration: Routing.() -> Unit): Routing = Routing()
fun Route.route(path: String, build: Route.() -> Unit): Route = this
fun Route.method(method: HttpMethod, body: Route.() -> Unit): Route = this
