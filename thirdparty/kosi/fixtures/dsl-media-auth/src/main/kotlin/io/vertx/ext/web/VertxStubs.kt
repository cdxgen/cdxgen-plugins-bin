// Minimal Vert.x API surface, shaped exactly as the router chain needs it:
// `router.get(path)` yields a Route, whose `.produces`/`.consumes` return
// the SAME route object and whose `.handler` takes the handler lambda.
package io.vertx.ext.web

import io.vertx.core.Handler

class Router {
    fun get(path: String): Route = Route()
    fun post(path: String): Route = Route()
    fun route(path: String): Route = Route()
}

class Route {
    fun produces(mimeType: String): Route = this
    fun consumes(mimeType: String): Route = this
    fun handler(handler: Handler<RoutingContext>): Route = this
}

class RoutingContext {
    fun pathParam(name: String): String = ""
    fun queryParam(name: String): String = ""
}
