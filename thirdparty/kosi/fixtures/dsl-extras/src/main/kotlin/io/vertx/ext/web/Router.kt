package io.vertx.ext.web

import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod

class RoutingContext
class Route {
    fun path(path: String): Route = this
    fun method(method: HttpMethod): Route = this
    fun handler(handler: Handler<RoutingContext>): Route = this
}
class Router {
    fun route(): Route = Route()
    fun get(path: String): Route = Route()
    fun mountSubRouter(mountPoint: String, subRouter: Router): Route = Route()
}
