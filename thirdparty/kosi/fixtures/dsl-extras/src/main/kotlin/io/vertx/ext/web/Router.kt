package io.vertx.ext.web

import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod

class RoutingContext
class Route {
    fun path(path: String): Route = this
    fun method(method: HttpMethod): Route = this
    fun handler(handler: Handler<RoutingContext>): Route = this
    fun subRouter(subRouter: Router): Route = this
}
class Router {
    fun route(): Route = Route()
    fun route(path: String): Route = Route()
    fun get(path: String): Route = Route()
}
