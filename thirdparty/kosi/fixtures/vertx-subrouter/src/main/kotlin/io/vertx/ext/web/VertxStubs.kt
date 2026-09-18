// Minimal Vert.x 5 API surface for the sub-router mount, shaped as the
// pinned jar declares it (javap on io/vertx/ext/web/Route.class in
// io.vertx:vertx-web:5.1.7):
//   public abstract io.vertx.ext.web.Route subRouter(io.vertx.ext.web.Router);
// The mount hangs off a ROUTE (`router.route("/api/*")`) and the mounted
// router is the call's ARGUMENT — a VALUE link, not a lambda.
package io.vertx.ext.web

import io.vertx.core.Handler

class Router {
    fun get(path: String): Route = Route()
    fun post(path: String): Route = Route()
    fun route(path: String): Route = Route()
}

class Route {
    fun subRouter(router: Router): Route = this
    fun handler(handler: Handler<RoutingContext>): Route = this
}

class RoutingContext {
    fun pathParam(name: String): String = ""
    fun queryParam(name: String): String = ""
}
