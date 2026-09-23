// vertx-web 4/5 by shape (vertx.io Router apidocs): every verb with a
// path, route(HttpMethod, path), and the *WithRegex forms.
package io.vertx.ext.web

import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod

class RoutingContext
class Route {
    fun handler(handler: Handler<RoutingContext>): Route = this
}
class Router {
    fun patch(path: String): Route = Route()
    fun head(path: String): Route = Route()
    fun options(path: String): Route = Route()
    fun trace(path: String): Route = Route()
    fun connect(path: String): Route = Route()
    fun route(method: HttpMethod, path: String): Route = Route()
    fun getWithRegex(regex: String): Route = Route()
    fun postWithRegex(regex: String): Route = Route()
    fun putWithRegex(regex: String): Route = Route()
    fun deleteWithRegex(regex: String): Route = Route()
    fun patchWithRegex(regex: String): Route = Route()
    fun headWithRegex(regex: String): Route = Route()
    fun optionsWithRegex(regex: String): Route = Route()
    fun routeWithRegex(regex: String): Route = Route()
}
