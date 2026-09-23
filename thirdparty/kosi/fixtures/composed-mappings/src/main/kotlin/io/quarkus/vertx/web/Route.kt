// quarkus-reactive-routes by shape: @Route(path, regex, methods) and
// @RouteBase(path); Route.HttpMethod is the verb enum.
package io.quarkus.vertx.web

annotation class Route(val path: String = "", val regex: String = "", val methods: Array<HttpMethod> = []) {
    enum class HttpMethod { GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH }
}
annotation class RouteBase(val path: String = "")
