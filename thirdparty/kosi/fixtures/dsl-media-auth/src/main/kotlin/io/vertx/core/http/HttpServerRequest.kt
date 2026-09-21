// Vert.x's request half (vertx.io docs, vertx-web manual: the handler's
// RoutingContext exposes `request()`, whose body getters read the parsed
// request). The form-attribute reader was endpoints evidence but
// not a taint source.
package io.vertx.core.http

interface HttpServerRequest {
    fun getFormAttribute(formAttributeName: String): String?
}
