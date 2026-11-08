package io.vertx.core.http

interface HttpServerRequest {
    fun remoteAddress(): io.vertx.core.net.SocketAddress
    fun authority(): String
    fun host(): String
}
