package io.grpc

object ManagedChannelBuilder {
    fun forAddress(host: String, port: Int): String = "$host:$port"
    fun forTarget(target: String): String = target
}
