package io.vertx.core

fun interface Handler<E> {
    fun handle(event: E)
}
