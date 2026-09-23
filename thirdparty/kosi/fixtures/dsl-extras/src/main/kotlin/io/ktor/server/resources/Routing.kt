package io.ktor.server.resources

import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext

inline fun <reified T : Any> Route.put(noinline body: suspend RoutingContext.(T) -> Unit): Route = this
inline fun <reified T : Any> Route.delete(noinline body: suspend RoutingContext.(T) -> Unit): Route = this
inline fun <reified T : Any> Route.patch(noinline body: suspend RoutingContext.(T) -> Unit): Route = this
inline fun <reified T : Any> Route.head(noinline body: suspend RoutingContext.(T) -> Unit): Route = this
inline fun <reified T : Any> Route.options(noinline body: suspend RoutingContext.(T) -> Unit): Route = this
