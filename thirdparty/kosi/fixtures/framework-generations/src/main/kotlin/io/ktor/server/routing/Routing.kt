// Ktor 3's routing surface, stubbed at the artifact's real package names
// (verified against ktor-server-core-jvm 3.0.0): the verb builders stay at
// `io.ktor.server.routing.get`/`post` exactly as Ktor 2 had them — what
// moved is the HANDLER RECEIVER, from Ktor 2's PipelineContext to
// `io.ktor.server.routing.RoutingContext`, and `call` is that type's own
// accessor property. Ktor 3 also introduces no new reader packages: the
// request readers stay under `io.ktor.server.request`.
package io.ktor.server.routing

import io.ktor.server.application.ApplicationCall

class RoutingContext {
    /** The handler's call: an accessor property, read by BARE NAME inside the lambda. */
    val call: ApplicationCall get() = ApplicationCall()
}

class Route

fun Route.get(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.post(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.put(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.delete(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.patch(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.head(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.options(path: String, body: suspend RoutingContext.() -> Unit): Unit = Unit
fun Route.route(path: String, body: Route.() -> Unit): Unit = Unit
