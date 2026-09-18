// Minimal offline Ktor routing surface so the sample carries one INBOUND
// route with a verb and a handler (P17 §3: the e2e's route assertions were
// `all()` over an empty list — honest but vacuous, R53's shape). The shapes
// mirror io.ktor:ktor-server-core's Route extensions; kosi matches the
// resolved FQNs, which these stubs provide without a network or a build.
package io.ktor.server.routing

class Route

fun Route.get(path: String, body: Route.() -> Unit): Unit = Unit

fun Route.routing(block: Route.() -> Unit): Route = this.also(block)
