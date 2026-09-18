// Ktor 1.x's routing surface at its own package (io.ktor.routing, the
// generation's real spelling — 1.6.7 artifact): every verb builder plus
// the accept content-selector and the route nester.
package io.ktor.routing

import io.ktor.application.ApplicationCall1

class Route1 {
    val call: ApplicationCall1 get() = ApplicationCall1()
}

fun Route1.get(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.post(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.put(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.delete(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.patch(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.head(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.options(path: String, body: suspend Route1.() -> Unit): Unit = Unit
fun Route1.route(path: String, body: Route1.() -> Unit): Unit = Unit
fun Route1.accept(contentType: String, body: Route1.() -> Unit): Unit = Unit
