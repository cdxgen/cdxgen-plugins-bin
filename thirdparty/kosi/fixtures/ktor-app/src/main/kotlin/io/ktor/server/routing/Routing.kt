package io.ktor.server.routing

class Route

// `path: String?` is ktor 2's own shape (RoutingRoot.kt:
// `fun Route.get(path: String? = null, name: String? = null, body)`), kept
// nullable here so the fixture can spell that generation's no-path route.
fun Route.get(path: String?, body: Route.() -> Unit): Unit = Unit
fun Route.post(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.route(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.routing(block: Route.() -> Unit): Unit = Unit
