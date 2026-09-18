package io.ktor.server.routing

class Route

// The ktor 2 DSL shapes (RoutingRoot.kt), spelled with the same signatures
// the ktor-app fixture stubs. The fixture calls them through an explicit
// receiver, so the tree typechecks clean and the entry declares no
// tolerated resolution errors.
fun Route.get(path: String?, body: Route.() -> Unit): Unit = Unit
fun Route.post(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.route(path: String, body: Route.() -> Unit): Unit = Unit
fun Route.routing(block: Route.() -> Unit): Unit = Unit
