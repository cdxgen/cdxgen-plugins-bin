// http4k-core 5.x org.http4k.routing by shape (routing.kt): `"/p" bind
// Method.GET to handler` is a route; `"/p" bind routes(..)` mounts a table
// under a prefix; `"/p" bind handler` serves every method.
package org.http4k.routing

import org.http4k.core.HttpHandler
import org.http4k.core.Method

interface RoutingHttpHandler
class PathMethod(val path: String, val method: Method)

fun routes(vararg list: RoutingHttpHandler): RoutingHttpHandler = object : RoutingHttpHandler {}
infix fun String.bind(method: Method): PathMethod = PathMethod(this, method)
infix fun PathMethod.to(action: HttpHandler): RoutingHttpHandler = object : RoutingHttpHandler {}
infix fun PathMethod.to(router: RoutingHttpHandler): RoutingHttpHandler = router
infix fun String.bind(router: RoutingHttpHandler): RoutingHttpHandler = router
infix fun String.bind(action: HttpHandler): RoutingHttpHandler = object : RoutingHttpHandler {}

// http4k routing/bind.kt: a Router is a request PREDICATE, bound to a handler
// or a table, and served at the enclosing mount's path.
interface Router
fun queryPresent(name: String): Router = object : Router {}
infix fun Router.bind(handler: HttpHandler): RoutingHttpHandler = object : RoutingHttpHandler {}
infix fun Router.bind(router: RoutingHttpHandler): RoutingHttpHandler = router
