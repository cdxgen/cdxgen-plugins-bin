// Positive half: http4k contract routes - "/path" bind METHOD to handler.
// The handler is the lambda on the `to` side of the bind.
// kosi:want endpoint framework=http4k path=~/convos mode=resolved count=3
// kosi:want endpoint framework=http4k path=/convos/search mode=resolved method=POST
// kosi:want-not endpoint framework=http4k path=~/ghost-convos mode=resolved
// kosi:want-not endpoint framework=http4k path=~/bound2 mode=resolved
package fixtures.http4kapp

import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.contract.bind

fun appRoutes(): List<Pair<Route, (Request) -> Response>> = listOf(
    "/convos" bind Method.GET to { _: Request -> Response("[]") },
    "/convos/:id" bind Method.GET to { _: Request -> Response("{}") },
    "/convos/search" bind Method.POST to { _: Request -> Response("[]") },
)

// A homonym infix with a different name (bind2) is a different symbol: the
// call-name rule matches `bind` exactly. A commented route stays commented.
private infix fun String.bind2(method: Method): String = method.name

private val notARoute = "/bound2" bind2 Method.GET
// "/ghost-convos" bind Method.GET to { _: Request -> Response("[]") }
