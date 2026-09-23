// http4k route tables nest (http4k.org/guide/reference/routing): a
// `"/api" bind routes(..)` MOUNTS the inner table under /api, including a
// table another function returns; `"/any" bind handler` serves every method.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=http4k path=/ping method=GET mode=resolved
// kosi:want endpoint framework=http4k path=/api/users method=GET fn=~app$lambda mode=resolved
// kosi:want endpoint framework=http4k path=/api/users/{id} method=DELETE mode=resolved
// kosi:want endpoint framework=http4k path=/api/v2/items method=POST mode=resolved
// kosi:want endpoint framework=http4k path=/admin/stats method=GET fn=~adminRoutes$lambda mode=resolved
// kosi:want endpoint framework=http4k path=/any anymethod=true fn=~app$lambda mode=resolved
//
// Negative half: a mount is not an endpoint, and no route inside one is
// published without its prefix.
// kosi:want-not endpoint framework=http4k path=/api
// kosi:want-not endpoint framework=http4k path=/api/v2
// kosi:want-not endpoint framework=http4k path=/admin
// kosi:want-not endpoint framework=http4k path=/users
// kosi:want-not endpoint framework=http4k path=/items
// kosi:want-not endpoint framework=http4k path=/stats
package fixtures.http4kroutes

import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.routing.RoutingHttpHandler
import org.http4k.routing.bind
import org.http4k.routing.routes
import org.http4k.routing.to

fun adminRoutes(): RoutingHttpHandler = routes(
    "/stats" bind Method.GET to { _: Request -> Response("s") },
)

val app: RoutingHttpHandler = routes(
    "/ping" bind Method.GET to { _: Request -> Response("pong") },
    "/api" bind routes(
        "/users" bind Method.GET to { _: Request -> Response("[]") },
        "/users/{id}" bind Method.DELETE to { _: Request -> Response("") },
        "/v2" bind routes(
            "/items" bind Method.POST to { _: Request -> Response("") },
        ),
    ),
    "/admin" bind adminRoutes(),
    "/any" bind { _: Request -> Response("any") },
)
