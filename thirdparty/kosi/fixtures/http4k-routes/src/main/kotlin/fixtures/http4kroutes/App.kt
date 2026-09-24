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
//
// A helper that takes parameters still builds a table, and a mount whose
// prefix does not fold keeps its routes unresolved, never at the root.
// kosi:want endpoint framework=http4k path=/tenant/report method=GET mode=resolved
// kosi:want-not endpoint framework=http4k path=/tenant
// kosi:want endpoint framework=http4k pathunresolved=~fold fn=~app$lambda mode=resolved
// kosi:want-not endpoint framework=http4k path=/hidden
//
// A VERB mount, `"/p" bind GET to routes(..)` (PathMethod.to(RoutingHttpHandler),
// http4k's RouterBasedHttpHandlerTest): the inner routes are under the prefix
// and admit only that verb; an inner route of another verb is never reached.
// http4k's `{$}` anchors the end of the path and is neither a segment nor a
// parameter (atom-tools#95: both found converting http4k to OpenAPI).
// kosi:want endpoint framework=http4k path=/{foo}/{bar} method=GET mode=resolved
// kosi:want endpoint framework=http4k path=/ro/r method=GET mode=resolved
// kosi:want endpoint framework=http4k path=/exact method=GET mode=resolved
// kosi:want-not endpoint framework=http4k path=/{bar}
// kosi:want-not endpoint framework=http4k path=/{foo}
// kosi:want-not endpoint framework=http4k path=/ro
// kosi:want-not endpoint framework=http4k path=/ro/w
// kosi:want-not endpoint framework=http4k path=/exact{$}
// A PREDICATE bind (`queryPresent("tagging") bind { }`, http4k's S3 fake)
// is served at the enclosing mount's path, and a predicate mount adds no
// segment; neither is a path kosi cannot fold.
// kosi:want endpoint framework=http4k path=/b/{key} method=PUT pathunresolved=none mode=resolved
// kosi:want endpoint framework=http4k path=/c/d method=GET pathunresolved=none mode=resolved
// An MCP capability binding (`Tool(..) bind { }`) is not an HTTP route,
// resolved or not.
// kosi:want-not endpoint framework=http4k fn=~diaryTool
package fixtures.http4kroutes

import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.routing.RoutingHttpHandler
import org.http4k.ai.mcp.bind
import org.http4k.routing.bind
import org.http4k.routing.queryPresent
import org.http4k.routing.routes
import org.http4k.routing.to

fun adminRoutes(): RoutingHttpHandler = routes(
    "/stats" bind Method.GET to { _: Request -> Response("s") },
)

fun tenantRoutes(name: String): RoutingHttpHandler = routes(
    "/report" bind Method.GET to { _: Request -> Response(name) },
)

val app: RoutingHttpHandler = routes(
    "/tenant" bind tenantRoutes("t"),
    System.getenv("BASE").orEmpty() bind routes("/hidden" bind Method.GET to { _: Request -> Response("") }),
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
    "/{foo}" bind Method.GET to routes(
        "/{bar}" bind { _: Request -> Response("foo then bar") },
    ),
    "/ro" bind Method.GET to routes(
        "/r" bind Method.GET to { _: Request -> Response("r") },
        "/w" bind Method.POST to { _: Request -> Response("w") },
    ),
    "/exact{$}" bind Method.GET to { _: Request -> Response("exact") },
    "/b/{key}" bind Method.PUT to routes(
        queryPresent("tagging") bind { _: Request -> Response("tagged") },
    ),
    "/c" bind routes(
        queryPresent("q") bind routes("/d" bind Method.GET to { _: Request -> Response("d") }),
    ),
)

fun diaryTool(name: String) = org.http4k.ai.mcp.Tool("diary_for_$name") bind { arg: String -> org.http4k.ai.mcp.ToolResponse(arg) }
