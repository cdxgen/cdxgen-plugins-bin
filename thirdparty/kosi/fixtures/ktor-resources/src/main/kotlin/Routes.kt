// Ktor's TYPED routing: `get<Article> { }`. There is no path argument at
// all — the route's path lives on `@Resource` on the type, and nested
// resource classes compose (`@Resource("{id}")` inside `@Resource("/articles")`
// means `/articles/{id}`).
//
// The detector reads a route's path from the call's first argument, so a
// typed route resolved to nothing: kosi registered the builder functions
// and then reported no path, which is worse than not supporting them —
// the route looked handled. Reading it needs the call's TYPE ARGUMENT,
// which the KIR did not carry.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want endpoint framework=ktor path=/articles mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/articles/{id} mode=resolved method=POST
//
// No route may be published with an unresolved register as its path.
// kosi:want-not endpoint framework=ktor path=~%
package fixtures.ktorresources

import io.ktor.resources.Resource
import io.ktor.server.resources.Route
import io.ktor.server.resources.get
import io.ktor.server.resources.post

@Resource("/articles")
class Articles {
    /** Nested: composes to `/articles/{id}`. */
    @Resource("{id}")
    class ById(val id: String = "")
}

fun registerTypedRoutes(route: Route) {
    route.get<Articles> { }
    route.post<Articles.ById> { }
}
