// Positive half: Ktor's DSL routes, including a NESTED route whose prefix
// lives on the enclosing route("...") call. The handler is the extracted
// lambda body, so fn= matches the lambda, not the enclosing function.
// kosi:want endpoint framework=ktor path=/health fn=~Routes mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/metrics/count fn=~Routes mode=resolved method=GET
//
// ktor 2's no-path spelling (`get(path: String? = null)`): a PROVABLE null
// path selects the route at its enclosing level — /metrics itself — and is
// never a path called /metrics/null or a lowering register's name (
// a null argument is not a path called /null).
// kosi:want endpoint framework=ktor path=/metrics fn=~Routes mode=resolved method=GET
// kosi:want-not endpoint framework=ktor path=~/metrics/t mode=resolved
// kosi:want-not endpoint framework=ktor path=~/null mode=resolved
// kosi:want endpoint framework=ktor path=/events fn=~Routes mode=resolved method=POST
// kosi:want-not endpoint framework=ktor path=~/legacy-report mode=resolved
// kosi:want-not endpoint framework=ktor path=~/ghost-route mode=resolved
package fixtures.ktorapp

import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

fun registerRoutes(): Route {
    routing {
        get("/health") { }
        route("/metrics") {
            get("/count") { }
            get(null) { }
        }
        post("/events") { }
        // get("/ghost-route") { }
    }
    return Route()
}
