// Positive half: Ktor's DSL routes, including a NESTED route whose prefix
// lives on the enclosing route("...") call. The handler is the extracted
// lambda body, so fn= matches the lambda, not the enclosing function.
// kosi:want endpoint framework=ktor path=/health fn=~Routes mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/metrics/count fn=~Routes mode=resolved method=GET
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
        }
        post("/events") { }
        // get("/ghost-route") { }
    }
    return Route()
}
