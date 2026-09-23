// Ktor spellings measured missing on real code (ktorio/ktor-samples
// httpbin: 25 routes): `route(path, HttpMethod.X) { handle { } }` and
// `method(HttpMethod.X) { handle { } }` carry the verb on a SELECTOR, and a
// bare `handle` serves any method (ktor.io server-routing: a route with no
// method "matches any HTTP method"). Routes grouped in `fun Route.x()`
// extensions take the prefix of every place they are called from.
//
// kosi:want endpoint framework=ktor path=/submit method=POST mode=resolved
// kosi:want endpoint framework=ktor path=/replace method=PUT mode=resolved
// kosi:want endpoint framework=ktor path=/anything anymethod=true mode=resolved
// kosi:want endpoint framework=ktor path=/api/users/{id} method=GET fn=~userRoutes mode=resolved
// kosi:want endpoint framework=ktor path=/v2/users/{id} method=GET fn=~userRoutes mode=resolved
// kosi:want endpoint framework=ktor path=/loop method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/loop method=DELETE mode=resolved
//
// Negative half: a method selector is not a path segment; an extension's
// route is never published without the prefix it is mounted under; a loop
// over literal verbs serves exactly those verbs (dsl-loop-verbs has the
// run-time case).
// kosi:want-not endpoint framework=ktor path=/users/{id}
// kosi:want-not endpoint framework=ktor path=/loop anymethod=true
// kosi:want-not endpoint framework=ktor path=/loop method=POST
// kosi:want-not endpoint framework=ktor path=/submit anymethod=true
package fixtures.ktorshapes

import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.method
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

fun Route.userRoutes() {
    get("/{id}") { }
}

fun Application.module() {
    routing {
        route("/submit", HttpMethod.Post) {
            handle { }
        }
        route("/replace") {
            method(HttpMethod.Put) {
                handle { }
            }
        }
        route("/anything") {
            handle { }
        }
        route("/api/users") {
            userRoutes()
        }
        route("/v2/users") {
            userRoutes()
        }
        for (m in listOf(HttpMethod.Get, HttpMethod.Delete)) {
            route("/loop") {
                method(m) {
                    handle { }
                }
            }
        }
    }
}
