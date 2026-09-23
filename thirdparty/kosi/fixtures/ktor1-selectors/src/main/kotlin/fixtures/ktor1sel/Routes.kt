// Ktor 1.x's selector spelling: `method(HttpMethod.Post) { handle { } }`
// with handle as a Route MEMBER.
// kosi:want endpoint framework=ktor path=/legacy/sel method=POST mode=resolved
// kosi:want endpoint framework=ktor path=/legacy/any anymethod=true mode=resolved
// kosi:want-not endpoint framework=ktor path=/legacy/sel anymethod=true
package fixtures.ktor1sel

import io.ktor.http.HttpMethod
import io.ktor.routing.method
import io.ktor.routing.route
import io.ktor.routing.routing

fun module() {
    routing {
        route("/legacy") {
            route("/sel") {
                method(HttpMethod.Post) {
                    handle { }
                }
            }
            route("/any") {
                handle { }
            }
        }
    }
}
