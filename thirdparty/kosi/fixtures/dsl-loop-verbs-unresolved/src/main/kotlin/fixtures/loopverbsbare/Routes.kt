// dsl-loop-verbs with NO Ktor on the classpath: HttpMethod does not type,
// so listOf(..), to, iterator() and next() lower as unresolved calls, and
// the routing calls resolve through their imports. Same wants, same
// negatives: a jar-less run must not lose or invent a verb. And a bare
// `get { }` next to an unresolved `install(..)` (httpbin /range): without
// Ktor it binds to the stdlib's Map `get` operator, which is still the route.
// kosi:want endpoint framework=ktor path=/range/{n} method=GET fn=~range$lambda mode=resolved
// Verbs registered in a loop (ktorio/ktor-samples httpbin: 25 routes). The
// collection is a literal listOf/setOf of HttpMethod constants, inline or in
// a top-level val; a destructured pair list carries the path too.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=ktor path=/status/{codes} method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/status/{codes} method=POST mode=resolved
// kosi:want endpoint framework=ktor path=/status/{codes} method=PUT mode=resolved
// kosi:want endpoint framework=ktor path=/unsafe method=POST mode=resolved
// kosi:want endpoint framework=ktor path=/unsafe method=DELETE mode=resolved
// kosi:want endpoint framework=ktor path=/patch method=PATCH mode=resolved
// kosi:want endpoint framework=ktor path=/delete method=DELETE mode=resolved
// kosi:want endpoint framework=ktor path=/chosen anymethod=false mode=resolved
//
// Negative half: a loop's verbs are exactly its elements; a destructured
// pair never crosses elements; a verb the program picks at run time (a
// parameter) is never claimed; the loop-bound prefix is never dropped.
// kosi:want-not endpoint framework=ktor path=/status/{codes} method=DELETE
// kosi:want-not endpoint framework=ktor path=/unsafe method=GET
// kosi:want-not endpoint framework=ktor path=/patch method=DELETE
// kosi:want-not endpoint framework=ktor path=/delete method=PATCH
// kosi:want-not endpoint framework=ktor path=/chosen method=GET
// kosi:want-not endpoint framework=ktor path=/
package fixtures.loopverbsbare

import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.routing.Route
import io.ktor.server.routing.method
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.routing.get
import io.ktor.server.application.install
import io.ktor.server.plugins.partialcontent.PartialContent

val ALL_METHODS = listOf(HttpMethod.Get, HttpMethod.Post, HttpMethod.Put)
val UNSAFE_METHODS = setOf(HttpMethod.Post, HttpMethod.Delete)

fun Route.statuses() {
    route("/status/{codes}") {
        for (method in ALL_METHODS) {
            method(method) {
                handle { }
            }
        }
    }
}

fun Route.unsafe() {
    route("/unsafe") {
        for (m in UNSAFE_METHODS) {
            method(m) {
                handle { }
            }
        }
    }
}

fun Route.pairs() {
    for ((method, path) in listOf(
        HttpMethod.Patch to "/patch",
        HttpMethod.Delete to "/delete",
    )) {
        route(path) {
            method(method) {
                handle { }
            }
        }
    }
}

fun Route.runtime(chosen: List<HttpMethod>) {
    route("/chosen") {
        for (m in chosen) {
            method(m) {
                handle { }
            }
        }
    }
}

fun Route.range() {
    route("/range/{n}") {
        install(PartialContent)
        get {
            call.parameters["n"]
        }
    }
}

fun Application.module() {
    routing {
        statuses()
        unsafe()
        pairs()
        runtime(listOf(HttpMethod.Get))
        range()
    }
}
