// Ktor's deployment base path, and the parameters a Ktor handler reads.
//
// Two gaps, both of which made kosi wrong rather than incomplete about the
// most widely used Kotlin server framework:
//
//  1. `ktor.deployment.rootPath` was already a base-path key, but a Ktor
//     project has no `application.properties` and no flat `application.yml`
//     — it has a brace-nested HOCON `application.conf`, which nothing read.
//     Every route of every Ktor deployment served under a context path was
//     therefore reported at the wrong URL.
//
//  2. Ktor's readers are ABSTRACT PROPERTIES (`call.parameters`,
//     `request.queryParameters`), and a property read lowered to a field
//     access whose path was the local variable's own name. Model packs
//     match callees, so all eight of the pack's Ktor sources were dead: no
//     Ktor application could produce a single taint slice. An abstract
//     property runs a method on the JVM and now lowers as the call it is.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Every route sits under the HOCON rootPath.
// kosi:want endpoint framework=ktor path=/gateway/articles/{id} mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/gateway/search mode=resolved method=GET
// kosi:want-not endpoint framework=ktor path=/articles/{id}
// kosi:want-not endpoint framework=ktor path=/search
//
// `call.parameters` is the MERGED map. The route settles the transport:
// `/articles/{id}` declares `id`, so `id` is a path parameter; `expand` is
// declared by no route and can only have arrived in the query string.
// kosi:want endpoint framework=ktor path=/gateway/articles/{id} pathparam=id mode=resolved
// kosi:want endpoint framework=ktor path=/gateway/articles/{id} queryparam=expand mode=resolved
// kosi:want-not endpoint framework=ktor path=/gateway/articles/{id} pathparam=expand
//
// `request.queryParameters` names its transport outright, with no route to
// consult.
// kosi:want endpoint framework=ktor path=/gateway/search queryparam=q mode=resolved
// A header is attacker input but it is not a URL parameter.
// kosi:want-not endpoint framework=ktor path=/gateway/search queryparam=X-Request-Id
//
// `route("/inbox") { get { .. } }`: the verb builder takes ONLY a lambda and
// the path is entirely the enclosing prefix. Reading the first argument as a
// path folds the LAMBDA register instead, and the route was published with
// the register's own name as a segment — a URL that exists nowhere, on the
// most common Ktor nesting idiom.
// kosi:want endpoint framework=ktor path=/gateway/inbox mode=resolved method=GET
// kosi:want-not endpoint framework=ktor path=~/inbox/t
// kosi:want-not endpoint framework=ktor path=~/inbox/v
//
// P28 §2: the four ktor-3-generation readers that were endpoints evidence
// but NOT taint sources — cookies, the single-header read, the raw query
// string, and RoutingCall.pathParameters. Each flows to a real sink; the
// wants fail if any source row is removed (R168's rule: the stub carries
// the real FQNs, the wants carry the flow).
// kosi:want flow source=untrusted-input sink=process-exec fn=~cookieSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~headerSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~queryStringSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~pathParametersSink mode=resolved
package fixtures.ktorcontext

import io.ktor.server.request.header
import io.ktor.server.request.queryString
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

fun module(root: Route) {
    root.routing {
        get("/articles/{id}") {
            // Both come out of ONE map; only the route can tell them apart.
            val id = call.parameters["id"]
            val expand = call.parameters["expand"]
            sink(id.orEmpty() + expand.orEmpty())
        }
        route("/inbox") {
            get {
                sink(call.parameters["unread"].orEmpty())
            }
        }
        get("/search") {
            val q = call.request.queryParameters["q"]
            val trace = call.request.headers["X-Request-Id"]
            sink(q.orEmpty() + trace.orEmpty())
        }
    }
}

fun sink(value: String): String = value

// P28 §2 arms: one per reader that had no source row. The sink is the
// engine's own process-exec; every arm returns the Process it started.
fun cookieSink(request: io.ktor.server.request.ApplicationRequest): Process =
    Runtime.getRuntime().exec(request.cookies["session"].orEmpty())

fun headerSink(request: io.ktor.server.request.ApplicationRequest): Process =
    Runtime.getRuntime().exec(request.header("X-Request-Id") ?: "")

fun queryStringSink(request: io.ktor.server.request.ApplicationRequest): Process =
    Runtime.getRuntime().exec(request.queryString())

fun pathParametersSink(call: RoutingCall): Process =
    Runtime.getRuntime().exec(call.pathParameters["id"].orEmpty())
