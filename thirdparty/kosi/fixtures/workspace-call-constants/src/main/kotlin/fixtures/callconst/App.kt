// the producer bucket — values defined by a CALL — was the largest
// failure bucket in every depth report this project had taken (producer 9,
// constant across every measurement). The register is defined by a call the
// folder could not see through. This fixture is the population that makes
// the widening observable END TO END, through Analyzer.analyze (the change
// rule, written against a capability proven only on hand-built IR is
// not a capability):
//
//  - `fun apiBase() = "https://api.example.com"` — the expression body is a
//    single constant return;
//  - `fun versionedBase() = VERSION` — the body reads a workspace
//    `const val` (the fieldget arm's own evidence);
//  - `fun configHost() = Config.host` — the `object`'s `const val` read.
//
// At the call site the value is the CALL RESULT: the published resolution
// is `folded` (FOLDED_CONST), never `literal` — the code names a call, and
// a consumer reading "literal" would be told a falsehood about the source.
//
// The defect restored (the workspace arm removed) publishes the REGISTER's
// machine name where the host belongs — exactly what looked like from
// the outside (`name=vhost`); the want-not on `resolution=unresolved` is
// that shape, pinned.
//
// The outbound URL rides okhttp3 (the same in-source stub shape
// cross-block-values uses); the endpoint base path rides the ktor route
// DSL, whose path argument folds through the same accessor.
//
// kosi:want-not diagnostic code=parse-error
//
// Outbound: one template over an accessor, one direct accessor call, one
// accessor over the object's const. All three fold.
// kosi:want service protocol=https name=api.example.com resolution=folded mode=resolved
// kosi:want service protocol=https name=api.example.com mode=resolved
// kosi:want service protocol=https name=config.example.com resolution=folded mode=resolved
// kosi:want service protocol=https name=versioned.example.internal resolution=folded mode=resolved
// The restored defect (and any regression to the register name):
// kosi:want-not service protocol=https resolution=unresolved mode=resolved
//
// Inbound: the route's PREFIX is a workspace accessor, the leaf a literal.
// kosi:want endpoint framework=ktor path=/api/v2/health fn=~registerRoutes mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/api/v2/items fn=~registerRoutes mode=resolved method=POST
// kosi:want-not endpoint framework=ktor path=~/% mode=resolved
package fixtures.callconst

import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import okhttp3.Request

/** Top-level `const val`: unique name workspace-wide, so the const table holds it. */
const val API_VERSION = "v3"

object DeployConfig {
    const val host = "config.example.com"
}

/** Shape 1: the expression body is a single constant return. */
fun apiBase(): String = "https://api.example.com"

/** Shape 2: the body reads the workspace `const val` through the const table's own arm. */
fun versionedBase(): String = "https://versioned.example.internal/$API_VERSION"

/** Shape 3: the `object`'s const, read through the accessor. */
fun configHost(): String = DeployConfig.host

/** The route PREFIX is itself a folded value. */
fun basePath(): String = "/api/v2"

fun registerRoutes(): Route {
    val root = Route()
    root.routing {
        route(basePath()) {
            get("/health") { }
            post("/items") { }
        }
    }
    return root
}

class Gateway {
    fun templated() {
        Request.Builder().url("${apiBase()}/v1/items")
    }

    fun direct() {
        Request.Builder().url(apiBase())
    }

    fun fromConfig() {
        Request.Builder().url(configHost())
    }

    fun fromVersioned() {
        Request.Builder().url(versionedBase())
    }
}
