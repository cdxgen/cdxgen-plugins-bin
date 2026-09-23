// Ktor configured in code: the environment's rootPath prefixes the routes.
//
// kosi:want endpoint framework=ktor path=/k/hello method=GET mode=resolved
// kosi:want-not endpoint framework=ktor path=/hello
package fixtures.codebase

import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

val env = applicationEngineEnvironment {
    rootPath = "/k"
    module {
        routing {
            get("/hello") { }
        }
    }
}
