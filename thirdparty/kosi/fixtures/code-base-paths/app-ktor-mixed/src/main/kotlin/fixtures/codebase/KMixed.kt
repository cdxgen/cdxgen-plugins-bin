// Two Ktor servers in one module, one with a rootPath: a route is not
// proven to be under it.
//
// kosi:want endpoint framework=ktor path=/mixed method=GET pathunresolved=~apps mode=resolved
// kosi:want-not endpoint framework=ktor path=/a/mixed
package fixtures.codebase

import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.serverConfig
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

val first = applicationEngineEnvironment { rootPath = "/a" }

val second = serverConfig {
    module {
        routing {
            get("/mixed") { }
        }
    }
}
