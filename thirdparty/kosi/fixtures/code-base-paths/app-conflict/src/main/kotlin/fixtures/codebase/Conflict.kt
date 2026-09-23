// Two apps in one module with different context paths: which one serves a
// route is not decided by the module, so the route keeps its own path and
// says the base is unproven.
//
// kosi:want endpoint framework=javalin path=/c method=GET pathunresolved=~contextPath mode=resolved
// kosi:want-not endpoint framework=javalin path=/one/c
package fixtures.codebase

import io.javalin.Javalin

fun conflict() {
    Javalin.create { config -> config.router.contextPath = "/one" }
    val b = Javalin.create { config -> config.router.contextPath = "/two" }
    b.get("/c") { }
}
