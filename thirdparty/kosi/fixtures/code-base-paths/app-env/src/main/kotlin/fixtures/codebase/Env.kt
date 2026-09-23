// A context path read at run time: the base is real and unknown.
//
// kosi:want endpoint framework=javalin path=/e method=GET pathunresolved=~fold mode=resolved
package fixtures.codebase

import io.javalin.Javalin

fun env() {
    val app = Javalin.create { config -> config.router.contextPath = System.getenv("CTX") ?: "/" }
    app.get("/e") { }
}
