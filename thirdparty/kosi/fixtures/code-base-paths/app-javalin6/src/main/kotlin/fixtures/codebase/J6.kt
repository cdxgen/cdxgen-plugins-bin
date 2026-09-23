// Javalin 6: the context path is set in code (javalin.io config docs:
// config.router.contextPath) and prefixes every route of the app.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=javalin path=/api/users method=GET fn=~codebase.j6$lambda mode=resolved
// kosi:want-not endpoint framework=javalin path=/users method=GET fn=~codebase.j6$lambda
package fixtures.codebase

import io.javalin.Javalin

fun j6() {
    val app = Javalin.create { config -> config.router.contextPath = "/api" }
    app.get("/users") { }
}
