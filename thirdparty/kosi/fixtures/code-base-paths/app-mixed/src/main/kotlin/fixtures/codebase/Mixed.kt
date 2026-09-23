// Two apps, only one sets a context path: the other's routes are not under
// it, and which app serves a route the module does not decide.
//
// kosi:want endpoint framework=javalin path=/m method=GET pathunresolved=~apps mode=resolved
// kosi:want-not endpoint framework=javalin path=/only/m
package fixtures.codebase

import io.javalin.Javalin

fun mixed() {
    Javalin.create { config -> config.router.contextPath = "/only" }
    val other = Javalin.create { }
    other.get("/m") { }
}
