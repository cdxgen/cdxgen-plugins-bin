// javalin-loop-paths with NO Javalin on the classpath: same wants.
// atom-tools#95 follow-up: loop-registered routes are not a Ktor quirk.
// Javalin published `/vr` and `/vit` for the lambda parameter, with and
// without a classpath. One route per literal element; anything unprovable
// is pathUnresolved.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=javalin path=/j-control method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=javalin path=/j-one method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=javalin path=/j-two method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=javalin path=/j-x method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=javalin path=/j-val method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=javalin path=/j-for method=POST pathunresolved=none mode=resolved
//
// Negative half: the lambda parameter's name is never a path, and a
// caller-supplied list stays unresolved.
// kosi:want endpoint framework=javalin fn=~dynamic pathunresolved=~fold mode=resolved
// kosi:want-not endpoint framework=javalin path=/vr
// kosi:want-not endpoint framework=javalin path=/vit
// kosi:want-not endpoint framework=javalin path=/vp
// kosi:want-not endpoint framework=javalin path=/vpath
package fixtures.javalinloopsbare

import io.javalin.Javalin

val ROUTES = listOf("/j-one", "/j-two")

fun main() {
    val app = Javalin.create()
    app.get("/j-control") { it.result("ok") }
    ROUTES.forEach { r -> app.get(r) { c -> c.result("ok") } }
    listOf("/j-x").forEach { app.get(it) { c -> c.result("ok") } }
    val single = "/j-val"
    app.get(single) { it.result("ok") }
    for (path in listOf("/j-for")) app.post(path) { it.result("ok") }
    dynamic(app, listOf("/j-d"))
}

fun dynamic(app: Javalin, paths: List<String>) {
    paths.forEach { p -> app.get(p) { it.result("ok") } }
}
