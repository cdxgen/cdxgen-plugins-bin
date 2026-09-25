// dsl-loop-paths with NO Ktor on the classpath: the routing calls resolve
// through their imports only. Same wants, same negatives.
// Routes whose PATH is a loop variable (atom-tools#95). kosi published the
// lambda parameter's register name as a substantiated path (`/vroute`,
// `/vq`, `/vit`): a URL that exists nowhere, indistinguishable from a real
// route downstream. A loop over a literal collection is one route per
// element; anything kosi cannot prove is `pathUnresolved`, never a name.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=ktor path=/control method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/x method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/y method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/one method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/two method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/m method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/each/a method=POST pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/each/b method=POST pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/api/p method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/api/q method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/on method=DELETE pathunresolved=none mode=resolved
//
// Negative half: no register name is ever a path; a collection the program
// supplies, grows, or indexes, and a computed path, stay unresolved.
// kosi:want endpoint framework=ktor fn=~dynamic pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~indexed pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~grown pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~computed pathunresolved=~fold mode=resolved
// kosi:want-not endpoint framework=ktor path=/vroute
// kosi:want-not endpoint framework=ktor path=/vq
// kosi:want-not endpoint framework=ktor path=/vit
// kosi:want-not endpoint framework=ktor path=/vp
// kosi:want-not endpoint framework=ktor path=/api/vit
// kosi:want-not endpoint framework=ktor path=/g1
// kosi:want-not endpoint framework=ktor path=/g2
// kosi:want-not endpoint framework=ktor path=/i1
package fixtures.looppathsbare

import io.ktor.server.application.Application
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

val PATHS = listOf("/one", "/two")

fun Route.forLoop() {
    for (p in listOf("/each/a", "/each/b")) {
        post(p) { }
    }
}

fun Route.nested() {
    route("/api") {
        listOf("/p", "/q").forEach { get(it) { } }
    }
}

fun Route.onEachPaths() {
    listOf("/on").onEach { p -> delete(p) { } }
}

fun Route.dynamic(paths: List<String>) {
    paths.forEach { p -> get(p) { } }
}

fun Route.indexed() {
    listOf("/i1").forEachIndexed { _, p -> get(p) { } }
}

fun Route.grown() {
    val paths = mutableListOf("/g1")
    paths.add("/g2")
    paths.forEach { p -> get(p) { } }
}

fun pathFor(name: String): String = "/" + name.reversed()

fun Route.computed(name: String) {
    get(pathFor(name)) { }
}

fun Application.module() {
    routing {
        get("/control") { }
        listOf("/x", "/y").forEach { route -> get(route) { } }
        PATHS.forEach { q -> get(q) { } }
        listOf("/m").forEach { get(it) { } }
        forLoop()
        nested()
        onEachPaths()
        dynamic(listOf("/d"))
        indexed()
        grown()
        computed("z")
    }
}
