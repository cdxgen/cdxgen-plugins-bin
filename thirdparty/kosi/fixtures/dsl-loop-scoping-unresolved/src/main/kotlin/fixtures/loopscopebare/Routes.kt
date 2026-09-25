// The jar-less twin of dsl-loop-scoping (no Ktor on the classpath), same
// wants.
//
// DSL route paths from loops and constants, scoped the way the program is
// (atom-tools#95 review). A top-level `var` list was read as its
// initializer although another function reassigns it, publishing a path the
// running app never serves; a local `val` list was not followed at all;
// and `get(LibPaths.USERS)`, from a library the run cannot see, folded to
// the workspace's unrelated `Local.USERS` through a bare-name table.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=ktor path=/e1 method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/e2 method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/own method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=ktor path=/own/tpl method=GET pathunresolved=none mode=resolved
//
// Negative half: a reassigned `var`, a local list grown after the loop, an
// external constant and an imported one are unresolved, never a guess.
// kosi:want endpoint framework=ktor fn=~viaFor pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~viaForEach pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~grownAfter pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~external pathunresolved=~fold mode=resolved
// kosi:want endpoint framework=ktor fn=~imported pathunresolved=~fold mode=resolved
// kosi:want-not endpoint framework=ktor path=/var-initial
// kosi:want-not endpoint framework=ktor path=/f1
// kosi:want-not endpoint framework=ktor path=/local-users
// kosi:want-not endpoint framework=ktor path=/local-imported
// kosi:want-not endpoint framework=ktor method=OWN
// kosi:want-not endpoint framework=ktor method=USERS
package fixtures.loopscopebare

import com.external.lib.LibPaths
import com.external.lib.LibPaths.IMPORTED
import io.ktor.server.application.Application
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing

var VAR_PATHS = listOf("/var-initial")

fun reconfigure() {
    VAR_PATHS = listOf("/var-real")
}

object Local {
    const val USERS = "/local-users"
    const val IMPORTED = "/local-imported"
    const val OWN = "/own"
}

fun Route.viaFor() {
    for (p in VAR_PATHS) post(p) { }
}

fun Route.viaForEach() {
    VAR_PATHS.forEach { get(it) { } }
}

fun Route.localVal() {
    val paths = listOf("/e1", "/e2")
    paths.forEach { get(it) { } }
}

fun Route.grownAfter() {
    val paths = mutableListOf("/f1")
    paths.forEach { get(it) { } }
    paths.add("/f2")
}

fun Route.external() {
    get(LibPaths.USERS) { }
}

fun Route.imported() {
    get(IMPORTED) { }
}

fun Route.local() {
    get(Local.OWN) { }
    get("${Local.OWN}/tpl") { }
}

fun Application.module() {
    reconfigure()
    routing {
        viaFor()
        viaForEach()
        localVal()
        grownAfter()
        external()
        imported()
        local()
    }
}
