// No context path in this module; a sibling's never leaks in.
//
// kosi:want endpoint framework=javalin path=/plain method=GET fn=~codebase.plain$lambda mode=resolved
// kosi:want-not endpoint framework=javalin path=/api/plain
// kosi:want-not endpoint framework=javalin path=/v4/plain
package fixtures.codebase

import io.javalin.Javalin

fun plain() {
    val app = Javalin.create { }
    app.get("/plain") { }
}
