// Javalin 3/4: config.contextPath.
//
// kosi:want endpoint framework=javalin path=/v4/items method=POST fn=~codebase.j4$lambda mode=resolved
// kosi:want-not endpoint framework=javalin path=/items fn=~codebase.j4$lambda
package fixtures.codebase

import io.javalin.Javalin

fun j4() {
    val app = Javalin.create { it.contextPath = "/v4" }
    app.post("/items") { }
}
