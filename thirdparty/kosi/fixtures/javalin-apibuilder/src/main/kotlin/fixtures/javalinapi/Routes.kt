// Javalin's ApiBuilder: the pack named only get/post/path, so put, patch,
// delete and head routes were missed (measured on javalin-samples).
// kosi:want endpoint framework=javalin path=/users/{id} method=PUT mode=resolved
// kosi:want endpoint framework=javalin path=/users/{id} method=PATCH mode=resolved
// kosi:want endpoint framework=javalin path=/users/{id} method=DELETE mode=resolved
// kosi:want endpoint framework=javalin path=/users method=HEAD mode=resolved
// kosi:want endpoint framework=javalin path=/users method=GET mode=resolved
// kosi:want-not endpoint framework=javalin path=/{id}
package fixtures.javalinapi

import io.javalin.apibuilder.ApiBuilder.delete
import io.javalin.apibuilder.ApiBuilder.get
import io.javalin.apibuilder.ApiBuilder.head
import io.javalin.apibuilder.ApiBuilder.patch
import io.javalin.apibuilder.ApiBuilder.path
import io.javalin.apibuilder.ApiBuilder.put

fun routes() {
    path("/users") {
        get("") { }
        head("") { }
        put("/{id}") { }
        patch("/{id}") { }
        delete("/{id}") { }
    }
}
