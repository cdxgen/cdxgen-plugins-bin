// DSL spellings measured missing (ktor.io, javalin.io, vertx.io docs):
// Ktor sse/webSocketRaw, Resources put/delete, selectors that add no path
// segment, regex routes; Javalin ws/sse, crud's five routes,
// addHttpHandler(HandlerType, ..); Vert.x's chained route().path().method()
// and Vert.x 4's mountSubRouter(prefix, router).
//
// kosi:want endpoint framework=ktor path=/events method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/raw method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/articles/{id} method=PUT mode=resolved
// kosi:want endpoint framework=ktor path=/articles/{id} method=DELETE mode=resolved
// kosi:want endpoint framework=ktor path=/articles/{id} method=PATCH mode=resolved
// kosi:want endpoint framework=ktor path=/articles/{id} method=HEAD mode=resolved
// kosi:want endpoint framework=ktor path=/articles/{id} method=OPTIONS mode=resolved
// kosi:want endpoint framework=javalin path=/api-socket method=GET mode=resolved
// kosi:want endpoint framework=javalin path=/api-stream method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/api/v2/items method=GET mode=resolved
// kosi:want endpoint framework=ktor pathunresolved=~regex mode=resolved
// kosi:want endpoint framework=javalin path=/socket method=GET mode=resolved
// kosi:want endpoint framework=javalin path=/stream method=GET mode=resolved
// kosi:want endpoint framework=javalin path=/added method=POST mode=resolved
// kosi:want endpoint framework=javalin path=/users method=GET mode=resolved
// kosi:want endpoint framework=javalin path=/users method=POST mode=resolved
// kosi:want endpoint framework=javalin path=/users/{user-id} method=PATCH mode=resolved
// kosi:want endpoint framework=javalin path=/users/{user-id} method=DELETE mode=resolved
// kosi:want endpoint framework=vertx path=/chained method=POST mode=resolved
// kosi:want endpoint framework=vertx path=/mounted/inner method=GET mode=resolved
//
// Negative half: a selector is never a path segment; crud's collection
// serves no PATCH; the regex is never a template.
// kosi:want-not endpoint framework=ktor path=~/X-Version
// kosi:want-not endpoint framework=javalin path=/users method=PATCH
// kosi:want-not endpoint framework=ktor path=~/files
// kosi:want-not endpoint framework=vertx path=/inner
package fixtures.dslextras

import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.crud
import io.javalin.apibuilder.ApiBuilder.path
import io.javalin.apibuilder.ApiBuilder.sse
import io.javalin.apibuilder.ApiBuilder.ws
import io.javalin.apibuilder.CrudHandler
import io.javalin.http.HandlerType
import io.ktor.resources.Resource
import io.ktor.server.resources.delete
import io.ktor.server.resources.head
import io.ktor.server.resources.options
import io.ktor.server.resources.patch
import io.ktor.server.resources.put
import io.ktor.server.routing.get
import io.ktor.server.routing.header
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.sse.sse
import io.ktor.server.websocket.webSocketRaw
import io.vertx.core.http.HttpMethod
import io.vertx.ext.web.Router

@Resource("/articles/{id}")
class ArticleById(val id: Long)

fun ktor() {
    routing {
        sse("/events") { }
        webSocketRaw("/raw") { }
        put<ArticleById> { }
        delete<ArticleById> { }
        patch<ArticleById> { }
        head<ArticleById> { }
        options<ArticleById> { }
        route("/api") {
            header("X-Version", "2") {
                route("/v2") {
                    get("/items") { }
                }
            }
        }
        route(Regex("/files/.+")) {
            get("") { }
        }
    }
}

class UserCrud : CrudHandler

fun javalin(app: Javalin) {
    app.ws("/socket") { }
    app.sse("/stream") { }
    app.addHttpHandler(HandlerType.POST, "/added") { }
    path("/") {
        crud("users/{user-id}", UserCrud())
        ws("/api-socket") { }
        sse("/api-stream") { }
    }
}

fun vertx(router: Router, sub: Router) {
    router.route().path("/chained").method(HttpMethod.POST).handler { }
    sub.get("/inner").handler { }
    router.mountSubRouter("/mounted", sub)
}
