// P19 §4: the Vert.x 5 sub-router mount — the shape P18 swapped INTO the
// pack (Route.subRouter, replacing Router.mountSubRouter, removed in
// Vert.x 5) but left inert: no fixture exercised it and the prefix walk
// only knew lambda-shaped nesting. Here the mounted router's routes
// publish under the mount route's path, `*` stripped; routes on the parent
// router are untouched; and no unprefixed copy of a mounted route exists.
// kosi:want endpoint framework=vertx path=/api/users mode=resolved method=GET fn=~lambda
// kosi:want endpoint framework=vertx path=/api/orders mode=resolved method=POST fn=~lambda
// kosi:want endpoint framework=vertx path=/health mode=resolved method=GET fn=~lambda
// kosi:want-not endpoint framework=vertx path=/users mode=resolved
// kosi:want-not endpoint framework=vertx path=/orders mode=resolved
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
package fixtures.vertxsubrouter

import io.vertx.core.Handler
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext

fun usersHandler(ctx: RoutingContext): String = ctx.pathParam("id")

fun ordersHandler(ctx: RoutingContext): String = ctx.queryParam("q")

fun buildRouters(): Router {
    val router = Router()
    val api = Router()
    api.get("/users").handler(Handler<RoutingContext> { ctx -> usersHandler(ctx) })
    api.post("/orders").handler(Handler<RoutingContext> { ctx -> ordersHandler(ctx) })
    router.route("/api/*").subRouter(api)
    router.get("/health").handler(Handler<RoutingContext> { ctx -> usersHandler(ctx) })
    return router
}
