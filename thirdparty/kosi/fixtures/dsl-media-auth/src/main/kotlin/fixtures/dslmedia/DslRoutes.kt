// P15 §4: media and auth for the frameworks P14 did not model. Three
// declaration sites that are NOT annotations and NOT named arguments:
//
//  - Vert.x chains them on the ROUTE OBJECT between the route call and the
//    handler: `router.get("/x").produces("application/json").handler { .. }`.
//  - Javalin's route builder carries them as the vararg RouteRole TAIL:
//    `app.get("/x", handler, Role.ADMIN)`.
//  - The servlet deployment descriptor's <security-constraint> names
//    url-patterns and the roles that may reach them (the web.xml of this
//    fixture, parsed for mappings since P13 and parsed PAST for auth).
//
// http4k's core DSL genuinely has no declaration site — the pack's own
// comment says so — and the last expectation pins that the empties are the
// truth rather than an unmodelled gap.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Vert.x: the chained route's media, and the chained HANDLER (the handler
// lambda sits on the `.handler` call, one hop past the media).
// kosi:want endpoint framework=vertx path=/chain mode=resolved produces=application/json consumes=application/xml
// kosi:want endpoint framework=vertx path=/chain mode=resolved fn=~lambda
// kosi:want-not endpoint framework=vertx path=/chain produces=text/csv
//
// The plain Vert.x route (no chain) declares nothing — an honest empty.
// kosi:want endpoint framework=vertx path=/plain mode=resolved
// kosi:want-not endpoint framework=vertx path=/plain authentication=~
//
// Javalin: the role tail names the requirement; the handler is the argument
// BEFORE the roles (taking the LAST argument as the handler resolved the
// ROLE register and lost the handler entirely).
// kosi:want endpoint framework=javalin path=/admin mode=resolved authentication=~role authentication=~ADMIN
// kosi:want endpoint framework=javalin path=/admin mode=resolved fn=~lambda
// kosi:want-not endpoint framework=javalin path=/admin authentication=~USER
//
// The role-free Javalin route declares no requirement.
// kosi:want endpoint framework=javalin path=/open mode=resolved fn=~lambda
// kosi:want-not endpoint framework=javalin path=/open authentication=~role
//
// The descriptor: /legacy/report is constrained by the /legacy prefix
// constraint (admin, auditor); /public carries a constraint with NO
// auth-constraint element — transport-only, no access requirement — and the
// deny-all shape is pinned where it is declared.
// kosi:want endpoint framework=servlet path=/legacy/* mode=resolved authentication=~security-constraint
// kosi:want endpoint framework=servlet path=/legacy/* mode=resolved authentication=~admin
// kosi:want-not endpoint framework=servlet path=/public authentication=~security-constraint
// kosi:want endpoint framework=servlet path=/denied mode=resolved authentication=~denied
//
// http4k: the honest empty, pinned — no media, no auth, on the core DSL.
// kosi:want endpoint framework=http4k path=/simple mode=resolved
// kosi:want-not endpoint framework=http4k path=/simple produces=~
// kosi:want-not endpoint framework=http4k path=/simple consumes=~
// kosi:want-not endpoint framework=http4k path=/simple authentication=~
package fixtures.dslmedia

import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.vertx.core.Handler
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import org.http4k.core.Method
import org.http4k.core.Response

private infix fun String.bind(method: String) = "$this $method"

fun chainHandler(ctx: RoutingContext): String = ctx.pathParam("id")

fun buildRouter(): Router {
    val router = Router()
    router.get("/chain")
        .produces("application/json")
        .consumes("application/xml")
        .handler(Handler<RoutingContext> { ctx -> chainHandler(ctx) })
    router.get("/plain").handler(Handler<RoutingContext> { ctx -> ctx.queryParam("q") })
    return router
}

fun adminHandler(ctx: Context): String = ctx.pathParam("id")

fun openHandler(ctx: Context): String = ctx.queryParam("q")

fun buildJavalin(): Javalin {
    val app = Javalin()
    app.get("/admin", { ctx -> adminHandler(ctx) }, RouteRole.ADMIN)
    app.get("/open", { ctx -> openHandler(ctx) })
    return app
}

private fun simpleHandler(request: org.http4k.core.Request): Response = Response.ok(request.uri)

@Suppress("unused")
fun http4kApp(): List<String> = listOf(
    "/simple" bind Method.GET to { req -> simpleHandler(req) },
)
