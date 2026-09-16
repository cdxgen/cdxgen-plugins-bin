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
// P17 §0 adds the two REAL auth declaration sites http4k's contract DSL has
// (the core DSL below keeps its honest empty): the contract BLOCK's security
// and a route's own meta security, which overrides it. Vert.x's auth-handler
// chain (`route.handler(BasicAuthHandler.create(auth))`) is modelled here
// too — the requirement attaches through the same chained handler call the
// media ride.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Vert.x: the chained route's media, and the chained HANDLER (the handler
// lambda sits on the `.handler` call, one hop past the media).
// kosi:want endpoint framework=vertx path=/chain mode=resolved produces=application/json consumes=application/xml
// kosi:want endpoint framework=vertx path=/chain mode=resolved fn=~lambda
// kosi:want-not endpoint framework=vertx path=/chain produces=text/csv
// kosi:want-not endpoint framework=vertx path=/chain authentication=~auth-handler
//
// Vert.x auth handler: the requirement rides the chain (an
// AuthenticationHandler IS a Handler<RoutingContext>), and the real handler
// still resolves past it.
// kosi:want endpoint framework=vertx path=/secure mode=resolved authentication=~auth-handler
// kosi:want endpoint framework=vertx path=/secure mode=resolved authentication=~BasicAuthHandler
// kosi:want endpoint framework=vertx path=/secure mode=resolved fn=~lambda
// kosi:want endpoint framework=vertx path=/token mode=resolved authentication=~JWTAuthHandler
// kosi:want endpoint framework=vertx path=/token mode=resolved fn=~lambda
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
// http4k CONTRACT routes: the block's `security` applies to every route in
// it (/inherited, whose meta is empty), and a route's own meta security
// OVERRIDES the block (/overridden) — the precedence the matcher itself
// applies (`meta.security ?: security ?: NoOp`).
// kosi:want endpoint framework=http4k path=/inherited mode=resolved method=GET
// kosi:want endpoint framework=http4k path=/inherited mode=resolved authentication=~contract-security
// kosi:want endpoint framework=http4k path=/inherited mode=resolved authentication=~ApiKeySecurity
// kosi:want-not endpoint framework=http4k path=/inherited authentication=~meta-security
// kosi:want endpoint framework=http4k path=/overridden mode=resolved method=GET
// kosi:want endpoint framework=http4k path=/overridden mode=resolved authentication=~meta-security
// kosi:want endpoint framework=http4k path=/overridden mode=resolved authentication=~BasicAuthSecurity
// kosi:want-not endpoint framework=http4k path=/overridden authentication=~contract-security
//
// An OAuth scheme: OAuthSecurity itself is SEALED and cannot be constructed,
// so the five constructible subclasses are what the pack models and this
// route is the one that proves the channel fires on them.
// kosi:want endpoint framework=http4k path=/oauth mode=resolved authentication=~meta-security
// kosi:want endpoint framework=http4k path=/oauth mode=resolved authentication=~AuthCodeOAuthSecurity
//
// An UNMODELLED meta scheme (app code implementing Security, not one of the
// pack's constructors): the requirement EXISTS — http4k's elvis ignores the
// block whenever meta declares any security — so the fallback must not name
// the BLOCK's scheme (R109's residual, P18). The entry names the site and
// the constructor the CODE declares, without claiming the pack models it.
// kosi:want endpoint framework=http4k path=/custom mode=resolved authentication=~meta-security
// kosi:want endpoint framework=http4k path=/custom mode=resolved authentication=~CustomSecurity
// kosi:want-not endpoint framework=http4k path=/custom authentication=~contract-security
// kosi:want-not endpoint framework=http4k path=/custom authentication=~ApiKeySecurity
// An EXPLICIT `security = null` in a route's meta. The framework's elvis
// (`meta.security?.filter ?: security?.filter`) takes the block's arm for a
// null meta value exactly as it does for an absent one, so /explicit-null
// inherits ApiKeySecurity and must NOT be reported as an unknown scheme —
// the other direction of R109's mistake (P18 review).
// kosi:want endpoint framework=http4k path=/explicit-null mode=resolved authentication=~contract-security
// kosi:want endpoint framework=http4k path=/explicit-null mode=resolved authentication=~ApiKeySecurity
// kosi:want-not endpoint framework=http4k path=/explicit-null authentication=~meta-security
// kosi:want-not endpoint framework=http4k path=/explicit-null authentication=~unknown
// kosi:want endpoint framework=http4k path=/outside mode=resolved
// kosi:want-not endpoint framework=http4k path=/outside authentication=~
//
// http4k CORE DSL: the honest empty, pinned — no media, no auth, on the
// shape with no declaration site.
// kosi:want endpoint framework=http4k path=/simple mode=resolved
// kosi:want-not endpoint framework=http4k path=/simple produces=~
// kosi:want-not endpoint framework=http4k path=/simple consumes=~
// kosi:want-not endpoint framework=http4k path=/simple authentication=~
package fixtures.dslmedia

import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.vertx.core.Handler
import io.vertx.ext.auth.authentication.AuthenticationProvider
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BasicAuthHandler
import io.vertx.ext.web.handler.JWTAuthHandler
import org.http4k.contract.bindContract
import org.http4k.contract.contract
import org.http4k.contract.meta
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.security.ApiKeySecurity
import org.http4k.security.AuthCodeOAuthSecurity
import org.http4k.security.BasicAuthSecurity

private infix fun String.bind(method: String) = "$this $method"

private val authProvider = object : AuthenticationProvider {}

fun chainHandler(ctx: RoutingContext): String = ctx.pathParam("id")

fun secureHandler(ctx: RoutingContext): String = ctx.queryParam("q")

fun buildRouter(): Router {
    val router = Router()
    router.get("/chain")
        .produces("application/json")
        .consumes("application/xml")
        .handler(Handler<RoutingContext> { ctx -> chainHandler(ctx) })
    router.get("/plain").handler(Handler<RoutingContext> { ctx -> ctx.queryParam("q") })
    router.route("/secure")
        .handler(BasicAuthHandler.create(authProvider))
        .handler(Handler<RoutingContext> { ctx -> secureHandler(ctx) })
    router.get("/token")
        .handler(JWTAuthHandler.create(authProvider))
        .handler(Handler<RoutingContext> { ctx -> ctx.queryParam("t") })
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

private fun contractHandler(request: Request): Response = Response.ok(request.uri)

/**
 * App code implementing http4k's Security — the shape a route's meta can
 * assign when none of the framework's own scheme constructors fits. The
 * pack deliberately does NOT model it: the /custom route pins that the
 * requirement is still reported (site + the constructor the code names)
 * and that the CONTRACT BLOCK's scheme does not leak in as the answer.
 */
class CustomSecurity(val cfg: String) : org.http4k.security.Security()

@Suppress("unused")
fun securedContract() = contract {
    security = ApiKeySecurity("api") { it == "secret" }
    routes += "/inherited" meta {
    } bindContract Method.GET to { req -> contractHandler(req) }
    routes += "/overridden" meta {
        security = BasicAuthSecurity("realm", "user:pass")
    } bindContract Method.GET to { req -> contractHandler(req) }
    routes += "/oauth" meta {
        security = AuthCodeOAuthSecurity("https://auth.example/authorize", "https://auth.example/token")
    } bindContract Method.GET to { req -> contractHandler(req) }
    routes += "/custom" meta {
        security = CustomSecurity("app-defined")
    } bindContract Method.GET to { req -> contractHandler(req) }
    routes += "/explicit-null" meta {
        security = null
    } bindContract Method.GET to { req -> contractHandler(req) }
}

// A bindContract OUTSIDE any contract block: no block security to inherit,
// no meta of its own — an honest empty beside the contract positives.
@Suppress("unused")
fun outsideContract() = listOf(
    "/outside" bindContract Method.GET to { req -> contractHandler(req) },
)

