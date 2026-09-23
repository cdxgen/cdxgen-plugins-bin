// short tail: the two frameworks listed as "in the pack" and found
// were not in it at all. Both are modelled from their own documentation.
//
// RATPACK — ratpack.io/manual/current/handlers.html: `void handle(Context
// context)`, "a handler is just a function that acts on a handling context".
// The single parameter is the framework's own collaborator, so handlerInput is
// `context` (the javalin/http4k conclusion, for the javalin/http4k reason) and
// request data arrives through `context.getRequest()`. Those readers are named
// in the endpoints pack AND carry source rows in the security pack — 's
// lesson: a contextReader that is endpoints evidence and nothing else means a
// header read into a sink is not a flow.
//
// DROPWIZARD — dropwizard.io/en/stable/manual/auth.html: a Dropwizard resource
// IS a Jakarta REST resource, so it needs no framework entry of its own. What
// it needs is for `@Auth` to be understood: "annotate the parameter
// representing your principal with @Auth". That parameter is the authenticated
// principal the framework injects, not a bound entity, and without the pack
// entry every secured Dropwizard resource grows a false source.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Ratpack: each documented reader reaches a sink. Drop a source row and the
// matching want fails.
// kosi:want flow source=untrusted-input sink=process-exec fn=~QueryParamSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~HeaderSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~CookieSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~BodySink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~CookiesSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~BodyStreamSink mode=resolved
//
// The SAME six readers at ratpack 1.x's package. a framework named in
// one spelling is invisible in the other, and the only way to know the 1.x
// rows work is to exercise them.
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyQueryParamSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyHeaderSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyCookieSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyCookiesSink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyBodySink mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~LegacyBodyStreamSink mode=resolved
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~LegacyContextOnlySink
//
// The Context itself is the framework's collaborator, never a seeded payload:
// a handler that only renders what the context hands it has no flow.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ContextOnlySink
//
// Dropwizard: the bound query parameter IS request data; the @Auth principal
// is NOT. The second want-not is the whole point of the pack entry.
// kosi:want flow source=untrusted-input sink=process-exec fn=~search mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~whoami
// (checked in every slot: the @Auth principal is never request data)
// Mounting (atom-tools#92 follow-up): a Handler class names no route; the
// chain that mounts it does. Instance form and lambda form both link, the
// mounted class takes the chain's path and verb, and a handler nobody
// mounts says so instead of publishing the fabricated `/Handler/handle`.
// kosi:want endpoint framework=ratpack path=/search method=GET fn=~.QueryParamSink.handle pathunresolved=none mode=resolved
// kosi:want endpoint framework=ratpack path=/api/any anymethod=true mode=resolved
// kosi:want endpoint framework=ratpack fn=~HeaderSink.handle pathunresolved=~declares mode=resolved
// kosi:want-not endpoint framework=ratpack path=/Handler/handle
// kosi:want-not endpoint framework=ratpack fn=~.QueryParamSink.handle pathunresolved=~declares
package fixtures.ratpackdropwizard

import io.dropwizard.auth.Auth
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.QueryParam
import ratpack.core.handling.Chain
import ratpack.core.handling.Context
import ratpack.core.handling.Handler
import ratpack.handling.Context as LegacyContext
import ratpack.handling.Handler as LegacyHandler

private fun run(command: String): Process = ProcessBuilder(command).start()

// ---- Ratpack -------------------------------------------------------------

class QueryParamSink : Handler {
    override fun handle(context: Context) {
        val q = context.getRequest().getQueryParams()["cmd"] ?: return
        run(q)
    }
}

class HeaderSink : Handler {
    override fun handle(context: Context) {
        val h = context.getRequest().getHeaders()["X-Cmd"] ?: return
        run(h)
    }
}

class CookieSink : Handler {
    override fun handle(context: Context) {
        val c = context.getRequest().oneCookie("cmd") ?: return
        run(c)
    }
}

class BodySink : Handler {
    override fun handle(context: Context) {
        val body = context.getRequest().getBody()
        run(body.toString())
    }
}

/**
 * The context is the framework's, not the request's: rendering through it
 * introduces nothing. If `contextParameterTypes` stops naming
 * `ratpack.core.handling.Context`, this handler reports a finding and the
 * want-not above fails.
 */
class ContextOnlySink : Handler {
    override fun handle(context: Context) {
        context.render("ok")
    }
}

class CookiesSink : Handler {
    override fun handle(context: Context) {
        run(context.getRequest().getCookies().joinToString())
    }
}

class BodyStreamSink : Handler {
    override fun handle(context: Context) {
        run(context.getRequest().getBodyStream().toString())
    }
}

// ---- Ratpack 1.x, the pre-JPMS package -----------------------------------
// Identical handlers against `ratpack.handling` / `ratpack.http`. If the pack
// carried only the 2.x spelling these would all fall silent, which is the
// failure is named after.

class LegacyQueryParamSink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        val q = context.getRequest().getQueryParams()["cmd"] ?: return
        run(q)
    }
}

class LegacyHeaderSink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        val h = context.getRequest().getHeaders()["X-Cmd"] ?: return
        run(h)
    }
}

class LegacyCookieSink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        val c = context.getRequest().oneCookie("cmd") ?: return
        run(c)
    }
}

class LegacyCookiesSink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        run(context.getRequest().getCookies().joinToString())
    }
}

class LegacyBodySink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        run(context.getRequest().getBody().toString())
    }
}

class LegacyBodyStreamSink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        run(context.getRequest().getBodyStream().toString())
    }
}

/** The 1.x context is the framework's too: no seed, no finding. */
class LegacyContextOnlySink : LegacyHandler {
    override fun handle(context: LegacyContext) {
        context.render("ok")
    }
}

// ---- Dropwizard ----------------------------------------------------------

class Principal(val name: String)

@Path("/users")
class UserResource {

    /** A bound query parameter: request data, and a real flow. */
    @GET
    @Path("/search")
    fun search(@QueryParam("q") q: String): String {
        run(q)
        return q
    }

    /**
     * dropwizard.io auth manual: the `@Auth` parameter is the principal the
     * framework injects once the authenticator has run. It is not something
     * the caller supplies, so it is not a source — and a principal's name
     * reaching a sink must NOT be reported as untrusted input.
     */
    @GET
    @Path("/whoami")
    fun whoami(@Auth principal: Principal): String {
        run(principal.name)
        return principal.name
    }
}

/** The application's chain: where handlers get their routes. */
fun routes(chain: Chain) {
    chain.get("search", QueryParamSink())
    chain.prefix("api") { api ->
        api.path("any") { context -> context.render("any") }
    }
}
