// framework GENERATIONS. Every rename on the JVM is a silent zero
// — modelled Ktor 2 only, and a Ktor 1.x application reported zero
// sources, zero sinks and its routes attributed to Vert.x. This fixture
// stubs several generations side by side at their REAL package names, so
// one detector run must find every generation's routes and flows:
//
//   - JAX-RS javax AND jakarta: routing (@GET, the PATCH twin added),
//     the UriInfo readers, and a @BeanParam binding (the javax twin
//     added)
//   - Servlet jakarta (the javax twin is pinned by handler-input-semantics)
//   - OkHttp 3's Java static AND the 4/5 companion extensions
//   - Apache HttpClient 4 and 5's request constructors (both modelled
// Pinned here for the first time)
//   - Ktor 3: the routing FQNs are Ktor 2's; the RECEIVER is new
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The near-misses: the same sinks fed constants, and the wrong framework a
// name-only matcher would hand these routes to.
// kosi:want-not flow source=~ sink=ssrf fn=~okhttpConstant
// kosi:want-not flow source=~ sink=ssrf fn=~hc5Constant
// kosi:want-not endpoint framework=vertx path=~legacy
// kosi:want-not endpoint framework=javalin path=~legacy
//
// javax UriInfo.getPathParameters — the twin added (jakarta shipped
// both readers; javax shipped only getQueryParameters).
// kosi:want flow source=untrusted-input sink=ssrf fn=~legacyPathParams mode=resolved
// jakarta UriInfo.getQueryParameters, same run.
// kosi:want flow source=untrusted-input sink=ssrf fn=~modernQueryParams mode=resolved
// The jakarta servlet source, end to end.
// kosi:want flow source=untrusted-input sink=ssrf fn=~servletSide mode=resolved
//
// javax JAX-RS routing: GET, and PATCH — the mapping twin added.
// kosi:want endpoint framework=quarkus path=/legacy mode=resolved method=GET
// kosi:want endpoint framework=quarkus path=/legacy mode=resolved method=PATCH
// jakarta JAX-RS routing, same file.
// kosi:want endpoint framework=quarkus path=/modern mode=resolved method=GET
//
// A @BeanParam parameter is a body-shaped aggregate, never a URL parameter
// (the javax twin added).
// kosi:want endpoint framework=quarkus path=/bound mode=resolved method=GET
// kosi:want-not endpoint framework=quarkus path=/bound pathparam=payload
//
// OkHttp 4/5's companion extensions — sinks.
// kosi:want flow source=untrusted-input sink=ssrf fn=~okhttp4Target mode=resolved
// HttpClient 5's request constructor (modelled, pinned here).
// kosi:want flow source=untrusted-input sink=ssrf fn=~hc5Target mode=resolved
// HttpClient 4's, both generations one fixture.
// kosi:want flow source=untrusted-input sink=ssrf fn=~hc4Target mode=resolved
//
// Ktor 3: the routing FQNs are Ktor 2's; the receiver is RoutingContext.
// kosi:want endpoint framework=ktor path=/ktor3/put mode=resolved method=PUT
// kosi:want endpoint framework=ktor path=/ktor3/delete mode=resolved method=DELETE
// kosi:want endpoint framework=ktor path=/ktor3/patch mode=resolved method=PATCH
// kosi:want endpoint framework=ktor path=/ktor3/head mode=resolved method=HEAD
// kosi:want endpoint framework=ktor path=/ktor3/options mode=resolved method=OPTIONS
// kosi:want endpoint framework=ktor path=/ktor3/nested/inner mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor3/ws mode=resolved
// kosi:want endpoint framework=ktor path=/ktor1/authed mode=resolved authentication=~authenticate
// kosi:want endpoint framework=ktor path=/ktor1/get mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor1/post mode=resolved method=POST
// kosi:want endpoint framework=ktor path=/ktor1/put mode=resolved method=PUT
// kosi:want endpoint framework=ktor path=/ktor1/delete mode=resolved method=DELETE
// kosi:want endpoint framework=ktor path=/ktor1/patch mode=resolved method=PATCH
// kosi:want endpoint framework=ktor path=/ktor1/head mode=resolved method=HEAD
// kosi:want endpoint framework=ktor path=/ktor1/options mode=resolved method=OPTIONS
// kosi:want endpoint framework=ktor path=/ktor1/nested/inner mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor1/json-only mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor1/ws mode=resolved
// kosi:want endpoint framework=ktor path=/ktor3/greeting mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor3/greeting queryparam=name mode=resolved
package fixtures.gens

import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.options
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.route
import io.ktor.server.websocket.webSocket
import io.ktor.auth.authenticate
import io.ktor.routing.accept
import io.ktor.routing.delete
import io.ktor.routing.get
import io.ktor.routing.head
import io.ktor.routing.options
import io.ktor.routing.patch
import io.ktor.routing.post
import io.ktor.routing.put
import io.ktor.routing.route
import io.ktor.websocket.webSocket
import jakarta.servlet.http.HttpServletRequest
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import java.net.URI
import javax.ws.rs.BeanParam
import javax.ws.rs.GET as LegacyGET
import javax.ws.rs.PATCH
import javax.ws.rs.Path as LegacyPath
import javax.ws.rs.core.UriInfo
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.apache.hc.client5.http.classic.methods.HttpGet
import org.apache.http.client.methods.HttpGet as HttpGet4

@LegacyPath("/legacy")
class LegacyRoutes {
    @LegacyGET
    fun get(): String = ""

    @PATCH
    fun patch(): String = ""
}

@Path("/modern")
class ModernRoutes {
    @GET
    fun get(): String = ""
}

/** A @BeanParam aggregate: every field is a binding, none a URL parameter. */
class BoundPayload(val q: String = "")

@Path("/bound")
class BoundRoutes {
    @GET
    fun bound(@BeanParam payload: BoundPayload): String = payload.q
}

class ModernResource(val request: HttpServletRequest, val info: jakarta.ws.rs.core.UriInfo)

fun legacyPathParams(info: UriInfo): URI = URI.create(info.getPathParameters()["target"].orEmpty())

fun modernQueryParams(info: jakarta.ws.rs.core.UriInfo): URI = URI.create(info.getQueryParameters()["target"].orEmpty())

fun servletSide(request: HttpServletRequest): URI = URI.create(request.getParameter("target").orEmpty())

fun okhttp4Target(reader: java.io.BufferedReader): HttpUrl = (reader.readLine() ?: "").toHttpUrl()

fun okhttpConstant(): HttpUrl = "https://constant.example".toHttpUrl()

fun hc5Target(reader: java.io.BufferedReader): HttpGet = HttpGet(reader.readLine() ?: "")

fun hc5Constant(): HttpGet = HttpGet("https://constant.example")

fun hc4Target(reader: java.io.BufferedReader): HttpGet4 = HttpGet4(reader.readLine() ?: "")

fun ktor3(root: Route, sink: (String) -> Unit) {
    root.get("/ktor3/greeting") {
        val name = call.parameters["name"].orEmpty()
        sink(name)
    }
}

// The verb builders both generations spell — every modelled verb
// row, one route each, so removing any row changes this fixture's report.
fun ktor3Verbs(root: Route) {
    root.put("/ktor3/put") { }
    root.delete("/ktor3/delete") { }
    root.patch("/ktor3/patch") { }
    root.head("/ktor3/head") { }
    root.options("/ktor3/options") { }
    root.route("/ktor3/nested") {
        get("/inner") { }
    }
    root.webSocket("/ktor3/ws") { }
}

fun ktor1Verbs(root: io.ktor.routing.Route1, sink: (String) -> Unit) {
    root.authenticate("basic") {
        get("/ktor1/authed") { }
    }
    root.get("/ktor1/get") { }
    root.post("/ktor1/post") { }
    root.put("/ktor1/put") { }
    root.delete("/ktor1/delete") { }
    root.patch("/ktor1/patch") { }
    root.head("/ktor1/head") { }
    root.options("/ktor1/options") { }
    root.route("/ktor1/nested") {
        get("/inner") { }
    }
    root.accept("application/json") {
        get("/ktor1/json-only") { }
    }
    root.webSocket("/ktor1/ws") { }
}
