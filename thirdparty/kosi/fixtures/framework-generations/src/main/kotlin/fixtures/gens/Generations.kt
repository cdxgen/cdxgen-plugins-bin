// P14 §2: framework GENERATIONS. Every rename on the JVM is a silent zero
// — R84 modelled Ktor 2 only, and a Ktor 1.x application reported zero
// sources, zero sinks and its routes attributed to Vert.x. This fixture
// stubs several generations side by side at their REAL package names, so
// one detector run must find every generation's routes and flows:
//
//   - JAX-RS javax AND jakarta: routing (@GET, the PATCH twin P14 added),
//     the UriInfo readers, and a @BeanParam binding (the javax twin P14
//     added)
//   - Servlet jakarta (the javax twin is pinned by handler-input-semantics)
//   - OkHttp 3's Java static AND the 4/5 companion extensions (P14)
//   - Apache HttpClient 4 and 5's request constructors (both modelled
//     since P12, pinned here for the first time)
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
// javax UriInfo.getPathParameters — the twin P14 added (jakarta shipped
// both readers; javax shipped only getQueryParameters).
// kosi:want flow source=untrusted-input sink=ssrf fn=~legacyPathParams mode=resolved
// jakarta UriInfo.getQueryParameters, same run.
// kosi:want flow source=untrusted-input sink=ssrf fn=~modernQueryParams mode=resolved
// The jakarta servlet source, end to end.
// kosi:want flow source=untrusted-input sink=ssrf fn=~servletSide mode=resolved
//
// javax JAX-RS routing: GET, and PATCH — the mapping twin P14 added.
// kosi:want endpoint framework=quarkus path=/legacy mode=resolved method=GET
// kosi:want endpoint framework=quarkus path=/legacy mode=resolved method=PATCH
// jakarta JAX-RS routing, same file.
// kosi:want endpoint framework=quarkus path=/modern mode=resolved method=GET
//
// A @BeanParam parameter is a body-shaped aggregate, never a URL parameter
// (the javax twin P14 added).
// kosi:want endpoint framework=quarkus path=/bound mode=resolved method=GET
// kosi:want-not endpoint framework=quarkus path=/bound pathparam=payload
//
// OkHttp 4/5's companion extensions — sinks since P14.
// kosi:want flow source=untrusted-input sink=ssrf fn=~okhttp4Target mode=resolved
// HttpClient 5's request constructor (modelled since P12, pinned here).
// kosi:want flow source=untrusted-input sink=ssrf fn=~hc5Target mode=resolved
// HttpClient 4's, both generations one fixture.
// kosi:want flow source=untrusted-input sink=ssrf fn=~hc4Target mode=resolved
//
// Ktor 3: the routing FQNs are Ktor 2's; the receiver is RoutingContext.
// kosi:want endpoint framework=ktor path=/ktor3/greeting mode=resolved method=GET
// kosi:want endpoint framework=ktor path=/ktor3/greeting queryparam=name mode=resolved
package fixtures.gens

import io.ktor.server.routing.Route
import io.ktor.server.routing.get
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
