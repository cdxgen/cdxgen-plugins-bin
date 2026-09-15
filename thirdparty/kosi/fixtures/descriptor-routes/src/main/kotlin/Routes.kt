// Two base paths that are NOT configuration keys, and routes that are not
// annotations at all.
//
// JAX-RS declares its base path in code, on an `Application` subclass
// (`@ApplicationPath("/api")`), and a servlet's URL can live only in
// `WEB-INF/web.xml`. Reading neither means reporting `/reports` for a route
// served at `/api/reports`, and reporting nothing at all for a descriptor-
// mapped servlet while the application serves it.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The JAX-RS base path composes onto the resource's own path.
// kosi:want endpoint framework=quarkus path=/api/reports mode=resolved
// kosi:want-not endpoint framework=quarkus path=/reports
//
// The descriptor's mappings are routes, with the verbs the class implements.
// kosi:want endpoint framework=servlet path=/legacy/* mode=resolved method=GET
// kosi:want endpoint framework=servlet path=/old/report mode=resolved method=GET
// A mapping with no servlet element names no class and must be dropped.
// kosi:want-not endpoint framework=servlet path=/ghost
//
// A servlet declares its parameters NOWHERE in its signature: the names are
// the literal keys of the reads in its body, and `getParameter` cannot say
// on its own whether a name came from the path or the query. The route
// settles it — `/old/report` declares no variable, so `format` can only
// have arrived in the query string.
// kosi:want endpoint framework=servlet path=/old/report queryparam=format mode=resolved
// A header is attacker input but it is not a URL parameter.
// kosi:want-not endpoint framework=servlet path=/old/report queryparam=X-Trace
//
// Filters: every request to these patterns runs `doFilter` first.
// kosi:want endpoint framework=servlet path=/admin/* fn=~AuditFilter mode=resolved
// A filter mapped through <servlet-name> inherits that servlet's patterns.
// kosi:want endpoint framework=servlet path=/legacy/* fn=~WrappingFilter mode=resolved
// kosi:want endpoint framework=servlet path=/old/report fn=~WrappingFilter mode=resolved
// A filter-mapping with no filter element names no class.
// kosi:want-not endpoint framework=servlet path=/phantom
// A filter serves every verb, so it pins none.
// kosi:want-not endpoint framework=servlet path=/admin/* method=GET
package fixtures.descriptorroutes

import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.ws.rs.ApplicationPath
import javax.ws.rs.GET
import javax.ws.rs.Path

/** The JAX-RS application: its annotation is the deployment base path. */
@ApplicationPath("/api")
class ReportingApplication

@Path("/reports")
class ReportResource {
    @GET
    @Path("")
    fun list(): String = "reports"
}

/**
 * Mapped only by `WEB-INF/web.xml`. Nothing in this source says `/legacy`,
 * and only `doGet` is implemented — so only GET is served.
 */
class LegacyServlet {
    fun doGet(request: HttpServletRequest): String =
        (request.getParameter("format") ?: "") + (request.getHeader("X-Trace") ?: "")
}

/** Mapped by URL pattern: runs before anything under `/admin`. */
class AuditFilter {
    fun doFilter(request: HttpServletRequest, chain: FilterChain): String =
        request.getHeader("Authorization") ?: ""
}

/** Mapped through `<servlet-name>`: its patterns are LegacyServlet's. */
class WrappingFilter {
    fun doFilter(request: HttpServletRequest, chain: FilterChain): String =
        request.getParameter("debug") ?: ""
}
