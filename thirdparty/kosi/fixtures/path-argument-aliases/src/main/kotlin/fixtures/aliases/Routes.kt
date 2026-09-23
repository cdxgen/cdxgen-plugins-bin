// The path is written under an ALIAS of `value` as often as under `value`
// itself: Micronaut's `uri`/`uris`, the servlet API's `urlPatterns`. A
// detector reading `value` alone published these routes at their class
// base, or at no path at all.
//
// kosi:want endpoint framework=micronaut path=/m/by-uri method=GET mode=resolved
// kosi:want endpoint framework=micronaut path=/m/u1 method=GET mode=resolved
// kosi:want endpoint framework=micronaut path=/m/u2 method=GET mode=resolved
// kosi:want endpoint framework=servlet path=/export method=GET mode=resolved
// kosi:want endpoint framework=servlet path=/export/* method=GET mode=resolved
//
// Negative half: an aliased route is never its class base, and a servlet's
// patterns never collapse to the root.
// kosi:want-not endpoint framework=micronaut path=/m
// kosi:want-not endpoint framework=servlet path=/
// kosi:want-not diagnostic code=parse-error
package fixtures.aliases

import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller("/m")
class MicronautApi {
    @Get(uri = "/by-uri")
    fun byUri(): String = "a"

    @Get(uris = ["/u1", "/u2"])
    fun byUris(): String = "b"
}

@WebServlet(urlPatterns = ["/export", "/export/*"])
class ExportServlet {
    fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.sendRedirect(request.getParameter("to"))
    }
}
