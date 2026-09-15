// A CONTEXT framework hands the handler a request object, not data — and,
// in the servlet case, hands it the RESPONSE in the same signature.
//
// `--endpoint-sources` used to seed every value parameter of a detected
// handler, so `response` was tainted exactly as hard as `request`: any
// value derived from the response object became attacker-controlled, and
// the report said an attacker's data had reached a sink it never touched.
// Input from a context framework comes out of the context through reader
// methods, which the security pack models; the parameters themselves are
// not seeded.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The route itself: `@WebServlet` declares it on the CLASS and the handlers
// are named by convention, a shape the mapping-on-the-function rule cannot
// express — so a servlet used to publish no endpoint at all.
// kosi:want endpoint framework=servlet path=/run mode=resolved method=GET
// kosi:want endpoint framework=servlet path=/run mode=resolved method=POST
//
// The positive: a reader on the request IS a source.
// kosi:want flow source=untrusted-input sink=process-exec fn=~doGet known-fail=syntax:1
//
// The near-miss that only context semantics get right: the handler's own
// parameters are not input. Nothing derived from the RESPONSE object may be
// reported, and a handler that touches neither reader must report nothing.
// kosi:want-not flow source=~ sink=~ fn=~doPost
//
// `@WebFilter` is the same class-declared shape with `doFilter` as the
// convention-named handler. A filter runs before any servlet and reads the
// same request, so omitting it omits the code every request passes through
// first. It serves every verb, so it pins none.
// kosi:want endpoint framework=servlet path=/admin/* fn=~AuditFilter mode=resolved
// kosi:want-not endpoint framework=servlet path=/admin/* method=GET
// Its reader names a query parameter exactly as a servlet's does.
// kosi:want endpoint framework=servlet path=/admin/* queryparam=audit mode=resolved
// The filter's request reader is a source like any other.
// kosi:want flow source=untrusted-input sink=process-exec fn=~AuditFilter known-fail=syntax:1
package fixtures.handlerinput

import javax.servlet.annotation.WebFilter
import javax.servlet.annotation.WebServlet
import javax.servlet.http.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@WebServlet("/run")
class RunServlet {

    /** The modelled reader is the source; the flow is real. */
    fun doGet(request: HttpServletRequest, response: HttpServletResponse): Process {
        response.sendRedirect("/done")
        return ProcessBuilder(request.getParameter("cmd")).start()
    }

    /**
     * The near-miss: the same handler shape, the same sink, but the value
     * comes from the RESPONSE parameter. Seeding handler parameters reports
     * this; reading the framework does not.
     */
    fun doPost(request: HttpServletRequest, response: HttpServletResponse): Process {
        response.sendRedirect("/done")
        return ProcessBuilder(response.toString()).start()
    }
}

/** Declared on the CLASS, handled by `doFilter`, serving every verb. */
@WebFilter("/admin/*")
class AuditFilter {
    fun doFilter(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain): Process {
        chain.doFilter(request, response)
        return ProcessBuilder(request.getParameter("audit")).start()
    }
}
