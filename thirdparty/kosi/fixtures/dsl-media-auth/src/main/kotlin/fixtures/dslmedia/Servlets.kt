// Descriptor-mapped servlets: nothing in this source says a URL. The
// authentication each carries comes from the <security-constraint> elements
// of WEB-INF/web.xml — the /legacy prefix constraint (admin, auditor), the
// transport-only constraint on /public (no auth-constraint element: NO
// access requirement), and the empty auth-constraint on /denied (DENY-ALL).
package fixtures.dslmedia

import javax.servlet.http.HttpServletRequest

class LegacyServlet {
    fun doGet(request: HttpServletRequest): String = request.getParameter("format") ?: ""
}

class PublicServlet {
    fun doGet(request: HttpServletRequest): String = request.getParameter("q") ?: ""
}

class DeniedServlet {
    fun doGet(request: HttpServletRequest): String = request.getParameter("x") ?: ""
}
