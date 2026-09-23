// Minimal stand-ins for the servlet request/response, at their real names,
// so the fixture needs no servlet jar.
package javax.servlet.http

class HttpServletRequest {
    fun getParameter(name: String): String = ""
    fun getHeader(name: String): String = ""
}

class HttpServletResponse {
    fun sendRedirect(location: String) {}
}

class FilterChain {
    fun doFilter(request: HttpServletRequest, response: HttpServletResponse) {}
}
