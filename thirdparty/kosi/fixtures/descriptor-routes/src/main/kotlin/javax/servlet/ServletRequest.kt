// The BASE interface a filter's doFilter receives (jakarta.servlet.Filter:
// doFilter(ServletRequest, ServletResponse, FilterChain)). A filter that
// reads a parameter sees ServletRequest.getParameter, not the HTTP-facing
// HttpServletRequest.getParameter — a different symbol, and for exactly the
// code an audit cares about first.
package javax.servlet

interface ServletRequest {
    fun getParameter(name: String): String?
}
