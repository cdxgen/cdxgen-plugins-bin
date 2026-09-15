// The jakarta (Servlet 5+ / Spring Boot 3) generation of the servlet API.
// The javax twin is pinned by `handler-input-semantics`; this fixture pins
// that the jakarta names detect and seed exactly the same way.
package jakarta.servlet.http

interface HttpServletRequest {
    fun getParameter(name: String): String?
    fun getHeader(name: String): String?
}
