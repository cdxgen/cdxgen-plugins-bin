// The servlet request, in the shape the API declares it: the readers are
// METHODS with a literal key, which is where a servlet's parameter names
// live. Nothing in the signature names them.
package javax.servlet.http

interface HttpServletRequest {
    fun getParameter(name: String): String?
    fun getHeader(name: String): String?
}
