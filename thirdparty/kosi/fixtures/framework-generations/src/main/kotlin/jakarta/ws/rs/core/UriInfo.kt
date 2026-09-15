// The jakarta generation of the UriInfo reader surface.
package jakarta.ws.rs.core

interface UriInfo {
    fun getQueryParameters(): Map<String, String>
    fun getPathParameters(): Map<String, String>
}
