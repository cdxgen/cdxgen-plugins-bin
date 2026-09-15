// The javax (JAX-RS 2.x / Jakarta EE 8 and older) generation of the reader
// surface the pack already modelled for jakarta. Every class here is a
// stub at the framework's REAL package name, so resolution produces the
// exact symbols the pack matches.
package javax.ws.rs.core

interface UriInfo {
    fun getPathParameters(): Map<String, String>
    fun getQueryParameters(): Map<String, String>
}
