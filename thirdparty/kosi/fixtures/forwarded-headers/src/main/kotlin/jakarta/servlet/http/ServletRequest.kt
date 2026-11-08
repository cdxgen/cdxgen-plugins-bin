// Stubs at the framework FQNs the pack patterns match; the shapes mirror the
// real declarations closely enough for the KIR the engine lowers.
package jakarta.servlet

interface ServletRequest {
    fun getRemoteAddr(): String
    fun getRemoteHost(): String
    fun getServerName(): String
    fun getServerPort(): Int
    fun getScheme(): String
    fun isSecure(): Boolean
}
