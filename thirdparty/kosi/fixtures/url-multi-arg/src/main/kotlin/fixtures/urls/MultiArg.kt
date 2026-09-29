// The multi-argument URL and URI constructors take the host (or the spec
// resolved against a context) past argument 0.
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~fixedHost mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=ssrf fn=~urlHost mode=endpoint
// kosi:want flow source=untrusted-input sink=ssrf fn=~urlSpec mode=endpoint
// kosi:want flow source=untrusted-input sink=ssrf fn=~uriHost mode=endpoint
// kosi:want flow source=untrusted-input sink=ssrf fn=~uriServer mode=endpoint
package fixtures.urls

import java.io.InputStream
import java.net.URI
import java.net.URL
import java.net.URLConnection

fun urlHost(): URLConnection {
    val host = readLine() ?: "x"
    return URL("https", host, "/status").openConnection()
}

fun urlSpec(): URLConnection {
    val spec = readLine() ?: "x"
    return URL(URL("https://api.internal/"), spec).openConnection()
}

fun uriHost(): InputStream {
    val host = readLine() ?: "x"
    return URI("https", host, "/p", null).toURL().openStream()
}

fun uriServer(): InputStream {
    val host = readLine() ?: "x"
    return URI("https", null, host, 443, "/p", null, null).toURL().openStream()
}

fun fixedHost(): URLConnection {
    val host = readLine() ?: "x"
    println(host)
    return URL("https", "api.internal", "/status").openConnection()
}
