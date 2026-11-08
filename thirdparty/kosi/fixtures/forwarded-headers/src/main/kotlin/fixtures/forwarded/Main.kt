// Fixture for the forwarded-header rules: request values a client can choose
// through the Forwarded and X-Forwarded-* headers behind a pass-through proxy
// (proxy-derived sources), the config that turns forwarded-header handling on
// (trusted-proxy-config signals), and the twins each rule must not fire on.
// The servlet accessors are rewritten by container and framework middleware
// (Tomcat RemoteIpValve, Spring ForwardedHeaderFilter), which is why their
// reads are proxy-derived rather than generic request input.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want flow source=proxy-derived sink=ssrf fn=~remoteAddrEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~remoteHostEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~serverNameEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~requestUrlEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~schemeEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~uriBuilderEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~vertxRemoteAddressEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~vertxAuthorityEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~serverPortEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~secureEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~uriBuilderContextPathEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~uriBuilderRequestUriEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~uriBuilderServletPathEcho mode=resolved
// kosi:want flow source=proxy-derived sink=ssrf fn=~vertxHostEcho mode=resolved
//
// The negative half: getScheme on java.net.URI (the receiver gate the servlet
// patterns carry), a getRemoteAddr on an application interface, and the
// forwarded-header getHeader read, which stays untrusted-input because the
// pack matches callee FQNs and has no argument-literal channel.
//
// kosi:want-not flow source=proxy-derived sink=ssrf fn=~uriTwin
// kosi:want-not flow source=proxy-derived sink=ssrf fn=~localTwin
// kosi:want flow source=untrusted-input sink=ssrf fn=~headerEcho mode=resolved
//
// The config half: each framework's own symbol turns the signal on, the
// remove-only filter and the none strategy stay quiet.
//
// kosi:want signal code=trusted-proxy-config fn=~ForwardedHeaderFilter mode=resolved
// kosi:want-not signal code=trusted-proxy-config fn=~removeOnlyRegistration
// kosi:want signal code=trusted-proxy-config fn=~RemoteIpValve mode=resolved
// kosi:want signal code=trusted-proxy-config fn=~ForwardedRequestCustomizer mode=resolved
// kosi:want signal code=trusted-proxy-config fn=~forwardedheaders.ForwardedHeaders mode=resolved
// kosi:want signal code=trusted-proxy-config fn=~forwardedheaders.XForwardedHeaders mode=resolved
// kosi:want signal code=trusted-proxy-config fn=server.forward-headers-strategy mode=resolved
package fixtures.forwarded

import io.vertx.core.http.HttpServerRequest
import io.vertx.core.net.SocketAddress
import jakarta.servlet.http.HttpServletRequest
import java.net.URI
import org.apache.catalina.valves.RemoteIpValve
import org.eclipse.jetty.server.ForwardedRequestCustomizer
import org.springframework.web.filter.ForwardedHeaderFilter
import org.springframework.web.servlet.support.ServletUriComponentsBuilder

fun remoteAddrEcho(req: HttpServletRequest): URI = URI.create(req.remoteAddr)
fun remoteHostEcho(req: HttpServletRequest): URI = URI.create(req.remoteHost)
fun serverNameEcho(req: HttpServletRequest): URI = URI.create(req.serverName)
fun requestUrlEcho(req: HttpServletRequest): URI = URI.create(req.requestURL.toString())
fun schemeEcho(req: HttpServletRequest): URI = URI.create(req.scheme)
fun uriBuilderEcho(): URI = URI.create(ServletUriComponentsBuilder.fromCurrentRequest().toUriString())
fun vertxRemoteAddressEcho(req: HttpServerRequest): URI = URI.create(req.remoteAddress().toString())
fun vertxAuthorityEcho(req: HttpServerRequest): URI = URI.create(req.authority())

fun serverPortEcho(req: HttpServletRequest): URI = URI.create(req.serverPort.toString())
fun secureEcho(req: HttpServletRequest): URI = URI.create(req.isSecure().toString())
fun uriBuilderContextPathEcho(): URI = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().toUriString())
fun uriBuilderRequestUriEcho(): URI = URI.create(ServletUriComponentsBuilder.fromCurrentRequestUri().toUriString())
fun uriBuilderServletPathEcho(): URI = URI.create(ServletUriComponentsBuilder.fromCurrentServletPath().toUriString())
fun vertxHostEcho(req: HttpServerRequest): URI = URI.create(req.host())

/** java.net.URI's getScheme is not the servlet accessor: the receiver gate holds. */
fun uriTwin(uri: URI): URI = URI.create(uri.scheme)

/** An application interface with the same accessor name stays untagged. */
interface LocalRequest {
    fun getRemoteAddr(): String
}

fun localTwin(req: LocalRequest): URI = URI.create(req.getRemoteAddr())

/** A forwarded-header read by literal stays the generic request-input source. */
fun headerEcho(req: HttpServletRequest): URI = URI.create(req.getHeader("X-Forwarded-For") ?: "")

/** Spring's filter deriving from the headers. */
fun springFilterRegistration() {
    val filter = ForwardedHeaderFilter()
    // registration would follow; the construction is the config
}

/** Remove-only mode strips the headers instead of trusting them: no signal. */
fun removeOnlyRegistration() {
    val filter = ForwardedHeaderFilter()
    filter.setRemoveOnly(true)
}

fun tomcatValveConfig() {
    val valve = RemoteIpValve()
}

fun jettyCustomizerConfig() {
    val customizer = ForwardedRequestCustomizer()
}

fun ktorInstallForwarded() {
    io.ktor.server.application.install(io.ktor.server.plugins.forwardedheaders.ForwardedHeaders)
}

fun ktorInstallXForwarded() {
    io.ktor.server.application.install(io.ktor.server.plugins.forwardedheaders.XForwardedHeaders)
}
