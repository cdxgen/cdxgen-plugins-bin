// The server-side sink families the model pass added, restricted to what
// the JDK itself provides so the fixture needs no third-party jar: JNDI
// lookup, XML external entities, dynamic code execution, deserialization,
// SSRF through the JDK HTTP client, and the sanitizers that legitimately
// stop each one. The library-specific members of these families (Spring,
// Ktor, Hibernate, the AI and MCP SDKs, the cloud SDKs) are modelled in the
// same categories but are NOT exercised here — docs/KOSI.md names them.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// One positive per family.
// kosi:want flow source=untrusted-input sink=jndi-injection fn=~jndiLookup known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=code-execution fn=~reflectiveLoad known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=deserialization fn=~decodeObject known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=ssrf fn=~fetchRemote known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=xxe fn=~parseXml known-fail=syntax:1
//
// The near-misses. Each reaches the SAME sink with a value that is either a
// constant or has passed the sanitizer that actually clears this category —
// an implementation that ignored sanitizers, or marked every argument
// tainted, would report on these.
// kosi:want-not flow source=~ sink=jndi-injection fn=~jndiLookupConstant
// kosi:want-not flow source=~ sink=code-execution fn=~reflectiveLoadConstant
// kosi:want-not flow source=~ sink=ssrf fn=~fetchRemoteEncoded
package fixtures.serversidetaint

import java.io.BufferedReader
import java.io.ObjectInputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpRequest
import javax.naming.InitialContext
import javax.xml.parsers.DocumentBuilderFactory

/** JNDI lookup on an attacker-supplied name — the log4shell shape. */
fun jndiLookup(reader: BufferedReader) {
    InitialContext().lookup(reader.readLine())
}

/** The near-miss: the same lookup, a constant name. */
fun jndiLookupConstant() {
    InitialContext().lookup("java:comp/env/jdbc/appDs")
}

/** A class name from input, loaded reflectively. */
fun reflectiveLoad(reader: BufferedReader): Class<*> = Class.forName(reader.readLine())

/** The near-miss: a constant class name. */
fun reflectiveLoadConstant(): Class<*> = Class.forName("java.lang.String")

/** Java deserialization of an attacker-controlled stream. */
fun decodeObject(reader: BufferedReader): Any? {
    val bytes = reader.readLine().toByteArray()
    return ObjectInputStream(bytes.inputStream()).readObject()
}

/** SSRF: the request URI comes from input. */
fun fetchRemote(reader: BufferedReader): HttpRequest =
    HttpRequest.newBuilder().uri(URI.create(reader.readLine())).build()

/**
 * The near-miss: the same sink, but the value is URL-encoded first, which
 * the pack registers as clearing this category — so it can only be a
 * component of a fixed URL, never the host.
 */
fun fetchRemoteEncoded(reader: BufferedReader): HttpRequest {
    val safe = URLEncoder.encode(reader.readLine(), "UTF-8")
    return HttpRequest.newBuilder().uri(URI.create("https://example.invalid/q?v=$safe")).build()
}

/** XXE: an externally supplied document parsed with a default factory. */
fun parseXml(reader: BufferedReader) {
    val builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    builder.parse(reader.readLine())
}
