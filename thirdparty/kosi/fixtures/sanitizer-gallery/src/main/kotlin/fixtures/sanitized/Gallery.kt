// P21 §2: the ten sanitizers that had never fired. R129 closed two of
// twelve by making their mechanism load-bearing; the depth report still
// read `fired: false` for the other ten, and a sanitizer that cannot be
// made to fire is a silent false-negative guarantee. This fixture is the
// R129 shape applied to all ten at once: the sanitized RESULT reaches the
// sink DIRECTLY, so with the pack entry present the flow is absent and
// with the entry REMOVED the unknown-call propagation carries the source's
// taint through the call and the want-not VIOLATES — which is the only
// proof that the entry's mechanism works (the security-pack liveness sweep
// re-proves it per entry, mechanically, on every test run).
//
// Every non-JDK class below is a real API, spelled with its real
// signature (the R102 rule): commons-lang3 3.x StringEscapeUtils,
// commons-text StringEscapeUtils, the OWASP Java Encoder's Encode,
// spring-web's HtmlUtils. The stubs carry the shapes only.
//
// The four positive controls pin each sink category's source→sink wiring,
// so the silence of the sanitized functions is the SANITIZER's doing and
// not a dead sink: rawPath, rawHtml, rawSql, rawLog all report.
//
// kosi:want-not diagnostic code=parse-error
//
// -- path-traversal -------------------------------------------------------
// kosi:want flow source=untrusted-input sink=path-traversal fn=~rawPath mode=resolved
// kosi:want-not flow source=untrusted-input sink=path-traversal fn=~canonicalPath mode=resolved
// kosi:want-not flow source=untrusted-input sink=path-traversal fn=~normalizedPath mode=resolved
//
// -- xss ------------------------------------------------------------------
// kosi:want flow source=untrusted-input sink=xss fn=~rawHtml mode=resolved
// kosi:want-not flow source=untrusted-input sink=xss fn=~lang3Escaped mode=resolved
// kosi:want-not flow source=untrusted-input sink=xss fn=~textEscaped mode=resolved
// kosi:want-not flow source=untrusted-input sink=xss fn=~owaspHtml mode=resolved
// kosi:want-not flow source=untrusted-input sink=xss fn=~owaspJs mode=resolved
// kosi:want-not flow source=untrusted-input sink=xss fn=~springEscaped mode=resolved
//
// -- ssrf (the URI-component encoder's own category set) -------------------
// kosi:want flow source=untrusted-input sink=ssrf fn=~rawUrl mode=resolved
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~owaspUri mode=resolved
//
// -- sql-query ------------------------------------------------------------
// kosi:want flow source=untrusted-input sink=sql-query fn=~rawSql mode=resolved
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~quotedPattern mode=resolved
//
// -- untrusted-input (normalizing shapes, log sink) ------------------------
// kosi:want flow source=untrusted-input sink=log-injection fn=~rawLog mode=resolved
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~parsedUuid mode=resolved
package fixtures.sanitized

import java.io.File
import java.io.PrintWriter
import java.net.URL
import java.nio.file.Paths
import java.sql.DriverManager
import java.util.UUID
import java.util.regex.Pattern
import org.apache.commons.lang3.StringEscapeUtils as Lang3Escape
import org.apache.commons.text.StringEscapeUtils as TextEscape
import org.owasp.encoder.Encode
import org.springframework.web.util.HtmlUtils

// -- path-traversal --------------------------------------------------------
// `java.io.File`'s constructor is the pack's path-traversal sink (argument 0).

fun rawPath() {
    val input = readLine() ?: return
    File(input)
}

fun canonicalPath() {
    val input = readLine() ?: return
    // java.io.File.getCanonicalPath clears path-traversal on its result.
    // The File is built from a Path, not from the raw string: the raw
    // `File(input)` constructor is itself the path-traversal sink, and the
    // flow must reach it only through the sanitizer (or, with the entry
    // removed, not at all).
    val safe = Paths.get(input).toFile().canonicalPath
    File(safe)
}

fun normalizedPath() {
    val input = readLine() ?: return
    // java.nio.file.Path.normalize clears path-traversal on its result.
    val safe = Paths.get(input).normalize()
    File(safe.toString())
}

// -- xss -------------------------------------------------------------------

fun rawHtml() {
    val input = readLine() ?: return
    val writer = PrintWriter(System.out)
    writer.print(input)
}

fun lang3Escaped() {
    val input = readLine() ?: return
    val safe = Lang3Escape.escapeHtml4(input)
    val writer = PrintWriter(System.out)
    writer.print(safe)
}

fun textEscaped() {
    val input = readLine() ?: return
    val safe = TextEscape.escapeHtml4(input)
    val writer = PrintWriter(System.out)
    writer.print(safe)
}

fun owaspHtml() {
    val input = readLine() ?: return
    val safe = Encode.forHtml(input)
    val writer = PrintWriter(System.out)
    writer.print(safe)
}

fun owaspJs() {
    val input = readLine() ?: return
    val safe = Encode.forJavaScript(input)
    val writer = PrintWriter(System.out)
    writer.print(safe)
}

fun springEscaped() {
    val input = readLine() ?: return
    val safe = HtmlUtils.htmlEscape(input)
    val writer = PrintWriter(System.out)
    writer.print(safe)
}

// -- ssrf ------------------------------------------------------------------

fun rawUrl() {
    val input = readLine() ?: return
    URL("https://api.example.internal/$input")
}

fun owaspUri() {
    val input = readLine() ?: return
    // org.owasp.encoder.Encode.forUriComponent clears xss, open-redirect and
    // ssrf on its result; the URI component is where the encoding belongs.
    val safe = Encode.forUriComponent(input)
    URL("https://api.example.internal/$safe")
}

// -- sql-query -------------------------------------------------------------

fun rawSql() {
    val input = readLine() ?: return
    val conn = DriverManager.getConnection("jdbc:h2:mem:test")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '$input'")
}

fun quotedPattern() {
    val input = readLine() ?: return
    // java.util.regex.Pattern.quote clears sql-query on its result: the
    // quoted text is a literal wherever it lands.
    val safe = Pattern.quote(input)
    val conn = DriverManager.getConnection("jdbc:h2:mem:test")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '$safe'")
}

// -- untrusted-input -------------------------------------------------------

fun rawLog() {
    val input = readLine() ?: return
    println(input)
}

fun parsedUuid() {
    val input = readLine() ?: return
    // java.util.UUID.fromString clears untrusted-input on its result.
    val safe = UUID.fromString(input)
    println(safe)
}
