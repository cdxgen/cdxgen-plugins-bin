package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path

/**
 * `WEB-INF/web.xml` servlet and filter mappings.
 *
 * A servlet's route does not have to be an annotation. The deployment
 * descriptor has been the JVM's way of mapping URLs to classes since long
 * before `@WebServlet`, and it is still how most inherited applications do
 * it — so a scanner that only reads annotations reports NO endpoints for
 * them while the application serves dozens. It also carries the one piece
 * of information nothing else has: an `<url-pattern>` may map several
 * patterns to one class, and a class may be mapped under a name that
 * appears nowhere in the source.
 *
 * A tolerant scanner over the descriptor's fixed shape, in the same spirit
 * as [AndroidManifestParser] — not a general XML parser. It joins two pairs
 * of elements: `<servlet>`/`<servlet-mapping>` and `<filter>`/
 * `<filter-mapping>`, each pairing a name to a class and a name to url
 * patterns. A mapping whose name has no declaring element is dropped rather
 * than guessed at.
 */
object WebXmlParser {

    /** One mapped class and every URL pattern the descriptor maps to it. */
    data class ServletMapping(
        val file: String,
        val className: String,
        val urlPatterns: List<String>,
        /** `servlet` or `filter` — a filter's handler is `doFilter` and it serves every verb. */
        val kind: String = KIND_SERVLET,
        /** `descriptor` for web.xml; `dsl` for a registration bean in code. */
        val foundBy: String = "descriptor",
    )

    const val KIND_SERVLET: String = "servlet"
    const val KIND_FILTER: String = "filter"

    /**
     * A `<security-constraint>`: the deployment descriptor's own
     * authentication requirement. The patterns it constrains come
     * from its `<web-resource-collection>`s; the roles that may access
     * them from `<auth-constraint><role-name>`. An EMPTY
     * `<auth-constraint/>` is the descriptor's DENY-ALL (no role may
     * access); an absent `<auth-constraint>` means the constraint only
     * constrains transport (USER-DATA-CONSTRAINT), not who may call —
     * authentication is not declared there, and the constraint is not
     * published as one.
     */
    data class SecurityConstraint(
        val urlPatterns: List<String>,
        val roles: List<String>,
        /** An empty `<auth-constraint/>`: DENY-ALL, no role may access. */
        val denyAll: Boolean,
    )

    fun parse(root: Path): List<ServletMapping> {
        if (!Files.isDirectory(root)) return emptyList()
        val descriptors = Files.walk(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { it.fileName.toString() == "web.xml" }
                .filter { it.parent?.fileName?.toString() == "WEB-INF" }
                .sorted()
                .toList()
        }
        val out = mutableListOf<ServletMapping>()
        for (descriptor in descriptors) {
            val text = try {
                Files.readString(descriptor)
            } catch (_: Exception) {
                continue
            }
            out.addAll(parseText(text, descriptor.toString()))
        }
        return out.sortedWith(compareBy({ it.kind }, { it.className }, { it.urlPatterns.firstOrNull() ?: "" }))
    }

    /** Every `<security-constraint>` in the descriptor, in document order. */
    fun securityConstraints(root: Path): List<SecurityConstraint> {
        if (!Files.isDirectory(root)) return emptyList()
        val descriptors = Files.walk(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { it.fileName.toString() == "web.xml" }
                .filter { it.parent?.fileName?.toString() == "WEB-INF" }
                .sorted()
                .toList()
        }
        val out = mutableListOf<SecurityConstraint>()
        for (descriptor in descriptors) {
            val text = try {
                Files.readString(descriptor)
            } catch (_: Exception) {
                continue
            }
            out.addAll(securityConstraintsOf(text))
        }
        return out
    }

    internal fun securityConstraintsOf(text: String): List<SecurityConstraint> {
        val stripped = text.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
        return elements(stripped, "security-constraint").mapNotNull { element ->
            val patterns = elements(element, "web-resource-collection")
                .flatMap { children(it, "url-pattern") }
                .distinct()
                .sorted()
            if (patterns.isEmpty()) return@mapNotNull null
            // `<auth-constraint/>` with no role children is DENY-ALL; an
            // absent element constrains transport only, not access. The
            // element matcher pairs opening and closing tags, so the
            // SELF-CLOSING deny-all form is recognised separately.
            val authElements = elements(element, "auth-constraint")
            val selfClosingDenyAll = SELF_CLOSING_AUTH_CONSTRAINT.containsMatchIn(element)
            if (authElements.isEmpty() && !selfClosingDenyAll) return@mapNotNull null
            val roles = authElements.flatMap { children(it, "role-name") }.distinct().sorted()
            SecurityConstraint(patterns, roles, denyAll = roles.isEmpty())
        }
    }

    private val SELF_CLOSING_AUTH_CONSTRAINT = Regex("""<auth-constraint\s*/>""")

    internal fun parseText(text: String, file: String): List<ServletMapping> {
        val stripped = text.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
        // name -> class, from <servlet>; name -> patterns, from <servlet-mapping>.
        val classByName = LinkedHashMap<String, String>()
        for (element in elements(stripped, "servlet")) {
            val name = child(element, "servlet-name") ?: continue
            val className = child(element, "servlet-class") ?: continue
            classByName.putIfAbsent(name, className)
        }
        val patternsByName = LinkedHashMap<String, MutableList<String>>()
        for (element in elements(stripped, "servlet-mapping")) {
            val name = child(element, "servlet-name") ?: continue
            val patterns = children(element, "url-pattern")
            if (patterns.isEmpty()) continue
            patternsByName.getOrPut(name) { mutableListOf() }.addAll(patterns)
        }
        val servlets = patternsByName.mapNotNull { (name, patterns) ->
            val className = classByName[name] ?: return@mapNotNull null
            ServletMapping(file, className, patterns.distinct().sorted(), KIND_SERVLET)
        }
        return servlets + filters(stripped, file, patternsByName)
    }

    /**
     * `<filter-mapping>` — the descriptor half a servlet scanner skips, and
     * the one that matters most for taint.
     *
     * A filter mapped to every path sees every request to the application before
     * any servlet does; its `doFilter` reads the same `HttpServletRequest`,
     * and authentication, rewriting and audit logic live there. Reporting
     * the servlets and not the filters reports the application's handlers
     * while omitting the code every request passes through first.
     *
     * A filter may be mapped by URL pattern OR by `<servlet-name>`, in which
     * case it inherits the patterns of the servlet it wraps — resolved here
     * rather than dropped, because `<servlet-name>` is the more common form
     * in descriptors that map a filter onto one endpoint. `*` as the servlet
     * name is the descriptor's own wildcard and means every request.
     */
    private fun filters(
        text: String,
        file: String,
        servletPatternsByName: Map<String, MutableList<String>>,
    ): List<ServletMapping> {
        val classByName = LinkedHashMap<String, String>()
        for (element in elements(text, "filter")) {
            val name = child(element, "filter-name") ?: continue
            val className = child(element, "filter-class") ?: continue
            classByName.putIfAbsent(name, className)
        }
        if (classByName.isEmpty()) return emptyList()
        val patternsByName = LinkedHashMap<String, MutableList<String>>()
        for (element in elements(text, "filter-mapping")) {
            val name = child(element, "filter-name") ?: continue
            val patterns = children(element, "url-pattern").toMutableList()
            for (servletName in children(element, "servlet-name")) {
                if (servletName == "*") patterns.add("/*")
                else patterns.addAll(servletPatternsByName[servletName].orEmpty())
            }
            if (patterns.isEmpty()) continue
            patternsByName.getOrPut(name) { mutableListOf() }.addAll(patterns)
        }
        return patternsByName.mapNotNull { (name, patterns) ->
            val className = classByName[name] ?: return@mapNotNull null
            ServletMapping(file, className, patterns.distinct().sorted(), KIND_FILTER)
        }
    }

    /**
     * The bodies of every `<tag>...</tag>`. `<servlet-mapping>` shares a
     * prefix with `<servlet>`, so the opening tag must end at `>` or
     * whitespace — matching on the prefix alone would read every mapping as
     * a servlet element and pair names with the wrong classes.
     */
    private fun elements(text: String, tag: String): List<String> =
        Regex("<$tag(?:\\s[^>]*)?>(.*?)</$tag>", RegexOption.DOT_MATCHES_ALL)
            .findAll(text)
            .map { it.groupValues[1] }
            .toList()

    private fun children(text: String, tag: String): List<String> =
        Regex("<$tag(?:\\s[^>]*)?>(.*?)</$tag>", RegexOption.DOT_MATCHES_ALL)
            .findAll(text)
            .map { it.groupValues[1].trim() }
            .filter { it.isNotEmpty() }
            .toList()

    private fun child(text: String, tag: String): String? = children(text, tag).firstOrNull()
}
