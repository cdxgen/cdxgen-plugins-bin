package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path

/**
 * Config-file value resolution. `application.yml` (a flat subset:
 * `key: value` lines with indentation ignored for keys, no anchors, no
 * lists), `*.properties` and `BuildConfig.{java,kt}` fields are read into a
 * table; a `${key}` template or a config-reader call with a literal key
 * resolves through it. Every value carries a resolution status — a value
 * kosi cannot prove is `unresolved`, never a guess and never dropped
 * silently.
 */
object ConfigResolver {

    /** One resolved (or unresolvable) value. */
    data class ConfigValue(
        val key: String,
        val value: String?,
        val source: Source,
    )

    enum class Source { YAML, PROPERTIES, BUILDCONFIG, HOCON }

    /**
     * The config table: key -> value with its origin file kind. Deterministic
     * order (sorted map).
     *
     * A key defined ONCE, or defined several times with the SAME value, has
     * that value. A key two files give DIFFERENT values is AMBIGUOUS and its
     * [ConfigValue.value] is null: the key is known, the value is not. That
     * is the discipline the `const val` tables already use — "a name holding
     * two values anywhere is ambiguous and is REFUSED, never guessed" — and
     * until this table did the opposite, keeping the FIRST reader's
     * value in sorted-path order and publishing it as a resolved fact (the
     * a later review). A multi-module repo where two modules'
     * `application.properties` both set `spring.datasource.url` published one
     * module's host, as a confident `resolution=config` service, chosen by
     * filename order. Two tables answered "what constant does this name
     * hold"; one refused ambiguity and one guessed (the rule).
     */
    class ConfigTable internal constructor(private val values: Map<String, ConfigValue>) {

        operator fun get(key: String): ConfigValue? = values[key]

        val size: Int get() = values.size

        fun keys(): Set<String> = values.keys

        companion object {
            val EMPTY = ConfigTable(emptyMap())
        }
    }

    fun load(root: Path): ConfigTable {
        if (!Files.isDirectory(root)) return ConfigTable.EMPTY
        val values = LinkedHashMap<String, ConfigValue>()
        // Deterministic discovery: sorted relative paths, properties before
        // yaml. We report rather than decide — which is why a key two files
        // DISAGREE about resolves to nothing (see [ConfigTable]) instead of
        // to whichever file sorted first.
        fun offer(key: String, value: String, source: Source) {
            val existing = values[key]
            when {
                existing == null -> values[key] = ConfigValue(key, value, source)
                // Already ambiguous, or the same value again: nothing to
                // decide either way.
                existing.value == null || existing.value == value -> Unit
                // Two files, two values, no ground to prefer one: the key is
                // known and its value is not.
                else -> values[key] = ConfigValue(key, null, existing.source)
            }
        }
        val files = Files.walk(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { p ->
                    val name = p.fileName.toString()
                    name == "application.yml" || name == "application.yaml" ||
                        name == "application.properties" || name.endsWith(".properties") ||
                        name == "application.conf" ||
                        name == "BuildConfig.java" || name == "BuildConfig.kt"
                }
                .sorted()
                .toList()
        }
        for (file in files) {
            val name = file.fileName.toString()
            when {
                name == "BuildConfig.java" || name == "BuildConfig.kt" ->
                    readBuildConfig(file).forEach { (k, v) -> offer(k, v, Source.BUILDCONFIG) }

                name.endsWith(".properties") ->
                    readProperties(file).forEach { (k, v) -> offer(k, v, Source.PROPERTIES) }

                name == "application.conf" ->
                    readHocon(file).forEach { (k, v) -> offer(k, v, Source.HOCON) }

                else ->
                    readYaml(file).forEach { (k, v) -> offer(k, v, Source.YAML) }
            }
        }
        return ConfigTable(values)
    }

    private fun readProperties(file: Path): Map<String, String> = try {
        val props = java.util.Properties()
        Files.newInputStream(file).use { props.load(it) }
        props.stringPropertyNames().sorted().associateWith { props.getProperty(it) }
    } catch (_: Exception) {
        emptyMap()
    }

    /**
     * The flat YAML subset: `key: value` lines, comments, quoted values
     * unquoted. Nesting is FLATTENED by indentation (a deeper key is joined
     * with dots) so `spring:` / `  datasource:` / `    url: x` reads as
     * `spring.datasource.url = x`. Documents starting with `---` and list
     * items are skipped; anything unparseable is skipped rather than guessed.
     */
    private fun readYaml(file: Path): Map<String, String> = try {
        val out = LinkedHashMap<String, String>()
        val stack = ArrayDeque<Pair<Int, String>>() // indent -> key segment
        for (rawLine in Files.readAllLines(file)) {
            val noComment = rawLine.substringBefore('#').trimEnd()
            val line = noComment.trim()
            if (line.isEmpty() || line == "---" || line.startsWith("- ")) continue
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val indent = rawLine.indexOfFirst { !it.isWhitespace() }.let { if (it < 0) 0 else it }
            val key = line.substring(0, colon).trim().removeSurrounding("\"").removeSurrounding("'")
            val value = line.substring(colon + 1).trim().removeSurrounding("\"").removeSurrounding("'")
            while (stack.isNotEmpty() && stack.last().first >= indent) stack.removeLast()
            stack.addLast(indent to key)
            if (value.isEmpty()) continue // a nested-table parent
            val fullKey = stack.joinToString(".") { it.second }
            out.putIfAbsent(fullKey, value)
        }
        out
    } catch (_: Exception) {
        emptyMap()
    }

    /**
     * HOCON `application.conf` — Ktor's default configuration file.
     *
     * `ktor.deployment.rootPath` is already a base-path key, but nothing
     * could ever supply it: a Ktor project does not have an
     * `application.properties` or a flat `application.yml`, it has a
     * BRACE-NESTED `application.conf`. Every Ktor deployment served under a
     * context path therefore had every one of its routes reported at the
     * wrong URL.
     *
     * The subset HOCON's own grammar makes unambiguous, flattened by brace
     * depth the way [readYaml] flattens by indentation: `key = value`,
     * `key value` (the separator is optional before an object), `key {` to
     * open a table and `}` to close it. Comments are `#` or `//`. An
     * `include`, a substitution (`${?PORT}`), a list and a multi-line string
     * are SKIPPED rather than guessed at — an unresolved value is the honest
     * answer and the config gate already counts it.
     */
    private fun readHocon(file: Path): Map<String, String> = try {
        val out = LinkedHashMap<String, String>()
        val path = ArrayDeque<String>()
        for (rawLine in Files.readAllLines(file)) {
            var line = rawLine.substringBefore('#').substringBefore("//").trim()
            if (line.isEmpty() || line.startsWith("include")) continue
            // A closing brace may trail a value (`deployment { port = 8080 }`),
            // so the line is consumed left to right rather than matched whole.
            while (line.isNotEmpty()) {
                if (line.startsWith("}")) {
                    if (path.isNotEmpty()) path.removeLast()
                    line = line.removePrefix("}").removePrefix(",").trim()
                    continue
                }
                val open = line.indexOf('{')
                val separator = line.indexOfFirst { it == '=' || it == ':' }
                if (open >= 0 && (separator < 0 || open < separator)) {
                    val key = line.substring(0, open).trim().trimEnd('=', ':').trim()
                        .removeSurrounding("\"")
                    if (key.isEmpty()) break
                    path.addLast(key)
                    line = line.substring(open + 1).trim()
                    continue
                }
                if (separator <= 0) break
                val key = line.substring(0, separator).trim().removeSurrounding("\"")
                var rest = line.substring(separator + 1).trim()
                // Only the text up to a closing brace belongs to this value.
                val close = rest.indexOf('}')
                val value = (if (close >= 0) rest.substring(0, close) else rest).trim().trimEnd(',')
                rest = if (close >= 0) rest.substring(close) else ""
                val unquoted = value.removeSurrounding("\"")
                if (key.isNotEmpty() && unquoted.isNotEmpty() &&
                    !unquoted.startsWith("[") && !unquoted.startsWith("\${")
                ) {
                    out.putIfAbsent((path + key).joinToString("."), unquoted)
                }
                line = rest
            }
        }
        out
    } catch (_: Exception) {
        emptyMap()
    }

    /**
     * BuildConfig fields: `public static final String NAME = "value";`
     * (Java) or `const val NAME = "value"` (Kotlin). Non-string fields are
     * skipped; the values are build-time constants, read as DATA.
     */
    private fun readBuildConfig(file: Path): Map<String, String> = try {
        val out = LinkedHashMap<String, String>()
        val regex = Regex("""(?:public\s+static\s+final\s+String|const\s+val)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"""")
        for (line in Files.readAllLines(file)) {
            val match = regex.find(line) ?: continue
            out.putIfAbsent(match.groupValues[1], match.groupValues[2])
        }
        out
    } catch (_: Exception) {
        emptyMap()
    }

    /** A string's provenance: how kosi knows what it contains. */
    enum class Status { LITERAL, FOLDED, CONFIG, ENV, UNRESOLVED }

    /**
     * Resolves a `${key}` template against the table. Fully resolved ->
     * CONFIG with the substituted value; a template naming an unknown key ->
     * UNRESOLVED; no template at all -> null (the caller keeps its own
     * literal status).
     */
    fun resolveTemplate(text: String, table: ConfigTable): Pair<String?, Status> {
        val regex = Regex("\\$\\{([^}]+)}")
        if (!regex.containsMatchIn(text)) return text to Status.LITERAL
        var fullyResolved = true
        val out = regex.replace(text) { match ->
            val key = match.groupValues[1].trim()
            val value = table[key]?.value
            if (value == null) {
                fullyResolved = false
                match.value
            } else {
                value
            }
        }
        return if (fullyResolved) out to Status.CONFIG else null to Status.UNRESOLVED
    }
}
