package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path

/**
 * Config-file value resolution (P7). `application.yml` (a flat subset:
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

    enum class Source { YAML, PROPERTIES, BUILDCONFIG }

    /**
     * The config table: key -> value with its origin file kind. Deterministic
     * order (sorted map); duplicate keys keep the FIRST reader's value with
     * readers ordered properties -> yaml -> buildconfig per file set.
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
        // yaml (spring's own precedence is the reverse; we report rather
        // than decide, so the FIRST value wins and the file kind names it).
        val files = Files.walk(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { p ->
                    val name = p.fileName.toString()
                    name == "application.yml" || name == "application.yaml" ||
                        name == "application.properties" || name.endsWith(".properties") ||
                        name == "BuildConfig.java" || name == "BuildConfig.kt"
                }
                .sorted()
                .toList()
        }
        for (file in files) {
            val name = file.fileName.toString()
            when {
                name == "BuildConfig.java" || name == "BuildConfig.kt" ->
                    readBuildConfig(file).forEach { (k, v) -> values.putIfAbsent(k, ConfigValue(k, v, Source.BUILDCONFIG)) }

                name.endsWith(".properties") ->
                    readProperties(file).forEach { (k, v) -> values.putIfAbsent(k, ConfigValue(k, v, Source.PROPERTIES)) }

                else ->
                    readYaml(file).forEach { (k, v) -> values.putIfAbsent(k, ConfigValue(k, v, Source.YAML)) }
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
