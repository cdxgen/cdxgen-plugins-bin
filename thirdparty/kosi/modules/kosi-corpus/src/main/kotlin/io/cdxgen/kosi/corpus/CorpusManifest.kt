package io.cdxgen.kosi.corpus

import java.nio.file.Files
import java.nio.file.Path

/**
 * Minimal parser for corpus.toml — the subset of TOML the corpus uses:
 * `[[fixtures]]` array tables plus `key = "string"` / `key = [...]` string
 * arrays. No TOML library (the dependency allowlist is closed). Entry order
 * is preserved so the bench runs fixtures deterministically.
 */
data class CorpusEntry(
    val slug: String,
    val tier: String,
    val path: String?,
    val repo: String?,
    val sha: String?,
    val capabilities: List<String>,
    val expectedFlows: String?,
    val features: List<String>,
) {
    fun validate() {
        if (path == null && repo == null) {
            throw IllegalArgumentException("corpus.toml entry $slug: either path or repo is required")
        }
        if (repo != null && sha == null) {
            throw IllegalArgumentException("corpus.toml entry $slug: repo entries must pin an exact sha")
        }
        if (slug.isBlank()) {
            throw IllegalArgumentException("corpus.toml entry: slug must not be blank")
        }
    }
}

data class CorpusManifest(
    val entries: List<CorpusEntry>,
) {
    fun select(tiers: Set<String>, only: String? = null): List<CorpusEntry> =
        entries.filter { it.tier in tiers && (only == null || it.slug == only) }

    companion object {
        fun parse(text: String): CorpusManifest {
            val tables = mutableListOf<LinkedHashMap<String, Any?>>()
            var current: LinkedHashMap<String, Any?>? = null
            text.lines().forEachIndexed { index, rawLine ->
                val lineNo = index + 1
                val line = rawLine.substringBefore('#').trim()
                if (line.isEmpty()) return@forEachIndexed
                Regex("""^\[\[fixtures]]$""").matchEntire(line)?.let {
                    current = linkedMapOf()
                    tables.add(current!!)
                    return@forEachIndexed
                }
                Regex("""^\[\[[a-zA-Z]+]]$""").matchEntire(line)?.let {
                    throw IllegalArgumentException(
                        "corpus.toml:$lineNo: unknown array table $line (only [[fixtures]] is supported)",
                    )
                }
                Regex("""^\[[a-zA-Z]+]$""").matchEntire(line)?.let {
                    throw IllegalArgumentException("corpus.toml:$lineNo: unsupported table $line")
                }
                val kv = Regex("""^([a-zA-Z_]+)\s*=\s*(.+)$""").find(line)
                    ?: throw IllegalArgumentException("corpus.toml:$lineNo: cannot parse '$rawLine'")
                val (key, value) = kv.destructured
                val parsed: Any = if (value.startsWith("[")) {
                    Regex(""""([^"]*)"""").findAll(value).map { it.groupValues[1] }.toList()
                } else if (value.startsWith("\"")) {
                    value.removeSurrounding("\"")
                } else {
                    throw IllegalArgumentException("corpus.toml:$lineNo: unsupported value for $key: $value")
                }
                val table = current
                    ?: throw IllegalArgumentException("corpus.toml:$lineNo: key outside a [[fixtures]] table")
                table[key] = parsed
            }
            val entries = tables.map { table -> entryFrom(table) }
            entries.forEach { it.validate() }
            return CorpusManifest(entries)
        }

        fun load(file: Path): CorpusManifest = parse(Files.readString(file))

        private fun entryFrom(table: LinkedHashMap<String, Any?>): CorpusEntry {
            fun str(key: String): String? = table[key] as? String
            @Suppress("UNCHECKED_CAST")
            fun list(key: String): List<String> = (table[key] as? List<String>) ?: emptyList()
            return CorpusEntry(
                slug = str("slug") ?: throw IllegalArgumentException("corpus.toml entry missing slug"),
                tier = str("tier") ?: throw IllegalArgumentException("corpus.toml entry ${str("slug")} missing tier"),
                path = str("path"),
                repo = str("repo"),
                sha = str("sha"),
                capabilities = list("capabilities"),
                expectedFlows = str("expected_flows"),
                features = list("features"),
            )
        }
    }
}
