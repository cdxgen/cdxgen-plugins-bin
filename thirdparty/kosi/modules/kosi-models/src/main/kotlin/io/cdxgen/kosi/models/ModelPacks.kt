package io.cdxgen.kosi.models

import io.cdxgen.kosi.schema.JsonReader

/**
 * Loads the shipped model packs from resources and merges user packs
 * (`--patterns`). Pack JSON is read with the hand-rolled reader; malformed
 * entries throw with the pack name and entry so the failure is actionable.
 */
object ModelPacks {

    const val SECURITY_PACK_RESOURCE = "/models/security-pack-v0.json"

    fun loadBuiltin(): ModelPack = loadResource(SECURITY_PACK_RESOURCE, "security-pack-v0")

    fun loadResource(resource: String, name: String): ModelPack {
        val text = javaClass.getResourceAsStream(resource)
            ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
            ?: throw IllegalStateException("builtin model pack missing: $resource")
        return parse(text, name)
    }

    fun parse(text: String, name: String): ModelPack {
        val root = JsonReader.parse(text).asObject()
        fun strings(key: String): List<String> = root.arr(key)?.strings() ?: emptyList()
        val sources = root.arr("sources")?.objects()?.map { entry ->
            SourcePattern(
                pattern = require(entry.str("pattern"), "sources[].pattern", name),
                category = require(entry.str("category"), "sources[].category", name),
            )
        } ?: emptyList()
        val sinks = root.arr("sinks")?.objects()?.map { entry ->
            SinkPattern(
                pattern = require(entry.str("pattern"), "sinks[].pattern", name),
                category = require(entry.str("category"), "sinks[].category", name),
                relevantArguments = entry.arr("relevantArguments")?.items?.map { it.asLong().toInt() } ?: emptyList(),
                receiverType = entry.str("receiverType"),
            )
        } ?: emptyList()
        val passthroughs = root.arr("passthroughs")?.objects()?.map { entry ->
            PassthroughPattern(
                pattern = require(entry.str("pattern"), "passthroughs[].pattern", name),
                category = require(entry.str("category"), "passthroughs[].category", name),
                flows = entry.arr("flows")?.items?.map { flow -> flow.asArray().items.map { it.asLong().toInt() } }
                    ?: emptyList(),
            )
        } ?: emptyList()
        val sanitizers = root.arr("sanitizers")?.objects()?.map { entry ->
            SanitizerPattern(
                pattern = require(entry.str("pattern"), "sanitizers[].pattern", name),
                clears = entry.arr("clears")?.strings() ?: emptyList(),
            )
        } ?: emptyList()
        val effects = root.arr("effects")?.objects()?.map { entry ->
            EffectPattern(
                pattern = require(entry.str("pattern"), "effects[].pattern", name),
                writesToArguments = entry.arr("writesToArguments")?.items?.map { it.asLong().toInt() } ?: emptyList(),
            )
        } ?: emptyList()
        return ModelPack(
            name = name,
            sources = sources,
            sinks = sinks,
            passthroughs = passthroughs,
            sanitizers = sanitizers,
            effects = effects,
        )
    }

    /** Merges packs; user packs win on identical patterns (last writer wins). */
    fun merge(builtin: ModelPack, user: List<ModelPack>): ModelPack {
        var merged = builtin
        for (pack in user) {
            merged = ModelPack(
                name = "${merged.name}+${pack.name}",
                sources = dedupe(merged.sources, pack.sources) { it.pattern },
                sinks = dedupe(merged.sinks, pack.sinks) { it.pattern },
                passthroughs = dedupe(merged.passthroughs, pack.passthroughs) { it.pattern },
                sanitizers = dedupe(merged.sanitizers, pack.sanitizers) { it.pattern },
                effects = dedupe(merged.effects, pack.effects) { it.pattern },
            )
        }
        return merged
    }

    private fun <T> dedupe(base: List<T>, overlay: List<T>, key: (T) -> String): List<T> {
        val byKey = LinkedHashMap<String, T>()
        base.forEach { byKey[key(it)] = it }
        overlay.forEach { byKey[key(it)] = it }
        return byKey.values.toList()
    }

    private fun require(value: String?, where: String, pack: String): String =
        value ?: throw IllegalStateException("model pack $pack: missing $where")
}

/**
 * The category registry used by the corpus annotation validator. Categories
 * are the union of the shipped packs' categories plus a small reserved core.
 * A `kosi:want flow source=<cat>` with a typo can never pass vacuously: it
 * fails validation before the engine runs.
 */
object Categories {

    /** Reserved names that must exist regardless of pack content. */
    val RESERVED = setOf(
        "untrusted-input", "android-intent", "process-exec", "sql-query",
        "path-traversal", "ssrf", "xss", "open-redirect", "log-injection",
        "deserialization", "hardcoded-secret", "weak-crypto", "ecb-mode",
        "insecure-tls", "crypto-asset", "iterator-adapter",
    )

    private val packCategories: Set<String> by lazy { ModelPacks.loadBuiltin().categories }

    /** The full validated vocabulary. */
    fun all(): Set<String> = RESERVED + packCategories

    fun isValid(category: String): Boolean {
        if (category.startsWith("~")) return all().any { it.endsWith(category.removePrefix("~")) }
        return category in all()
    }

    fun vocabularyError(category: String): String =
        "unknown category \"$category\"; add it to the shipped model packs (models/*.json) " +
            "or to Categories.RESERVED when the analyzer starts emitting it. " +
            "Known categories: ${all().sorted().joinToString(", ")}"
}

/**
 * The one pattern-matching rule shared by model packs, corpus expectations and
 * (later) the call-graph: a symbol matches a pattern when the pattern's
 * segments are a suffix of the symbol's segments, or the strings are equal.
 */
object PatternMatcher {

    fun matches(pattern: String, symbol: String): Boolean {
        if (pattern == symbol) return true
        val patternSegments = pattern.split('.')
        val symbolSegments = symbol.split('.')
        if (patternSegments.size > symbolSegments.size) return false
        return symbolSegments.takeLast(patternSegments.size) == patternSegments
    }
}
