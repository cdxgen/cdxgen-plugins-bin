package io.cdxgen.kosi.graph

/**
 * Symbol classification for the graph breakdown (03-SCHEMA.md stats). The
 * four buckets are a DISJOINT partition of the node set so a breakdown can be
 * checked against its total: synthetic first (a synthesized member is
 * synthetic regardless of where it lives), then local, then stdlib, then
 * dependency. Edges classify by their TARGET — a call into the stdlib is a
 * stdlib edge, whoever made it.
 */
object Classification {

    /**
     * Prefixes treated as "stdlib" for `--include-stdlib` and the breakdown:
     * the Kotlin stdlib and the JDK module library. `kotlinx.*` is NOT here —
     * coroutines and serialization are versioned libraries, i.e. dependencies.
     */
    private val STDLIB_PREFIXES = listOf(
        "kotlin.",
        "java.",
        "javax.",
        "jdk.",
        "sun.",
        "com.sun.",
    )

    enum class Bucket { SYNTHETIC, LOCAL, STDLIB, DEPENDENCY }

    fun bucketOf(fqn: String, local: Boolean, synthetic: Boolean): Bucket = when {
        synthetic -> Bucket.SYNTHETIC
        local -> Bucket.LOCAL
        isStdlib(fqn) -> Bucket.STDLIB
        else -> Bucket.DEPENDENCY
    }

    fun isStdlib(fqn: String): Boolean = STDLIB_PREFIXES.any { fqn.startsWith(it) || fqn == it.removeSuffix(".") }

    /**
     * The dotted package prefix of a canonical symbol (everything before the
     * last segment); collapsed edges collect the packages they traverse.
     */
    fun packageOf(fqn: String): String = when (val idx = fqn.lastIndexOf('.')) {
        -1 -> ""
        else -> fqn.substring(0, idx)
    }

    /**
     * Pattern-notation suffix match (JSON_ATTRIBUTE_REFERENCE.md): the
     * pattern's segments are a suffix of the symbol's segments, so
     * `RestController` matches `org.springframework.web.bind.annotation.RestController`.
     */
    fun suffixMatches(pattern: String, fqn: String): Boolean {
        if (pattern.isEmpty()) return false
        val p = pattern.split('.')
        val f = fqn.split('.')
        if (p.size > f.size) return false
        return p.withIndex().all { (i, seg) -> f[f.size - p.size + i] == seg }
    }
}
