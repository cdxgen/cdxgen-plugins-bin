package io.cdxgen.kosi.flow

/**
 * Taint written into STATIC fields — a property of an `object`, a companion
 * object, or a file's top level, which the lowering keys on one never-stored
 * `vstatic:<owner>` base (see `BodyLower.staticField`). A static has no
 * scope: `H.last = input` in one handler and `exec(H.last)` in another share
 * the field, but every function is analysed from an empty state, so the
 * write reached nothing. The seeds are what a run's writes put there, keyed
 * by (base, path suffix) with the categories written; a later pass births
 * them at every read of the field, the way a pack source births at its call.
 *
 * `held.set(x)` on a static `ThreadLocal` writes the ELEMENT state of the
 * object the field holds: seeded as `<path>.[]`, and born on the read's
 * element state, where `held.get()` reads it.
 */
internal data class StaticSeeds(
    val seeds: Map<String, Map<String, Set<String>>>,
    /** The functions that wrote each base, for naming a seeded read's source. */
    val writers: Map<String, Set<String>> = emptyMap(),
) {

    fun isEmpty(): Boolean = seeds.isEmpty()

    /**
     * What a read of [base] at [suffix] carries: `("", category)` for a
     * value written into the field, `("[]", category)` for one written into
     * the element state of the object it holds.
     */
    fun birthsAt(base: String, suffix: String): List<Pair<String, String>> {
        val bySuffix = seeds[base] ?: return emptyList()
        val out = mutableListOf<Pair<String, String>>()
        bySuffix[suffix]?.forEach { out.add("" to it) }
        bySuffix[if (suffix.isEmpty()) "[]" else "$suffix.[]"]?.forEach { out.add("[]" to it) }
        return out
    }

    /** A seeded read's source name: the field and who wrote it. */
    fun sourceName(read: io.cdxgen.kosi.kir.KirFieldGet): String {
        val written = writers[read.receiver].orEmpty()
        val by = when {
            written.isEmpty() -> ""
            written.size <= 3 -> " written in " + written.joinToString(", ")
            else -> " written in " + written.take(3).joinToString(", ") + " and ${written.size - 3} more"
        }
        return "static " + staticFieldName(read) + by
    }

    companion object {
        val NONE = StaticSeeds(emptyMap())
    }
}

/** Collects the static writes of one reporting sweep, deterministically. */
internal class StaticSeedCollector {
    private val lock = Any()
    private val writes = java.util.TreeMap<String, java.util.TreeMap<String, java.util.TreeSet<String>>>()
    private val writers = java.util.TreeMap<String, java.util.TreeSet<String>>()

    fun record(base: String, suffix: String, categories: Collection<String>, writer: String) = synchronized(lock) {
        if (categories.isEmpty()) return@synchronized
        writes.getOrPut(base) { java.util.TreeMap() }.getOrPut(suffix) { java.util.TreeSet() }.addAll(categories)
        writers.getOrPut(base) { java.util.TreeSet() }.add(writer)
    }

    fun seeds(): StaticSeeds = synchronized(lock) {
        StaticSeeds(
            writes.mapValues { (_, bySuffix) -> bySuffix.mapValues { (_, categories) -> categories.toSortedSet() } },
            writers.mapValues { (_, functions) -> functions.toSortedSet() },
        )
    }
}

internal const val STATIC_BASE_PREFIX = "vstatic:"

/** A read of a static field: where a seed births (see [StaticSeeds]). */
internal fun isStaticRead(ins: io.cdxgen.kosi.kir.KirIns): Boolean =
    ins is io.cdxgen.kosi.kir.KirFieldGet && ins.receiver.startsWith(STATIC_BASE_PREFIX)

/** The dotted name a static field read names, for a slice's source: `fixtures.H.Companion.last`. */
internal fun staticFieldName(read: io.cdxgen.kosi.kir.KirFieldGet): String {
    val owner = read.receiver.removePrefix(STATIC_BASE_PREFIX).replace('/', '.')
    val path = read.path.elements.joinToString(".") { element ->
        when (element) {
            is io.cdxgen.kosi.kir.AccessPath.Element.Field -> element.name
            io.cdxgen.kosi.kir.AccessPath.Element.Index -> "[]"
            io.cdxgen.kosi.kir.AccessPath.Element.Star -> "*"
        }
    }
    return if (path.isEmpty()) owner else "$owner.$path"
}
