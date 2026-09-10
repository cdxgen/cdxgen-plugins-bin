package io.cdxgen.kosi.models

/**
 * Model-pack patterns (02-ARCHITECTURE.md §7). The tuple notation `flows`
 * and the argument indexes follow Tai-e: `-1` = the call's result, `0` = the
 * RECEIVER when the callee has one (otherwise the first argument), `n` = the
 * n-th element of that (receiver,) arguments sequence. Constructor callees
 * render as the class FQN with no `<init>` suffix, so a constructor's first
 * parameter is index 0. P4 executes these packs for the first time; the
 * argument convention and the renderer it must match are pinned by
 * ModelPackTest and by the taint fixtures.
 *
 * Pattern notation is a single normalised form: a dot-separated,
 * generic-free, whitespace-free symbol path, matched against the canonical
 * renderer's output by suffix-segment match (see [PatternMatcher]). The
 * shipped packs are validated against real renderer output by a test in this
 * module, so a pattern that can never match anything fails the build.
 */
data class SourcePattern(
    val pattern: String,
    val category: String,
) {
    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.str("category", category)
        w.str("pattern", pattern)
        w.endObject()
    }
}

data class SinkPattern(
    val pattern: String,
    val category: String,
    val relevantArguments: List<Int>,
    val receiverType: String?,
    /**
     * Severity as DATA (P4): the slice's severity comes from the matched
     * pack entry, never from a code-side category table. Packs that omit it
     * get "high" — the honest default for an unnamed risk.
     */
    val severity: String = "high",
) {
    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.str("category", category)
        w.beginArray("relevantArguments")
        for (a in relevantArguments) w.num(a.toLong())
        w.endArray()
        w.str("pattern", pattern)
        w.str("receiverType", receiverType)
        w.str("severity", severity)
        w.endObject()
    }
}

data class PassthroughPattern(
    val pattern: String,
    val category: String,
    val flows: List<List<Int>>,
    /**
     * Element flows: same tuple notation, but index 0 reads the RECEIVER's
     * ELEMENT state (`xs[...]`, a channel's sent values) instead of the
     * receiver value itself — how `Channel.receive` yields what `send`
     * delivered (P6).
     */
    val elementFlows: List<List<Int>> = emptyList(),
) {
    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.str("category", category)
        w.beginArray("flows")
        for (flow in flows) {
            w.beginArray()
            for (i in flow) w.num(i.toLong())
            w.endArray()
        }
        w.endArray()
        w.str("pattern", pattern)
        w.endObject()
    }
}

data class SanitizerPattern(
    val pattern: String,
    val clears: List<String>,
) {
    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.beginArray("clears")
        for (c in clears) w.str(c)
        w.endArray()
        w.str("pattern", pattern)
        w.endObject()
    }
}

data class EffectPattern(
    val pattern: String,
    val writesToArguments: List<Int>,
) {
    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.str("pattern", pattern)
        w.beginArray("writesToArguments")
        for (a in writesToArguments) w.num(a.toLong())
        w.endArray()
        w.endObject()
    }
}

data class ModelPack(
    val name: String,
    val sources: List<SourcePattern>,
    val sinks: List<SinkPattern>,
    val passthroughs: List<PassthroughPattern>,
    val sanitizers: List<SanitizerPattern>,
    val effects: List<EffectPattern>,
) {
    /** Every distinct category this pack can produce (sources and sinks). */
    val categories: Set<String>
        get() = sources.map { it.category }.toSet() + sinks.map { it.category }.toSet()
}
