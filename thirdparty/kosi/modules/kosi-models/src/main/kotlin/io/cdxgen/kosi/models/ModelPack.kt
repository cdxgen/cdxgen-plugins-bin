package io.cdxgen.kosi.models

/**
 * Model-pack patterns (02-ARCHITECTURE.md §7). The tuple notation `flows`
 * and the argument indexes follow Tai-e: `-1` = the call's result, `0` = the
 * RECEIVER when the callee has one (otherwise the first argument), `n` = the
 * n-th element of that (receiver,) arguments sequence. Constructor callees
 * render as the class FQN with no `<init>` suffix, so a constructor's first
 * parameter is index 0. Executes these packs for the first time; the
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
     * Severity as DATA: the slice's severity comes from the matched
     * pack entry, never from a code-side category table. Packs that omit it
     * get "high" — the honest default for an unnamed risk.
     */
    val severity: String = "high",
    /**
     * The position of a VARARG parameter: every argument from here on is
     * relevant too. A vararg's written arguments occupy adjacent positions
     * (`ProcessBuilder("sh", "-c", cmd)` puts `cmd` at 2), so an index list
     * alone watches only the first of them.
     */
    val varargFrom: Int? = null,
) {
    /** [relevantArguments] plus every vararg position up to [lastIndex]. */
    fun argumentIndexes(lastIndex: Int): List<Int> = (
        relevantArguments + (varargFrom?.let { from -> (from..lastIndex).toList() } ?: emptyList())
        ).distinct().sorted()

    fun writeJson(w: io.cdxgen.kosi.schema.JsonWriter) {
        w.beginObject()
        w.str("category", category)
        w.beginArray("relevantArguments")
        for (a in relevantArguments) w.num(a.toLong())
        w.endArray()
        w.str("pattern", pattern)
        w.str("receiverType", receiverType)
        w.str("severity", severity)
        if (varargFrom != null) w.num("varargFrom", varargFrom.toLong())
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
     * delivered.
     */
    val elementFlows: List<List<Int>> = emptyList(),
    /**
     * The position of a VARARG parameter: a flow out of this position is also
     * a flow out of every later argument (`String.format(fmt, a, b)` puts `b`
     * at 2). See [SinkPattern.varargFrom].
     */
    val varargFrom: Int? = null,
) {
    /** [flows] with the vararg position's flows repeated for every later argument up to [lastIndex]. */
    fun argumentFlows(lastIndex: Int): List<List<Int>> {
        val from = varargFrom ?: return flows
        val extra = flows.filter { it.size >= 2 && it[0] == from }
            .flatMap { flow -> ((from + 1)..lastIndex).map { index -> listOf(index) + flow.drop(1) } }
        return (flows + extra).distinct()
    }

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
        if (varargFrom != null) w.num("varargFrom", varargFrom.toLong())
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

/**
 * A LITERAL source: a string literal stored into a local whose NAME
 * matches [namePattern] births a fact with [category] at the store. This is
 * how hardcoded secret/key material enters the flow graph — there is no
 * source call to hang a pack entry on, but the name rule is still DATA, and
 * the flow engine matches names against it exactly like callee symbols.
 */
data class LiteralSourcePattern(
    val namePattern: String,
    val category: String,
)

/**
 * A call whose PRODUCED OBJECT carries the input's taint on its
 * FIELDS — Jackson `readValue`, kotlinx `decodeFromString`, Gson `fromJson`.
 * The input->result move is the passthrough table's job (format-adapter
 * rows); this entry adds what a passthrough cannot say: every FIELD READ of
 * the result derives the same category, which is how a request body reaches
 * a sink through a DTO. The deserialization-as-a-risk SINK stays beside it —
 * deserializing untrusted bytes is a finding even when nothing reads a field.
 */
data class DeserializerPattern(val pattern: String)

/**
 * A SINK declared by an INTERFACE the framework implements at
 * runtime — there is no body to walk and no FQN a pattern can name, because
 * the declaring interface is USER code. Matched on what the declaration
 * carries: the enclosing interface's SUPERTYPES (Spring Data: every method
 * on an interface extending a repository base is a query the framework
 * derives or reads from @Query) or its ANNOTATIONS (Room: a @Dao interface's
 * @Query/@RawQuery methods).
 */
data class InterfaceSinkPattern(
    val supertypes: List<String> = emptyList(),
    val interfaceAnnotations: List<String> = emptyList(),
    val methodAnnotations: List<String> = emptyList(),
    val category: String,
    val severity: String = "high",
)

data class ModelPack(
    val name: String,
    val sources: List<SourcePattern>,
    val sinks: List<SinkPattern>,
    val passthroughs: List<PassthroughPattern>,
    val sanitizers: List<SanitizerPattern>,
    val effects: List<EffectPattern>,
    val literalSources: List<LiteralSourcePattern> = emptyList(),
    val deserializers: List<DeserializerPattern> = emptyList(),
    val interfaceSinks: List<InterfaceSinkPattern> = emptyList(),
) {
    /** Every distinct category this pack can produce (sources and sinks). */
    val categories: Set<String>
        get() = sources.map { it.category }.toSet() + sinks.map { it.category }.toSet()
}
