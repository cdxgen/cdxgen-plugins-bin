package io.cdxgen.kosi.schema

/**
 * DataFlow evidence (03-SCHEMA.md). Slice invariants asserted by `kosi golden`:
 * `sourceId ∈ nodeIds`, `sinkId ∈ nodeIds`, `edgeIds` form a connected path
 * from sourceId to sinkId, and ruleId/severity/confidence/riskScore non-empty.
 */
data class FlowNode(
    val id: String,
    val name: String,
    val kind: String,
    val modulePath: String,
    val purl: String,
    val filePath: String,
    val position: Position?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("filePath", filePath)
        w.str("id", id)
        w.str("kind", kind)
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.str("purl", purl)
        position?.writeJson(w, "position")
        w.endObject()
    }
}

data class FlowEdge(
    val id: String,
    val sourceId: String,
    val targetId: String,
    val kind: String,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("id", id)
        w.str("kind", kind)
        w.str("sourceId", sourceId)
        w.str("targetId", targetId)
        w.endObject()
    }
}

/**
 * P22 §2: the closed vocabulary of [FlowSlice.pathKind] — what a slice's
 * trace IS. Pinned by `SlicePathKindVocabularyTest` the way
 * `RootsVocabularyTest` pins the roots vocabulary: a fourth value does not
 * ship, and every published slice carries exactly one.
 */
object PathKind {
    /** A full source→sink walk, not cut. */
    const val COMPLETE = "complete"

    /** The walk was elided (trace cap, missing middle); endpoints guaranteed. */
    const val PARTIAL = "partial"

    /** No provable path — the finding stands on the symbol match alone. */
    const val SYMBOL_ONLY = "symbol-only"

    val ALL = sortedSetOf(COMPLETE, PARTIAL, SYMBOL_ONLY)
}

data class FlowSlice(
    val id: String,
    val sourceId: String,
    val sinkId: String,
    val sourceName: String,
    val sinkName: String,
    val sourceFunction: String,
    val sinkFunction: String,
    val sourceModulePath: String,
    val sinkModulePath: String,
    val sourcePurl: String,
    val targetPurl: String,
    val purls: List<String>,
    val sourceCategory: String,
    val sinkCategory: String,
    val taintKinds: List<String>,
    val nodeIds: List<String>,
    val edgeIds: List<String>,
    val pathLength: Int,
    val elided: Boolean?,
    val sanitizerNodeIds: List<String>,
    val sinkArgumentIndex: Int?,
    val accessPath: String?,
    val crossesModule: Boolean,
    val crossesDependency: Boolean,
    /**
     * P22 §2: what the slice's trace IS, published rather than left for the
     * consumer to re-derive from `nodeIds` (P21 §3's schema gap):
     *
     *  - `complete`    — a full source→sink walk, not cut;
     *  - `partial`     — the walk was elided (trace cap, missing middle);
     *                    the endpoints are guaranteed, the middle is not;
     *  - `symbol-only` — no provable path; the finding stands on the
     *                    symbol match alone.
     *
     * It replaces two fields that were facts nowhere: `reachableFromRoots`
     * was false on every slice in every shipped slot and true by
     * construction in the one mode that published it (the mode, not the
     * slice, carried the information — `dataFlow.mode` still does), and
     * `rootWitness` was null everywhere (R117's rule: a field that never
     * varies is not a fact, it is a schema lie a consumer will eventually
     * believe).
     */
    val pathKind: String,
    val ruleId: String,
    val ruleName: String,
    val description: String,
    val severity: String,
    val confidence: String,
    val riskScore: String,
    val flowKey: String,
    /**
     * P5: the summary origins this slice's trace crossed at interprocedural
     * boundaries, sorted and distinct — `computed`, `pack`, `default`,
     * `recursive-approx`. Empty for a purely intraprocedural slice. This is
     * the per-slice half of the default-origin measurement: a slice whose
     * origins are ALL `default` exists only because the blanket propagation
     * did.
     */
    val origins: List<String> = emptyList(),
    /**
     * P20 §1: for a slice that entered through an ENDPOINT HANDLER's
     * parameter, the value-parameter it entered through (`#0` = the first
     * non-receiver parameter) and the transport the parameter's annotation
     * names (path/query/header/cookie/form/body). Null for every other
     * birth — before P20 an endpoint-rooted slice could say "this handler
     * is reachable from untrusted input" but never WHICH parameter, which
     * is the difference between "guard this input" and "audit the handler".
     */
    val sourceParameter: String? = null,
    val sourceTransport: String? = null,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("accessPath", accessPath)
        w.str("confidence", confidence)
        w.bool("crossesDependency", crossesDependency)
        w.bool("crossesModule", crossesModule)
        w.str("description", description)
        w.beginArray("origins")
        for (o in origins.sorted()) w.str(o)
        w.endArray()
        w.beginArray("edgeIds")
        for (e in edgeIds) w.str(e)
        w.endArray()
        if (elided != null) w.bool("elided", elided) else w.nul("elided")
        w.str("flowKey", flowKey)
        w.str("id", id)
        w.beginArray("nodeIds")
        for (n in nodeIds) w.str(n)
        w.endArray()
        w.num("pathLength", pathLength)
        w.str("pathKind", pathKind)
        w.str("riskScore", riskScore)
        w.str("ruleId", ruleId)
        w.str("ruleName", ruleName)
        w.beginArray("sanitizerNodeIds")
        for (s in sanitizerNodeIds) w.str(s)
        w.endArray()
        if (sinkArgumentIndex != null) w.num("sinkArgumentIndex", sinkArgumentIndex) else w.nul("sinkArgumentIndex")
        w.str("sinkCategory", sinkCategory)
        w.str("sinkFunction", sinkFunction)
        w.str("sinkId", sinkId)
        w.str("sinkModulePath", sinkModulePath)
        w.str("sinkName", sinkName)
        w.str("sourceCategory", sourceCategory)
        w.str("sourceFunction", sourceFunction)
        w.str("sourceId", sourceId)
        w.str("sourceModulePath", sourceModulePath)
        w.str("sourceName", sourceName)
        if (sourceParameter != null) w.str("sourceParameter", sourceParameter) else w.nul("sourceParameter")
        w.str("sourcePurl", sourcePurl)
        if (sourceTransport != null) w.str("sourceTransport", sourceTransport) else w.nul("sourceTransport")
        w.str("severity", severity)
        w.str("targetPurl", targetPurl)
        w.beginArray("taintKinds")
        for (t in taintKinds.sorted()) w.str(t)
        w.endArray()
        w.beginArray("purls")
        for (p in purls.sorted()) w.str(p)
        w.endArray()
        w.endObject()
    }
}

/** Taint summary with origin provenance (golem's blanket-propagation lesson). */
data class FlowSummary(
    val functionId: String,
    val function: String,
    val parameterNames: List<String>,
    val parameterTypes: List<String>,
    val returnType: String,
    val paramToReturn: List<String>,
    val paramToParam: List<String>,
    val paramToReceiver: List<String>,
    val paramToSink: Map<String, List<Int>>,
    val sourceReturns: List<String>,
    val sanitizes: List<String>,
    val accessPaths: Map<String, String>,
    val origin: String,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginObject("accessPaths")
        for (entry in accessPaths.entries.sortedBy { it.key }) w.str(entry.key, entry.value)
        w.endObject()
        w.str("function", function)
        w.str("functionId", functionId)
        w.str("origin", origin)
        w.beginArray("paramToParam")
        for (v in paramToParam.sorted()) w.str(v)
        w.endArray()
        w.beginArray("paramToReceiver")
        for (v in paramToReceiver.sorted()) w.str(v)
        w.endArray()
        w.beginObject("paramToSink")
        for (key in paramToSink.keys.sorted()) {
            w.beginArray(key)
            for (v in (paramToSink[key] ?: emptyList()).sorted()) w.num(v.toLong())
            w.endArray()
        }
        w.endObject()
        w.beginArray("paramToReturn")
        for (v in paramToReturn.sorted()) w.str(v)
        w.endArray()
        w.beginArray("parameterNames")
        for (v in parameterNames) w.str(v)
        w.endArray()
        w.beginArray("parameterTypes")
        for (v in parameterTypes) w.str(v)
        w.endArray()
        w.str("returnType", returnType)
        w.beginArray("sanitizes")
        for (v in sanitizes.sorted()) w.str(v)
        w.endArray()
        w.beginArray("sourceReturns")
        for (v in sourceReturns.sorted()) w.str(v)
        w.endArray()
        w.endObject()
    }
}

data class DataFlowEvidence(
    val mode: String,
    val patterns: ModelPackRef,
    val nodes: List<FlowNode>,
    val edges: List<FlowEdge>,
    val slices: List<FlowSlice>,
    val summaries: List<FlowSummary>,
    val stats: DataFlowStats,
    val diagnostics: List<Diagnostic>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("mode", mode)
        w.beginArray("diagnostics")
        for (d in diagnostics.sortedWith(Diagnostic.COMPARATOR)) d.writeJson(w)
        w.endArray()
        w.beginArray("edges")
        for (e in edges) e.writeJson(w)
        w.endArray()
        w.beginArray("nodes")
        for (n in nodes) n.writeJson(w)
        w.endArray()
        patterns.writeJson(w, "patterns")
        w.beginArray("slices")
        for (s in slices) s.writeJson(w)
        w.endArray()
        w.beginArray("summaries")
        for (s in summaries) s.writeJson(w)
        w.endArray()
        stats.writeJson(w, "stats")
        w.endObject()
    }
}

/** Reference to the effective merged pack (pack contents live in kosi-models). */
data class ModelPackRef(
    val builtin: List<String>,
    val user: List<String>,
    val sourceCount: Int,
    val sinkCount: Int,
    val passthroughCount: Int,
    val sanitizerCount: Int,
    val effectCount: Int,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("builtin")
        for (b in builtin.sorted()) w.str(b)
        w.endArray()
        w.num("effectCount", effectCount)
        w.num("passthroughCount", passthroughCount)
        w.beginArray("user")
        for (u in user.sorted()) w.str(u)
        w.endArray()
        w.num("sanitizerCount", sanitizerCount)
        w.num("sinkCount", sinkCount)
        w.num("sourceCount", sourceCount)
        w.endObject()
    }
}

data class DataFlowStats(
    val sliceCount: Int,
    val uniqueFlows: Int,
    val crossDependencySlices: Int,
    val crossModuleSlices: Int = 0,
    val reachableSlices: Int,
    val connectivity: Double,
    val integrityViolations: Int,
    val summariesComputed: Int,
    val summariesByOrigin: Map<String, Int>,
    /** Slices whose trace crossed >= 1 summary boundary and crossed ONLY `default` ones. */
    val defaultOriginSlices: Int = 0,
    /** Slices whose trace crossed >= 1 summary boundary — the default-origin denominator. */
    val summaryCrossingSlices: Int = 0,
    /** P6: slices whose trace crosses a suspend boundary. */
    val suspendCrossingSlices: Int = 0,
    /** P5: dispatch joins by candidate width, e.g. {"2": 5}. */
    val dispatchJoins: Map<String, Int> = emptyMap(),
    /**
     * P9: summaries derived from dependency bytecode (`origin=bytecode`) that
     * a workspace call site actually applied — the gate's numerator is taken
     * over THESE, never over every jar function summarised.
     */
    val bytecodeSummaries: Int = 0,
    /**
     * P9: slices whose trace enters a dependency jar AND whose boundary moves
     * carry `origin=bytecode` — the cross-dependency taint the whole phase
     * exists to measure, with both producers named.
     */
    val crossDependencyBytecodeSlices: Int = 0,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("bytecodeSummaries", bytecodeSummaries)
        w.dbl("connectivity", connectivity)
        w.num("crossDependencyBytecodeSlices", crossDependencyBytecodeSlices)
        w.num("crossDependencySlices", crossDependencySlices)
        w.num("crossModuleSlices", crossModuleSlices)
        w.beginObject("dispatchJoins")
        for ((key2, value) in dispatchJoins.toSortedMap(compareBy { it.toIntOrNull() ?: Int.MAX_VALUE })) {
            w.num(key2, value.toLong())
        }
        w.endObject()
        w.num("defaultOriginSlices", defaultOriginSlices)
        w.num("integrityViolations", integrityViolations)
        w.beginObject("summariesByOrigin")
        for (key in summariesByOrigin.keys.sorted()) {
            w.num(key, (summariesByOrigin[key] ?: 0).toLong())
        }
        w.endObject()
        w.num("summariesComputed", summariesComputed)
        w.num("sliceCount", sliceCount)
        w.num("uniqueFlows", uniqueFlows)
        w.num("reachableSlices", reachableSlices)
        w.num("summaryCrossingSlices", summaryCrossingSlices)
        w.num("suspendCrossingSlices", suspendCrossingSlices)
        w.endObject()
    }
}
