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
 * The closed vocabulary of [FlowSlice.pathKind] — what a slice's
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

/**
 * The closed vocabulary of [FlowFrame.role] — what happened at one
 * hop of a trace. Pinned by `FrameRoleVocabularyTest` beside
 * [PathKind.ALL]: a ninth role does not ship, and a role with no producer
 * anywhere in the corpus is a schema lie (the rule, applied to the new
 * vocabulary on the day it is born, not later).
 */
object FrameRole {
    /** The taint's birth: a pack source call, an endpoint parameter, a literal. */
    const val SOURCE = "source"

    /** A register/field/index move carrying the value one hop within a frame. */
    const val MOVE = "move"

    /** A call whose callee (further frames) continues the trace. */
    const val CALL = "call"

    /** A value leaving a callee back to its caller. */
    const val RETURN = "return"

    /** A virtual call where more than one target was considered or narrowing applied. */
    const val DISPATCH = "dispatch"

    /** A summary boundary: the hop rests on an interprocedural summary. */
    const val SUMMARY = "summary"

    /** A sanitizer matched at this hop but did not clear the flowing category. */
    const val SANITIZER_NOT_APPLIED = "sanitizer-not-applied"

    /** The taint's consumption: a pack sink call. */
    const val SINK = "sink"

    val ALL = sortedSetOf(SOURCE, MOVE, CALL, RETURN, DISPATCH, SUMMARY, SANITIZER_NOT_APPLIED, SINK)
}

/**
 * One named hop of a slice's trace — (function, file, line, role),
 * the unit `09-PRECISION.md` §4 calls for. The frame list is ordered source
 * to sink; [FlowSlice.pathKind] (with [FlowSlice.framesCutBy]) says whether
 * the list is the whole walk.
 *
 * [dispatchWidth]/[dispatchTargets]/[dispatchNarrowedBy] carry the per-hop
 * dispatch evidence on `dispatch` frames: how many targets the site
 * considered, which were applied, and what narrowed them (`cha`, `rta`,
 * `vta`, `single-impl`, `sealed`).
 */
data class FlowFrame(
    val function: String,
    val file: String,
    val line: Int,
    val role: String,
    val dispatchWidth: Int? = null,
    val dispatchTargets: List<String> = emptyList(),
    val dispatchNarrowedBy: String? = null,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        if (dispatchNarrowedBy != null) w.str("dispatchNarrowedBy", dispatchNarrowedBy) else w.nul("dispatchNarrowedBy")
        if (dispatchWidth != null) w.num("dispatchWidth", dispatchWidth) else w.nul("dispatchWidth")
        w.beginArray("dispatchTargets")
        for (t in dispatchTargets.sorted()) w.str(t)
        w.endArray()
        w.str("file", file)
        w.str("function", function)
        w.num("line", line)
        w.str("role", role)
        w.endObject()
    }
}

/**
 * What makes a slice a CRYPTO flow — key or secret material (the `hardcoded-
 * secret` literal sources) reaching a crypto API (`crypto-asset`) or a TLS
 * misconfiguration (`insecure-tls`). It lives in the schema module, beside
 * [FlowSlice], because two pieces of code answer this question and they must
 * answer it the same way (the rule). The bench has counted
 * `cryptoFlowSlices` with this predicate; `--dataflow crypto` never
 * consulted it and published every slice the `security` mode does, so the
 * mode named a filter that did not exist — and a consumer who asked for
 * crypto flows was handed log-injection findings labelled `"mode": "crypto"`
 * (the matrix's first finding).
 */
object CryptoFlow {
    const val SOURCE_CATEGORY = "hardcoded-secret"
    val SINK_CATEGORIES = sortedSetOf("crypto-asset", "insecure-tls")

    fun isCryptoFlow(slice: FlowSlice): Boolean =
        slice.sourceCategory == SOURCE_CATEGORY && slice.sinkCategory in SINK_CATEGORIES
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
     * what the slice's trace IS, published rather than left for the
     * consumer to re-derive from `nodeIds` (the schema gap):
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
     * `rootWitness` was null everywhere (the rule: a field that never
     * varies is not a fact, it is a schema lie a consumer will eventually
     * believe).
     */
    val pathKind: String,
    /**
     * The trace as named hops — ordered (function, file, line,
     * role), source first, sink last. `frames>=N` and `via=fn:...` corpus
     * expectations read this list; cdxgen renders it as `callstack`
     * evidence. Empty only where [pathKind] is `symbol-only` (no walk, no
     * hops to name).
     */
    val frames: List<FlowFrame> = emptyList(),
    /**
     * When [frames] is not the whole walk, the cap that cut it
     * (e.g. `trace-nodes`) — the frame-list form of the PARTIAL contract.
     * Null on a complete list.
     */
    val framesCutBy: String? = null,
    val ruleId: String,
    val ruleName: String,
    val description: String,
    val severity: String,
    val confidence: String,
    val riskScore: String,
    val flowKey: String,
    /**
     * The summary origins this slice's trace crossed at interprocedural
     * boundaries, sorted and distinct — `computed`, `pack`, `default`,
     * `recursive-approx`. Empty for a purely intraprocedural slice. This is
     * the per-slice half of the default-origin measurement: a slice whose
     * origins are ALL `default` exists only because the blanket propagation
     * did.
     */
    val origins: List<String> = emptyList(),
    /**
     * For a slice that entered through an ENDPOINT HANDLER's
     * parameter, the value-parameter it entered through (`#0` = the first
     * non-receiver parameter) and the transport the parameter's annotation
     * names (path/query/header/cookie/form/body). Null for every other
     * birth — previously, an endpoint-rooted slice could say "this handler
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
        w.beginArray("frames")
        for (f in frames) f.writeJson(w)
        w.endArray()
        if (framesCutBy != null) w.str("framesCutBy", framesCutBy) else w.nul("framesCutBy")
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
    /**
     * Source-born field writes, as `p<i>.<suffix>:<category>`
     * strings — taint born at a source inside the callee and stored into
     * parameter i's object. The caller's argument carries the write after
     * the call.
     */
    val sourceFieldWrites: List<String> = emptyList(),
    /**
     * Parameter-object FIELDS reaching the return's same field, as
     * `p<i>.<suffix>` strings — `fun get(raw: String) = Session(token =
     * raw)` returns an object whose `token` carries the argument.
     */
    val paramToReturnFields: List<String> = emptyList(),
    /**
     * What the body passes when it invokes function-valued
     * parameters, as `p<j>(arg<k>)<-p<i>` (my parameter i's taint) or
     * `p<j>(arg<k>)<-source:<category>` (a source born in me).
     */
    val invokes: List<String> = emptyList(),
    /**
     * Sinks the body reaches with an argument it handed to an INVOKED
     * function-valued parameter, as `p<j>(arg<k>).<path>` strings — the DSL
     * builder's channel: `b.block(); b.go()` inside the callee sinks a field
     * (`path`) of the object it passed as argument k of the lambda it
     * invoked, so a lambda that writes its capture into that argument's
     * field reaches that sink. The write itself is the caller's lambda's
     * `paramFieldWrites`; this half says where the written value goes.
     */
    val invokedArgSinks: List<String> = emptyList(),
    /**
     * Source-born taint reaching the RETURN's FIELD, as
     * `<suffix>:<category>` strings — `fun make() = Wrapped(readLine() ?:
     * "")` returns an object whose field carries a source born inside it.
     * The channel the constructor synthesis made load-bearing (it moved
     * source facts off the bare return key into constructed objects'
     * fields) and no vocabulary carried (http4k's delegation
     * factories went silent).
     */
    val sourceReturnFields: List<String> = emptyList(),
    /**
     * Parameter i's FIELD reaching the RETURN value, as
     * `p<i>.<suffix>` strings — the getter channel
     * (`val body get() = raw`) and every `by`-delegation forwarder. The
     * inverse of [paramToReturnFields], and the half that was missing: the
     * summary said only that the parameter reached the return, and the
     * caller then probed the argument's bare key, where an object carrying
     * its taint in a field has nothing.
     */
    val paramFieldToReturn: List<String> = emptyList(),
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginObject("accessPaths")
        for (entry in accessPaths.entries.sortedBy { it.key }) w.str(entry.key, entry.value)
        w.endObject()
        w.str("function", function)
        w.str("functionId", functionId)
        w.beginArray("invokedArgSinks")
        for (v in invokedArgSinks.sorted()) w.str(v)
        w.endArray()
        w.beginArray("invokes")
        for (v in invokes.sorted()) w.str(v)
        w.endArray()
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
        w.beginArray("sourceFieldWrites")
        for (v in sourceFieldWrites.sorted()) w.str(v)
        w.endArray()
        w.beginArray("sourceReturnFields")
        for (v in sourceReturnFields.sorted()) w.str(v)
        w.endArray()
        w.beginArray("paramFieldToReturn")
        for (v in paramFieldToReturn.sorted()) w.str(v)
        w.endArray()
        w.beginArray("paramToReturnFields")
        for (v in paramToReturnFields.sorted()) w.str(v)
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
    /**
     * This evidence narrowed to [kept], as a WHOLE — the slices, the
     * nodes and edges those slices still reference, and every counter derived
     * from them.
     *
     * There is one of these because a filter that drops slices and leaves the
     * rest of the document behind publishes a contradiction: `nodes[]` and
     * `edges[]` describing traces that are not in `slices[]`, and counters
     * (`connectivity`, `suspendCrossingSlices`, `summaryCrossingSlices`,
     * `defaultOriginSlices`, `integrityViolations`) still measuring the
     * unfiltered population. The reachable-mode intersection recomputed four
     * of those counters and left the other five plus the node and edge
     * arrays; the crypto filter, written from it, reproduced the same
     * gap. Two places narrowing one document is exactly the shape this change
     * is about, so there is now one place.
     *
     * `summaries[]` is deliberately NOT narrowed: a summary is a fact about a
     * FUNCTION, computed whether or not any surviving slice runs through it,
     * and `summariesComputed`/`summariesByOrigin` count what the run
     * computed. Narrowing those would report less analysis than was done.
     */
    fun restrictTo(kept: List<FlowSlice>): DataFlowEvidence {
        if (kept.size == slices.size) return this
        val keptNodeIds = kept.flatMapTo(HashSet()) { it.nodeIds }
        val keptEdgeIds = kept.flatMapTo(HashSet()) { it.edgeIds }
        val nodesOut = nodes.filter { it.id in keptNodeIds }
        val edgesOut = edges.filter { it.id in keptEdgeIds }
        val edgesById = edgesOut.associateBy { it.id }
        val nodesById = nodesOut.associateBy { it.id }
        // The same rule the engine uses: a `pack` origin on a source birth is
        // PROVENANCE, not a summary boundary.
        val boundaryOrigins = { origins: List<String> -> origins.filter { it != "pack" } }
        return copy(
            nodes = nodesOut,
            edges = edgesOut,
            slices = kept,
            stats = stats.copy(
                sliceCount = kept.size,
                uniqueFlows = kept.map { it.flowKey }.toSortedSet().size,
                crossDependencySlices = kept.count { it.crossesDependency },
                crossModuleSlices = kept.count { it.crossesModule },
                connectivity = if (kept.isEmpty()) {
                    1.0
                } else {
                    kept.count { slice -> sliceIsConnected(slice, edgesById) }.toDouble() / kept.size
                },
                integrityViolations = kept.count { slice ->
                    slice.nodeIds.any { it !in nodesById } || !sliceIsConnected(slice, edgesById)
                },
                defaultOriginSlices = kept.count { slice ->
                    val boundary = boundaryOrigins(slice.origins)
                    boundary.isNotEmpty() && boundary.all { it == "default" }
                },
                summaryCrossingSlices = kept.count { boundaryOrigins(it.origins).isNotEmpty() },
                suspendCrossingSlices = kept.count { slice ->
                    slice.nodeIds.any { nodesById[it]?.kind == "suspend" }
                },
                // The depth measurements are properties of the
                // SURVIVING slices (the rule — a narrowed document
                // narrows its derived counters), while the dispatch-width
                // histogram and truncations{} measure the RUN's call sites
                // and caps and stay.
                maxObservedDepth = kept.maxOfOrNull { it.frames.size } ?: 0,
                depthHistogram = kept.groupingBy { it.frames.size.toString() }.eachCount(),
            ),
        )
    }

    /** Every consecutive node pair of the trace is joined by a published edge. */
    private fun sliceIsConnected(slice: FlowSlice, edgesById: Map<String, FlowEdge>): Boolean {
        if (slice.nodeIds.size < 2) return slice.edgeIds.isEmpty()
        if (slice.edgeIds.size != slice.nodeIds.size - 1) return false
        for ((i, edgeId) in slice.edgeIds.withIndex()) {
            val edge = edgesById[edgeId] ?: return false
            if (edge.sourceId != slice.nodeIds[i] || edge.targetId != slice.nodeIds[i + 1]) return false
        }
        return true
    }

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
    /**
     * How many published slices are proven root-reachable — non-zero ONLY
     * when the run both asked for `--dataflow reachable` AND produced a call
     * graph to intersect with. Asking without a graph (`--callgraph none`)
     * computes nothing, and the field then reads 0 meaning "not measured",
     * never "every slice" (a later review). The taint engine always
     * writes 0 here; the Analyzer's intersection is the only writer of a
     * non-zero value, and `summary.reachableSliceCount` reads this field
     * rather than deriving a second answer.
     */
    val reachableSlices: Int,
    val connectivity: Double,
    val integrityViolations: Int,
    val summariesComputed: Int,
    val summariesByOrigin: Map<String, Int>,
    /** Slices whose trace crossed >= 1 summary boundary and crossed ONLY `default` ones. */
    val defaultOriginSlices: Int = 0,
    /** Slices whose trace crossed >= 1 summary boundary — the default-origin denominator. */
    val summaryCrossingSlices: Int = 0,
    /** Slices whose trace crosses a suspend boundary. */
    val suspendCrossingSlices: Int = 0,
    /** Dispatch joins by candidate width, e.g. {"2": 5}. */
    val dispatchJoins: Map<String, Int> = emptyMap(),
    /**
     * Summaries derived from dependency bytecode (`origin=bytecode`) that
     * a workspace call site actually applied — the gate's numerator is taken
     * over THESE, never over every jar function summarised.
     */
    val bytecodeSummaries: Int = 0,
    /**
     * Slices whose trace enters a dependency jar AND whose boundary moves
     * carry `origin=bytecode` — the cross-dependency taint the whole phase
     * exists to measure, with both producers named.
     */
    val crossDependencyBytecodeSlices: Int = 0,
    /**
     * The deepest named-hop count any published slice carries —
     * "how deep does kosi actually go on this repo" as a number in the
     * report rather than an anecdote (09-PRECISION.md §4). 0 when no slice
     * carries frames.
     */
    val maxObservedDepth: Int = 0,
    /**
     * Slice count by frame count (the depth histogram). Exact
     * counts, like `dispatchJoins` — a bucket a reviewer can re-derive.
     */
    val depthHistogram: Map<String, Int> = emptyMap(),
    /**
     * Dispatch-width histogram — targets CONSIDERED per virtual hop
     * across the run, pre-narrowing, so the difference between considered
     * and applied (the narrowing the trace names per hop) is a measurement.
     * `dispatchJoins` keeps counting APPLIED summaries; both stay because
     * the bench and BUILD.md read the old one.
     */
    val dispatchWidthHistogram: Map<String, Int> = emptyMap(),
    /**
     * Every dataflow cap that bound this run, by its published
     * name, with the number of times it cut. The depth doctrine's (a):
     * every cap is declared, measured and visible IN THE REPORT — the
     * `truncations{}` the deep tier's PASS line requires at zero. Empty is
     * the claim "no cap bound".
     */
    val truncations: Map<String, Int> = emptyMap(),
    /**
     * Functions skipped BY POLICY (`--dataflow-skip-generated`),
     * which is not a cap: the skipped bodies' summaries still apply and
     * nothing is lost. Published beside `truncations{}` so "cut off by a
     * budget" and "deliberately not reported" are different vocabularies —
     * the counter used to ride `truncations{}`, burying real cap signal
     * under numbers that meant "working as intended".
     */
    val skips: Map<String, Int> = emptyMap(),
    /**
     * Convergence aids that cost NO flow: `summary-scc-join`, the SCCs whose
     * fixpoint was made monotone by joining each member's previous summary
     * (a join only adds effects). Never in `truncations{}`, which is caps
     * only. Serialised only when non-empty.
     */
    val convergence: Map<String, Int> = emptyMap(),
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
        w.beginObject("dispatchWidthHistogram")
        for ((key2, value) in dispatchWidthHistogram.toSortedMap(compareBy { it.toIntOrNull() ?: Int.MAX_VALUE })) {
            w.num(key2, value.toLong())
        }
        w.endObject()
        w.num("defaultOriginSlices", defaultOriginSlices)
        w.beginObject("depthHistogram")
        for ((key2, value) in depthHistogram.toSortedMap(compareBy { it.toIntOrNull() ?: Int.MAX_VALUE })) {
            w.num(key2, value.toLong())
        }
        w.endObject()
        w.num("integrityViolations", integrityViolations)
        w.num("maxObservedDepth", maxObservedDepth)
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
        w.beginObject("truncations")
        for ((key, value) in truncations.toSortedMap()) w.num(key, value.toLong())
        w.endObject()
        w.beginObject("skips")
        for ((key, value) in skips.toSortedMap()) w.num(key, value.toLong())
        w.endObject()
        if (convergence.isNotEmpty()) {
            w.beginObject("convergence")
            for ((key, value) in convergence.toSortedMap()) w.num(key, value.toLong())
            w.endObject()
        }
        w.endObject()
    }
}
