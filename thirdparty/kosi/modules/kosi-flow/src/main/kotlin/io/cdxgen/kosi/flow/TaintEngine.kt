package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBranch
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCast
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirElvis
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirPhi
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirSuspendPoint
import io.cdxgen.kosi.kir.KirThrow
import io.cdxgen.kosi.kir.KirTypeCheck
import io.cdxgen.kosi.models.ModelPack
import io.cdxgen.kosi.models.PatternMatcher
import io.cdxgen.kosi.models.SourcePattern
import io.cdxgen.kosi.schema.DataFlowEvidence
import io.cdxgen.kosi.schema.DataFlowStats
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.FlowEdge
import io.cdxgen.kosi.schema.FlowFrame
import io.cdxgen.kosi.schema.FlowNode
import io.cdxgen.kosi.schema.FlowSlice
import io.cdxgen.kosi.schema.FrameRole
import io.cdxgen.kosi.schema.ModelPackRef
import io.cdxgen.kosi.schema.PathKind
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.Severity
import java.security.MessageDigest


internal class CompiledFunction(
    val function: KirFunction,
    val blocks: List<KirBlock>,
    val sitesByBlock: Map<String, List<Site>>,
    val siteById: Map<Int, Site>,
    val successors: Map<String, List<String>>,
    val predecessors: Map<String, List<String>>,
)

internal fun compile(function: KirFunction, firstSiteId: Int = 0): CompiledFunction? {
    val body = function.body ?: return null
    if (body.blocks.isEmpty()) return null
    var nextSite = firstSiteId
    val sitesByBlock = HashMap<String, List<Site>>()
    val siteById = HashMap<Int, Site>()
    for (block in body.blocks) {
        val sites = block.instructions.mapIndexed { indexInBlock, ins ->
            val site = Site(nextSite++, block.id, indexInBlock, ins)
            siteById[site.id] = site
            site
        }
        sitesByBlock[block.id] = sites
    }
    val indexOfBlock = body.blocks.withIndex().associate { (i, b) -> b.id to i }
    val successors = HashMap<String, MutableList<String>>()
    val predecessors = HashMap<String, MutableList<String>>()
    for (block in body.blocks) {
        val succs = successors.getOrPut(block.id) { mutableListOf() }
        fun link(target: String) {
            if (target !in succs) succs.add(target)
            predecessors.getOrPut(target) { mutableListOf() }.add(block.id)
        }
        var terminates = false
        for (ins in block.instructions) {
            when (ins) {
                is KirBranch -> {
                    link(ins.thenBlock)
                    link(ins.elseBlock)
                    terminates = true
                }

                is KirReturn, is KirThrow -> terminates = true
                else -> {}
            }
        }
        if (!terminates) {
            // Fallthrough to the NEXT block in list order (KirModule's CFG contract).
            body.blocks.getOrNull((indexOfBlock[block.id] ?: 0) + 1)?.let { link(it.id) }
        }
    }
    return CompiledFunction(function, body.blocks, sitesByBlock, siteById, successors, predecessors)
}

// The abstract state, the chain keys and the merge machinery live ONCE, in
// Transfer.kt (R65): FlowState<F>, ChainKey<F>, Move and FlowTransfer are
// shared by the reporting engine and the summary analysis.

/** One executable program point: instruction [ins] of block [blockId], flat id [id]. */
internal data class Site(val id: Int, val blockId: String, val indexInBlock: Int, val ins: KirIns)


/**
 * A taint fact: born at the source call [site], carrying [category]. A
 * non-negative [param] marks an ENDPOINT-PARAMETER birth (P20 §1): the
 * handler's value-parameter index the taint entered through, so two
 * parameters of one handler are two facts — "which input is untrusted" is
 * a per-parameter fact, not a per-function one. `-1` is every other birth.
 */
internal data class TaintFact(val site: Int, val category: String, val param: Int = -1, val fieldBearing: Boolean = false) : Comparable<TaintFact> {
    /**
     * P26 §1.3: this fact sits on a value whose CONTENT came out of a pack
     * DESERIALIZER (Jackson `readValue`, kotlinx `decodeFromString`, Gson
     * `fromJson`) — the produced object carries the input's taint on its
     * FIELDS, so a field read of it derives the same category. Ordinary
     * facts (a tainted reference to some object) derive nothing on a field
     * read: the object's fields are other values.
     */
    val isFieldBearing: Boolean get() = fieldBearing

    /** The field-bearing variant of this fact. */
    fun asFieldBearing(): TaintFact =
        if (fieldBearing) this else TaintFact(site, category, param, fieldBearing = true)

    override fun compareTo(other: TaintFact): Int =
        compareValuesBy(this, other, { it.site }, { it.category }, { it.param }, { it.fieldBearing })
}

/**
 * Reporting facts carry paths on STATE KEYS, so a field read derives nothing
 * — except a [TaintFact.fieldBearing] fact, whose value's FIELDS carry the
 * taint a pack deserializer moved there.
 */
/**
 * P27 §1: reads "register at access path" in the REPORTING engine, across an
 * alias class and across BOTH ways a value's taint can be represented here.
 *
 *  - on the KEY, the ordinary case: a field write or a summary channel put
 *    the fact at `(register, path)`;
 *  - on the BARE key when the fact is FIELD-BEARING (P26 §1.3) — a
 *    deserializer's result carries the input's taint on every field, and
 *    there is no key per field because the fields were never written by
 *    code the engine saw.
 *
 * Reading only the keyed form is why a `@RequestBody` DTO died at the first
 * mapper: Jackson's result is field-bearing, the mapper asked for
 * `customerName`, and the keyed probe found nothing.
 */
internal fun readReportingPath(
    state: FlowState<TaintFact>,
    bases: Collection<String>,
    path: String,
): List<TaintFact> {
    val out = mutableListOf<TaintFact>()
    for (base in bases.sorted()) {
        out += state.factsOf(TaintKey(base, path))
        if (path.isNotEmpty()) {
            out += state.factsOf(TaintKey(base, "")).filter { it.isFieldBearing }
        }
    }
    return out.distinct()
}

private object TaintFactOps : FactOps<TaintFact> {
    override fun categoryOf(fact: TaintFact): String = fact.category
    override fun deriveOnFieldRead(fact: TaintFact, suffix: String): TaintFact? =
        if (fact.fieldBearing) fact.asFieldBearing() else null
}

/**
 * The taint engine: the P4 intraprocedural, field-sensitive fixpoint plus
 * P5's interprocedural summaries and P6's async propagation over the same
 * CFG machinery (02-ARCHITECTURE.md §6). Everything that decides what is a
 * source, a sink, a passthrough, a sanitizer or an effect comes from the
 * [ModelPack]; the engine hard-codes no rule about categories.
 *
 * Precision contract: taint is tracked on ACCESS PATHS `(base, field*)`, so
 * writing `obj.query` never taints `obj.column` — the corpus's clean-sibling
 * negative pins this, and `Options.accessPathDepth = 0` collapses every path
 * to its base register, which is the field-INsensitive engine that negative
 * must be able to switch on.
 *
 * Interprocedural contract (P5): the pack is authoritative at every call
 * site; only when NO pack entry matches does a computed callee summary
 * apply, and only when no summary exists does the `--unknown-call` default
 * run. Every boundary move carries its origin (`computed`, `pack`,
 * `default`, `recursive-approx`), and every slice records the origins its
 * trace passed through.
 *
 * Determinism contract: states are sorted maps, facts sorted sets, the
 * worklist is FIFO over stable successor lists, and every emitted collection
 * is sorted before ids are assigned. Two runs on one input produce
 * byte-identical evidence.
 */
/**
 * P28 §2: the value types an `all` payload can arrive as WITHOUT fields —
 * framework-independent (kotlin/java String and primitives), so no pack can
 * widen or narrow it by omission. An unresolved type is NOT simple: it seeds
 * field-bearing, the triage-over-silence direction.
 *
 * Top-level and `internal` so `AllPayloadSimpleTypesTest` can check every
 * spelling here against the pack's doc-derived `simpleParameterTypes`. It was
 * private, and the copy had drifted: it said `java.lang.Char`, which is not a
 * JVM type, and nothing could disagree with it (R168).
 */
internal val ALL_PAYLOAD_SIMPLE_TYPES = setOf(
    "kotlin.String", "kotlin.Int", "kotlin.Long", "kotlin.Short", "kotlin.Byte",
    "kotlin.Double", "kotlin.Float", "kotlin.Boolean", "kotlin.Char",
    "java.lang.String", "java.lang.Integer", "java.lang.Long", "java.lang.Short",
    "java.lang.Byte", "java.lang.Double", "java.lang.Float", "java.lang.Boolean",
    "java.lang.Character",
)

object TaintEngine {

    /** File path -> (relativePath, modulePath), plus the module purl lookup. Same shape as the graph's attribution. */
    data class Attribution(
        val byAbsoluteFilePath: Map<String, Pair<String, String>>,
        val purlByModulePath: Map<String, String>,
    ) {
        companion object {
            val NONE = Attribution(emptyMap(), emptyMap())
        }
    }

    data class Options(
        val mode: String,
        /** <= 0 collapses every access path to its base register: field-insensitive. */
        val accessPathDepth: Int,
        val maxSlices: Int,
        val maxTraceNodes: Int,
        val maxFunctionInstructions: Int,
        /** `--unknown-call propagate|drop` (02-ARCHITECTURE.md §6). */
        val unknownCallPropagate: Boolean,
        val skipGenerated: Boolean,
        /**
         * P5: how virtual call sites pick the summaries to join — `cha` joins
         * every overriding body, `rta`/`vta`/`auto` keep only targets whose
         * owner class the engine saw constructed (a `KirNew` site anywhere,
         * plus singletons), `static`/`none` apply no join at virtual sites.
         * The value travels with the run's `--callgraph` choice.
         */
        val dispatchMode: String = "cha",
        /** A dispatch join wider than this is counted and diagnosed, not joined silently. */
        val dispatchJoinBudget: Int = 8,
        /** Per-SCC iteration budget for the summary fixpoint. */
        val summaryIterationBudget: Int = 32,
        /**
         * P5: a summary analysis whose live state (registers x facts) blows
         * past this budget is DROPPED, not partially published — callers
         * fall to the labelled unknown default. Real-repo functions can
         * otherwise push the fixpoint into gigabytes and OOM the run.
         */
        val maxSummaryStateEntries: Int = 60000,
        /**
         * P15: the same honest degradation for the summary's ESCAPE SET.
         * Composed sink effects multiply through summary application (each
         * application joins every callee effect with every live fact, keyed
         * by the joined access path), and a recursive AndroidX cluster
         * (FragmentManagerImpl) grew ONE function's effect map to 68M
         * entries — ~8 GB — filling any heap the corpus JVM could spare,
         * which is why `deps_max_classes` was pinned at 50 (P14). Two
         * bounds fix it: composed param paths deeper than the deepest path
         * the lowering can put on a fact key are dropped (they can never
         * match one — see SummaryAnalysis.paramPathCap), and the effect map itself is
         * budgeted like the state (R58): a function whose escapes exceed
         * this publishes NO summary rather than a partial one, and callers
         * fall to the labelled unknown default.
         */
        val maxSummarySinkEffects: Int = 8192,
        /**
         * P7 endpoint-rooted taint, when the run asks for it: handler
         * canonical name -> the category its parameters carry. Seeds live
         * at the synthetic entry site (-1) so endpoint-rooted slices walk
         * from the handler's own signature.
         */
        val endpointSources: Map<String, String> = emptyMap(),
        /**
         * P27 §2: framework id -> the parameter types that are the
         * framework's OWN collaborators rather than request data, for the
         * `annotated-or-bound` shape (Spring MVC's implicit command object).
         */
        val endpointContextParameterTypes: Map<String, List<String>> = emptyMap(),
        /** P27 §2: framework id -> annotations meaning "the framework supplies this". */
        val endpointNonInputAnnotations: Map<String, List<String>> = emptyMap(),
        /** P27 §2: framework id -> the types it resolves as a scalar query parameter. */
        val endpointSimpleParameterTypes: Map<String, List<String>> = emptyMap(),
        /**
         * Framework PARAMETER annotations: annotation FQN pattern -> the
         * full annotation data (the taint CATEGORY the parameter carries
         * and the TRANSPORT `kind` — path/query/header/cookie/form/body).
         *
         * When a handler annotates any parameter with one of these, ONLY
         * those parameters are seeded, each with its own category, and the
         * slice names the parameter (`#2`) and its transport. A Spring
         * controller method takes its injected repository and the
         * authenticated principal in the same signature as the query string;
         * seeding all of them — the only thing possible before the KIR
         * carried parameter annotations — taints the dependency container.
         * Handlers with no modelled annotation keep the all-parameters
         * behaviour, which is what Ktor and the servlet shapes need.
         */
        val endpointParameterAnnotations: Map<String, io.cdxgen.kosi.models.ParameterAnnotation> = emptyMap(),
        /** Handler canonical name -> the framework id that detected it. */
        val endpointHandlerFrameworks: Map<String, String> = emptyMap(),
        /**
         * Framework id -> how it hands input to a handler: `annotated`,
         * `context` or `all` (see FrameworkModel.handlerInput). A framework
         * missing from this map seeds every parameter, which is the
         * behaviour every framework had before P13.
         */
        val endpointHandlerInput: Map<String, String> = emptyMap(),
        /**
         * P9 `--deps`: the dependency tier, already lowered to the SAME KIR
         * by kosi-bytecode. Its functions are compiled with site ids
         * continuing after the workspace's, summarised by the SAME
         * [Summarizer] with `origin=bytecode`, and applied at workspace call
         * sites exactly like workspace summaries. Null = workspace-only run:
         * every code path below is a no-op and the report is byte-identical
         * to a run without the tier (the invariance the corpus asserts).
         */
        val depsModule: KirModule? = null,
        /** P9: purls of the jars [depsModule] was lowered from — the cross-dependency marker set. */
        val depsPurls: Set<String> = emptySet(),
        /** P9: demangled aliases (alias canonical name -> primary canonical names, tried in order). */
        val depsAliases: Map<String, List<String>> = emptyMap(),
        /** P9: classes lowered from the jars (the tier's published denominator). */
        val depsClassCount: Int = 0,
        /**
         * P9: body-less dependency records the lowerer EXCLUDED. Supplied by
         * the lowerer rather than recounted here: one number, one producer —
         * the engine cannot see the records at all, because a body-less one
         * is never put in the module it receives.
         */
        val depsBodylessRecords: Int = 0,
        /**
         * P10: called between analysis steps; returns a diagnostic code when
         * the run must DEGRADE now (the report still ships), null to carry on.
         */
        val shouldStop: (() -> String?)? = null,
        /** P10: worker parallelism for the per-function main analysis (deterministic at any width). */
        val dataflowWorkers: Int = 1,
    )

    data class Result(
        val evidence: DataFlowEvidence,
        /** Functions the worklist actually ran over — the denominator of the cap rate. */
        val functionsAnalysed: Int,
        val fixpointCapHits: Int,
        /** Source/sink SITES the pack matched in analysed code (not pack sizes). */
        val sourceSites: Int,
        val sinkSites: Int,
        /** Unknown calls through which taint actually propagated: measurable precision loss. */
        val unknownCallPropagations: Int,
        val truncations: Map<String, Int>,
        /**
         * P28 (R176): functions SKIPPED BY POLICY, not cut by a cap —
         * `--dataflow-skip-generated` skipping synthetic bodies. Their
         * summaries still apply, so nothing is lost and the counter was
         * never a truncation: reporting it as one buried the real cap
         * signal (coil's summary-state-budget beside 301
         * "truncations" that meant "working as intended") and the number
         * GROWS as the engine synthesises more, reading as a regression
         * when it is the opposite. `truncations{}` is caps only.
         */
        val skips: Map<String, Int> = emptyMap(),
        val diagnostics: List<Diagnostic>,
        /** P5: the converged summaries (computed ones plus pack-derived ones). */
        val summaries: List<io.cdxgen.kosi.schema.FlowSummary>,
        /** P5: SCCs processed and how many hit their iteration budget (counter + denominator). */
        val sccsProcessed: Int,
        val sccIterationCapHits: Int,
        /** P5: dispatch joins by candidate width, e.g. {"1": 12, "3": 2}. */
        val dispatchJoins: Map<Int, Int>,
        /** P6: slices whose trace crosses a suspend boundary. */
        val suspendCrossingSlices: Int,
        /** P9 `--deps`: body-less records the tier EXCLUDED (never summarised). */
        val bodylessRecords: Int = 0,
        /** P9: classes lowered from the dependency jars. */
        val dependencyClasses: Int = 0,
        /** P9: dependency methods lowered WITH bodies (summaries were computed over these). */
        val dependencyFunctions: Int = 0,
        /**
         * P20 §0: the depth scoreboard for one run — the numbers the depth
         * report's taint table publishes. Not part of the report schema;
         * the depth gate reads them off the engine's Result.
         */
        val depth: DepthStats = DepthStats(0, 0, 0, 0, emptyList()),
        /**
         * P22 §0: what this run's workspace summaries say about RETURN
         * VALUES — the second answer to "what does this call return" (the
         * const folder's is the first). The depth report's agreement gate
         * reads it; nothing in the report schema carries it.
         */
        val returnOpinions: ReturnOpinions = ReturnOpinions(emptyMap()),
    )

    /**
     * P22 §0: per workspace function, whether a summary exists and whether
     * it claims taint can reach the RETURN value (`paramToReturn` or
     * `sourceReturns` non-empty). Keyed by [functionKey]; [opinion] mirrors
     * the folder's resolution — descriptor-narrowed where the site carries
     * one, the union over the name's overloads where it does not (the same
     * widening toward more candidates the folder applies).
     */
    class ReturnOpinions(private val byKey: Map<String, Boolean>) {
        /** False when the run has no summary for the callee (no opinion). */
        fun opinion(fqn: String, descriptor: String?): Pair<Boolean, Boolean> {
            descriptor?.let { d ->
                byKey["$fqn\u0000$d"]?.let { return true to it }
            }
            var found = false
            var taint = false
            for ((key, claimsTaint) in byKey) {
                if (key.substringBefore('\u0000') == fqn) {
                    found = true
                    taint = taint || claimsTaint
                }
            }
            return found to taint
        }
    }

    /**
     * P20 §0: how much taint depth a run actually had, measured rather
     * than assumed:
     *
     *  - [entryFactsSeeded] — endpoint-parameter facts seeded (the entry
     *    arm of the sources-seeded denominator; the pack arm is
     *    [Result.sourceSites]).
     *  - [slicesDroppedUnprovable] — sink hits dropped at slice build
     *    because the fact's birth could not be proven against the pack.
     *  - [capAffectedSinkHits] — sink hits inside functions whose fixpoint
     *    hit the iteration budget: published best-effort, never exact.
     *  - [summaryMissingEvents] — call sites into summary-less functions
     *    carrying facts: sinks inside the callee this run could not see.
     *  - [sanitizersApplied] — the sanitizer FQNs that actually cleared a
     *    fact somewhere in the run. A sanitizer outside this set never
     *    fired, which is R63 for the security pack.
     */
    data class DepthStats(
        val entryFactsSeeded: Int,
        val slicesDroppedUnprovable: Int,
        val capAffectedSinkHits: Int,
        val summaryMissingEvents: Int,
        val sanitizersApplied: List<String>,
        /** Pack source/sink SITES the pack matched in analysed code. */
        val sourceSites: Int = 0,
        val sinkSites: Int = 0,
    )

    // ---- the per-run context --------------------------------------------------

    /**
     * What every per-function analysis needs beyond its own CFG: the
     * module-wide site table (site ids are GLOBAL, so one trace can span
     * functions), the resolved callee sets, and the converged summaries.
     * With `--deps` (P9) the site table also carries the dependency tier's
     * sites — one trace can walk into a jar and back — and [deps] exposes
     * the tier's summaries for boundary application.
     */
    /**
     * P25 §0: a declared function used as a value. [summaryKey] is its key
     * in the summary table; [receiverOffset] is 1 when the function's first
     * parameter is its receiver (a bound reference `obj::method` binds it,
     * so the invocation's argument 0 is the callee's parameter 1) and 0
     * otherwise.
     */
    internal data class FunctionValueTarget(val summaryKey: String, val receiverOffset: Int)

    internal class EngineContext(
        val pack: ModelPack,
        val siteIndex: Map<Int, Pair<CompiledFunction, Site>>,
        val callIndex: CallIndex,
        val table: Map<String, FunctionSummary>,
        val lambdaDefs: Map<String, Map<String, String>>,
        val captures: Map<String, Map<String, List<String>>>,
        val options: Options,
        val deps: DepsTier? = null,
        /**
         * P25 §0: function values that name a DECLARED function — every
         * `::reference`, bound reference and anonymous `fun`, which the
         * lowering now resolves to the target's canonical name. A lambda's
         * table key is name-with-no-descriptor; a declared function's key
         * carries its descriptor, so the lambda lookup alone could never
         * find one and every reference spelling died at the invocation.
         *
         * A canonical name shared by several declared overloads is NOT
         * resolved: the reference names one of them and nothing in the KIR
         * says which, and answering with an arbitrary overload is the
         * mistake P22 §1 fixed for the summary table. Those are counted as
         * unresolved lambdas, which is what they are.
         */
        val functionValues: Map<String, FunctionValueTarget> = emptyMap(),
    ) {
        private val lock = Any()
        var joinOverruns: Int = 0
            private set
        var lambdaUnresolved: Int = 0
            private set
        val joinWidths: java.util.TreeMap<Int, Int> = java.util.TreeMap()
        /** Callee FQNs where a pack entry actually moved taint (pack-origin summaries). */
        val packAppliedSources = sortedSetOf<String>()
        val packAppliedPassthroughs = sortedSetOf<String>()
        /** source-return births: the caller fact -> the callee's internal source path. */
        val sourceReturnPaths = HashMap<TaintFact, List<Int>>()
        /** P9: dependency summaries that actually moved taint at a workspace call site. */
        val bytecodeAppliedFqns = sortedSetOf<String>()

        // ---- P20 §0 depth counters (the scoreboard the phase report leads with) ----

        /** Endpoint-parameter facts actually seeded (the sources-seeded denominator's entry arm). */
        var entryFactsSeeded: Int = 0
            private set
        /** Sanitizer FQNs whose application actually cleared at least one fact. */
        val sanitizersApplied = sortedSetOf<String>()
        /**
         * Call sites into functions whose summary is MISSING (skipped by a
         * budget) that carried facts on their arguments — potential
         * interprocedural sinks the run could not see.
         */
        var summaryMissingEvents: Int = 0
            private set
        /** Sink hits dropped at slice build: no provable source/trace for the fact. */
        var slicesDroppedUnprovable: Int = 0
            private set
        /** Sink hits inside functions whose fixpoint hit the iteration budget. */
        var capAffectedSinkHits: Int = 0
            private set
        /** Workspace callees with no summary in the final table (the summary-missing set). */
        val missingSummaries = sortedSetOf<String>()

        fun recordEntryFacts(n: Int) = synchronized(lock) { entryFactsSeeded += n }
        fun recordSanitizerApplied(fqn: String) = synchronized(lock) { sanitizersApplied.add(fqn) }
        fun recordSummaryMissing() = synchronized(lock) { summaryMissingEvents += 1 }
        fun recordSliceDropUnprovable() = synchronized(lock) { slicesDroppedUnprovable += 1 }
        fun recordCapAffectedSinkHits(n: Int) = synchronized(lock) { capAffectedSinkHits += n }

        // Mutations are guarded so the P10 worker parallelism stays
        // deterministic at any width: outcomes are merged in compiled order
        // regardless of which worker produced them.
        fun recordJoin(width: Int) = synchronized(lock) { joinWidths.merge(width, 1, Int::plus) }
        fun recordJoinOverrun() = synchronized(lock) { joinOverruns += 1 }
        fun recordSourceReturn(fact: TaintFact, path: List<Int>) = synchronized(lock) { sourceReturnPaths[fact] = path }
        fun recordPackSource(fqn: String) = synchronized(lock) { packAppliedSources.add(fqn) }
        fun recordPackPassthrough(fqn: String) = synchronized(lock) { packAppliedPassthroughs.add(fqn) }
        fun recordLambdaUnresolved() = synchronized(lock) { lambdaUnresolved += 1 }
        fun recordBytecodeApplied(fqn: String) = synchronized(lock) { bytecodeAppliedFqns.add(fqn) }

        // ---- P24 §3: the per-site evidence the frames read ------------------

        /** Dispatch evidence per call site: targets considered, applied, narrowed by. */
        data class DispatchInfo(val considered: Int, val applied: List<String>, val narrowedBy: String?)

        val dispatchBySite = java.util.TreeMap<Int, DispatchInfo>()

        fun recordDispatch(site: Int, considered: Int, applied: List<String>, narrowedBy: String?) = synchronized(lock) {
            dispatchBySite[site] = DispatchInfo(considered, applied.sorted(), narrowedBy)
        }

        /**
         * P24 §3: sanitizer sites where the flowing categories SURVIVED —
         * the `sanitizer-not-applied` role's producer. Category set because
         * a site can see several facts.
         */
        val sanitizerSurvivedBySite = java.util.TreeMap<Int, Set<String>>()

        fun recordSanitizerSurvived(site: Int, survived: Set<String>) = synchronized(lock) {
            sanitizerSurvivedBySite[site] = (sanitizerSurvivedBySite[site] ?: emptySet()) + survived
        }

        /** P24 §3: targets considered per virtual hop, pre-narrowing. */
        val dispatchWidths = java.util.TreeMap<Int, Int>()

        fun recordDispatchWidth(width: Int) = synchronized(lock) { dispatchWidths.merge(width, 1, Int::plus) }
    }

    /**
     * The P9 `--deps` tier: the dependency module's compiled functions (site
     * ids continuing after the workspace's), its own call index, and the
     * summaries the SAME summariser computed over them with
     * `origin=bytecode`. A workspace call into the tier resolves by
     * canonical name (through the demangler's aliases) plus descriptor.
     */
    internal class DepsTier(
        val compiled: List<CompiledFunction>,
        val callIndex: CallIndex,
        /** Keyed by [functionKey], exactly as the summariser published it. */
        val table: Map<String, FunctionSummary>,
        val aliases: Map<String, List<String>>,
        val purls: Set<String>,
        val classCount: Int,
        val functionCount: Int,
        val bodylessRecords: Int,
        val summarised: Summarizer.Result,
    ) {
        /**
         * The summaries joined by canonical NAME. There is deliberately no
         * descriptor parameter on [summaries]: Kotlin `vararg`/`Unit`-bridge
         * call descriptors never equal the raw JVM ones the class file
         * carries, so a workspace call site can only ever name the tier by
         * FQN — and a name-keyed reader must not be answered with ONE
         * overload's effects. Until P22 the tier's `associateBy` kept the
         * last overload and dropped the rest (R133's shape in the tier);
         * the view is now the CONSERVATIVE JOIN across every overload of
         * the name — a may-analysis union, so an effect any overload has is
         * an effect the name carries. Sorted concatenation keeps the join
         * deterministic.
         */
        private val byName: Map<String, FunctionSummary> = buildMap {
            for ((key, summary) in table) {
                val name = key.substringBefore('\u0000')
                val existing = this[name]
                this[name] = if (existing == null) summary else existing.join(summary)
            }
        }

        /**
         * Resolves a workspace call into the tier's summary by canonical
         * name (direct, then demangler aliases).
         */
        fun summaries(fqn: String): FunctionSummary? {
            byName[fqn]?.let { return it }
            for (alias in aliases[fqn].orEmpty()) {
                byName[alias]?.let { return it }
            }
            return null
        }
    }

    fun analyze(module: KirModule, pack: ModelPack, attribution: Attribution, options: Options): Result {
        val diagnostics = mutableListOf<Diagnostic>()
        val truncations = java.util.TreeMap<String, Int>()
        val skips = java.util.TreeMap<String, Int>()
        /**
         * R176: the skip kinds that are POLICY, not caps — reported in
         * `skips{}`, never in `truncations{}`. Anything added here is a
         * deliberate, lossless exclusion whose summaries still apply.
         */
        val POLICY_SKIPS = setOf("generated-functions")
        val candidates = mutableListOf<SliceCandidate>()
        val nodeInfos = java.util.TreeSet<NodeInfo>(compareBy { it.sortKey })
        var functionsAnalysed = 0
        var fixpointCapHits = 0
        var sourceSites = 0
        var sinkSites = 0
        var unknownCallPropagations = 0
        var sliceCapReported = false
        // P10: the budget whose trip degraded this run (a diagnostic code), if any.
        var stopCode: String? = null

        // ---- compile everything once, with GLOBAL site ids ------------------
        val functions = module.functions
            .filter { it.body != null }
            .sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }))
        val compiled = mutableListOf<CompiledFunction>()
        var nextSite = 0
        for (function in functions) {
            val cf = compile(function, nextSite) ?: continue
            nextSite += cf.siteById.size
            compiled.add(cf)
        }
        val siteIndex = HashMap<Int, Pair<CompiledFunction, Site>>()
        for (cf in compiled) {
            for ((id, site) in cf.siteById) siteIndex[id] = cf to site
        }

        // ---- P5: resolve callees, condense SCCs, compute summaries -----------
        // allFunctions: the DI facts are SIGNATURE facts, and a binding
        // method (`@Binds`) is abstract — bodyless, invisible to the compiled
        // list (P26 §2).
        val callIndex = CallIndex(compiled, options.dispatchMode, module.functions)

        // ---- P9: the `--deps` tier, summarised BEFORE the workspace's -------
        // (dependencies never call back into the workspace, so their
        // summaries need nothing from it — while workspace functions whose
        // bodies pass taint THROUGH a dependency compose the jar's effects
        // into their own summaries). The tier's functions are compiled with
        // site ids CONTINUING after the workspace's — one global site space,
        // so one trace can walk into the jar and back out. Body-less records
        // never reach this loop: they have no body to compile and are
        // counted, never concluded about.
        val depsFunctions = options.depsModule?.functions
            ?.filter { it.body != null }
            ?.sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }))
            .orEmpty()
        val depsCompiled = mutableListOf<CompiledFunction>()
        if (options.depsModule != null) {
            var depSite = nextSite
            for (function in depsFunctions) {
                val cf = compile(function, depSite) ?: continue
                depSite += cf.siteById.size
                depsCompiled.add(cf)
            }
        }
        val depsTier = options.depsModule?.let {
            val depCallIndex = CallIndex(depsCompiled, options.dispatchMode)
            // The tier runs on the SAME per-SCC iteration budget as the
            // workspace. It briefly carried a 4x one, justified as keeping
            // the `bytecode` label from degrading to `recursive-approx` —
            // which the label cannot do (the relabel below is guarded on the
            // workspace origin), so the constant bought nothing the corpus
            // could see. An under-converged tier stays visible instead, in
            // the sccIterationCapHits the run publishes over sccsProcessed.
            val depSummary = Summarizer(depsCompiled, depCallIndex, pack, options, SummaryOrigin.BYTECODE).compute()
            for ((kind, count) in depSummary.skipped) {
                truncations.merge(kind, count, Int::plus)
            }
            // P16 §2: the composed-path depth cap's exact drops, counted per
            // run — the degradation was real but invisible before.
            if (depSummary.composedPathDrops > 0) {
                truncations.merge("composed-path-depth", depSummary.composedPathDrops, Int::plus)
            }
            if (stopCode == null) depSummary.stoppedBy?.let { stopCode = it }
            DepsTier(
                compiled = depsCompiled,
                callIndex = depCallIndex,
                table = depSummary.table,
                aliases = options.depsAliases,
                purls = options.depsPurls,
                classCount = options.depsClassCount,
                functionCount = depsCompiled.size,
                bodylessRecords = options.depsBodylessRecords,
                summarised = depSummary,
            )
        }
        if (depsTier != null) {
            for (cf in depsCompiled) {
                for ((id, site) in cf.siteById) siteIndex[id] = cf to site
            }
        }

        val summarizer = Summarizer(compiled, callIndex, pack, options, deps = depsTier)
        val summaryResult = summarizer.compute()
        for ((kind, count) in summaryResult.skipped) {
            truncations.merge(kind, count, Int::plus)
        }
        if (summaryResult.composedPathDrops > 0) {
            truncations.merge("composed-path-depth", summaryResult.composedPathDrops, Int::plus)
        }
        if (stopCode == null) summaryResult.stoppedBy?.let { stopCode = it }

        // Keyed by FUNCTION (P22 §1): two overloads of one name each carrying
        // lambdas must not answer for each other's lambda bodies.
        val lambdaDefs = compiled.associate { functionKey(it.function) to lambdaDefsOf(it) }
        val captures = compiled.associate { cf ->
            functionKey(cf.function) to buildMap {
                for (block in cf.blocks) {
                    for (ins in block.instructions) {
                        if (ins is KirLambda) put(ins.function, ins.captures)
                    }
                }
            }
        }
        // P24 §4: the access-path `*` collapse, counted where it binds —
        // every collapsed path in the analysed bodies is a field the
        // engine can no longer tell apart. Zero on the deep tier at the
        // default depth is the depth doctrine's (a); non-zero is a
        // measurement, never a shrug.
        var accessPathCollapses = 0
        for (cf in compiled) {
            for (block in cf.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is KirFieldGet -> if (ins.path.collapsed) accessPathCollapses++
                        is KirFieldSet -> if (ins.path.collapsed) accessPathCollapses++
                        else -> {}
                    }
                }
            }
        }
        if (accessPathCollapses > 0) {
            truncations.merge("access-path-collapse", accessPathCollapses, Int::plus)
        }

        // P25 §0: declared functions reachable as VALUES, by canonical name,
        // and only where the name is unambiguous (see FunctionValueTarget).
        val functionValues = buildMap {
            val byCanonical = compiled.groupBy { it.function.canonicalName }
            for ((canonical, functions) in byCanonical) {
                val withBody = functions.filter { it.function.body != null }
                val only = withBody.singleOrNull() ?: continue
                val key = functionKey(only.function)
                if (key !in summaryResult.table) continue
                put(canonical, FunctionValueTarget(key, if (only.function.params.firstOrNull()?.receiver == true) 1 else 0))
            }
        }

        val context = EngineContext(
            pack = pack,
            siteIndex = siteIndex,
            callIndex = callIndex,
            table = summaryResult.table,
            lambdaDefs = lambdaDefs,
            captures = captures,
            options = options,
            deps = depsTier,
            functionValues = functionValues,
        )
        // P20 §0: the summary-missing set — compiled functions with no
        // summary in the final table. A body-less function never compiles
        // and owes nothing; a compiled one owes its summary to every caller.
        // Names, not keys: call sites ask by FQN.
        val summarisedNames = summaryResult.table.keys.mapTo(HashSet()) { it.substringBefore('\u0000') }
        for (cf in compiled) {
            if (cf.function.canonicalName !in summarisedNames) {
                context.missingSummaries.add(cf.function.canonicalName)
            }
        }
        if (depsTier != null) {
            val depSummarisedNames = depsTier.table.keys.mapTo(HashSet()) { it.substringBefore('\u0000') }
            for (cf in depsCompiled) {
                if (cf.function.canonicalName !in depSummarisedNames) {
                    context.missingSummaries.add(cf.function.canonicalName)
                }
            }
        }

        // ---- the per-function main analysis ----------------------------------
        // P10: the per-function work runs on [options.dataflowWorkers] workers
        // and is folded back in COMPILED ORDER, so candidates, node ids and
        // slice ids are identical at any worker width. The budget hook runs
        // per function; a trip keeps everything already analysed, counts what
        // is being dropped, and ships the partial result.
        data class Slot(val cf: CompiledFunction, val outcome: FunctionOutcome?, val skippedKind: String?)

        fun analyseSlot(cf: CompiledFunction): Slot {
            val function = cf.function
            if (options.skipGenerated && function.syntheticCause != null) {
                return Slot(cf, null, "generated-functions")
            }
            val instructionCount = cf.sitesByBlock.values.sumOf { it.size }
            if (instructionCount > options.maxFunctionInstructions) {
                return Slot(cf, null, "function-instructions")
            }
            options.shouldStop?.invoke()?.let { code ->
                return Slot(cf, null, code)
            }
            return Slot(cf, analyseFunction(cf, context), null)
        }

        val slots: List<Slot> = if (options.dataflowWorkers > 1 && compiled.size > 1) {
            val width = minOf(options.dataflowWorkers, compiled.size)
            val pool = java.util.concurrent.Executors.newFixedThreadPool(width)
            try {
                val futures = compiled.map { cf -> pool.submit(java.util.concurrent.Callable { analyseSlot(cf) }) }
                futures.map { it.get() }
            } finally {
                pool.shutdown()
            }
        } else {
            compiled.map { analyseSlot(it) }
        }
        for (slot in slots) {
            val outcome = slot.outcome
            if (outcome == null) {
                val kind = slot.skippedKind ?: "dataflow-truncated"
                // R176: policy skips are not truncations. The generated
                // bodies' summaries still apply; a cap counter that includes
                // them lies about what bounded the run.
                if (kind in POLICY_SKIPS) {
                    skips.merge(kind, 1, Int::plus)
                } else {
                    truncations.merge(kind, 1, Int::plus)
                }
                if (kind == DiagnosticCodes.ANALYSIS_TIME_BUDGET || kind == DiagnosticCodes.RSS_BUDGET) {
                    stopCode = kind
                }
                continue
            }
            val cf = slot.cf
            functionsAnalysed++
            if (outcome.capHit) fixpointCapHits++
            if (outcome.capHit) {
                context.recordCapAffectedSinkHits(outcome.hits.sumOf { it.facts.size } + outcome.interHits.size)
            }
            sourceSites += outcome.sourceSites
            sinkSites += outcome.sinkSites
            unknownCallPropagations += outcome.unknownCallPropagations
            for (hit in outcome.hits) {
                for (fact in hit.facts) {
                    if (candidates.size >= options.maxSlices) {
                        if (!sliceCapReported) {
                            truncations.merge("slices", 1, Int::plus)
                            sliceCapReported = true
                        }
                        continue
                    }
                    buildSlice(cf, context, outcome.chain, hit, fact, attribution)?.let { candidate ->
                        candidates.add(candidate)
                        nodeInfos.addAll(candidate.nodes)
                    } ?: context.recordSliceDropUnprovable()
                }
            }
            for (hit in outcome.interHits) {
                if (candidates.size >= options.maxSlices) {
                    if (!sliceCapReported) {
                        truncations.merge("slices", 1, Int::plus)
                        sliceCapReported = true
                    }
                    continue
                }
                buildInterproceduralSlice(cf, context, outcome.chain, hit, attribution)?.let { candidate ->
                    candidates.add(candidate)
                    nodeInfos.addAll(candidate.nodes)
                } ?: context.recordSliceDropUnprovable()
            }
        }

        if (fixpointCapHits > 0) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.FIXPOINT_CAP,
                    severity = Severity.WARNING,
                    message = "$fixpointCapHits of $functionsAnalysed analysed function(s) hit the worklist " +
                        "iteration budget before converging; their slices are best-effort and flows a further " +
                        "round would have added are absent",
                    count = fixpointCapHits,
                ),
            )
        }
        if (summaryResult.sccIterationCapHits > 0) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.SUMMARY_ITERATION_CAP,
                    severity = Severity.WARNING,
                    message = "${summaryResult.sccIterationCapHits} of ${summaryResult.sccsProcessed} strongly " +
                        "connected component(s) hit the summary iteration budget; their members' summaries are " +
                        "the last iterate, labelled origin=recursive-approx, and flows a further round would " +
                        "have added are absent",
                    count = summaryResult.sccIterationCapHits,
                ),
            )
        }
        if (context.joinOverruns > 0) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.DISPATCH_JOIN_WIDTH,
                    severity = Severity.INFO,
                    message = "${context.joinOverruns} call site(s) joined more summaries than the width " +
                        "budget ${options.dispatchJoinBudget}; the JOIN over all targets was applied and " +
                        "precision may suffer where the targets disagree",
                    count = context.joinOverruns,
                ),
            )
        }
        if (context.lambdaUnresolved > 0) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.LAMBDA_UNRESOLVED,
                    severity = Severity.INFO,
                    message = "${context.lambdaUnresolved} lambda value(s) could not be resolved to an " +
                        "extracted body (callable references, local functions); no summary was applied " +
                        "through them",
                    count = context.lambdaUnresolved,
                ),
            )
        }
        for ((kind, count) in truncations) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.DATAFLOW_TRUNCATED,
                    severity = Severity.INFO,
                    message = "dataflow limit '$kind' hit $count time(s); the affected functions or slices are absent",
                    count = count,
                ),
            )
        }
        // R176: policy skips carry their own vocabulary — a diagnostic here
        // would re-create the very confusion the split exists to end (a
        // skip is not a truncation), but SILENCE is not the alternative
        // either: the counts are published in stats.skips{} and
        // stats.policySkips{} for consumers.
        for ((kind, count) in skips) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.DATAFLOW_SKIPPED_POLICY,
                    severity = Severity.INFO,
                    message = "$count function(s) skipped by policy '$kind' (summaries still apply; nothing " +
                        "was cut by a cap — see stats.policySkips)",
                    count = count,
                ),
            )
        }

        if (stopCode != null) {
            diagnostics.add(
                Diagnostic(
                    code = stopCode!!,
                    severity = Severity.WARNING,
                    message = "the analysis budget was exceeded; the run degraded without discarding computed " +
                        "evidence: $functionsAnalysed of ${compiled.size} workspace function(s) analysed, " +
                        "${summaryResult.table.size} workspace and ${depsTier?.table?.size ?: 0} dependency " +
                        "summary(ies) converged before the trip; everything after the trip is absent",
                    count = compiled.size - functionsAnalysed,
                ),
            )
        }

        // bytecodeAppliedFqns records CANONICAL NAMES (call sites ask by
        // FQN); the tier's table is keyed by functionKey — compare on the
        // name half (P22 §1).
        val bytecodeSummaries = depsTier
            ?.table
            ?.entries
            ?.filter { it.key.substringBefore('\u0000') in context.bytecodeAppliedFqns }
            ?.map { it.value.toSchema() }
            .orEmpty()
        val allSummaries = buildList {
            addAll(summaryResult.table.values.map { it.toSchema() })
            addAll(packOriginSummaries(context))
            addAll(bytecodeSummaries)
        }.sortedBy { it.functionId }

        // P24 §4: the caps live in the report, not in a diagnostic a
        // consumer must parse — `truncations{}` per cap, empty when none
        // bound (which is the depth doctrine's claim, checkable).
        val evidence = materialise(candidates, nodeInfos, pack, options, allSummaries, context, bytecodeSummaries.size)
            .let { it.copy(stats = it.stats.copy(truncations = truncations, skips = skips)) }
        return Result(
            evidence = evidence,
            functionsAnalysed = functionsAnalysed,
            fixpointCapHits = fixpointCapHits,
            sourceSites = sourceSites,
            sinkSites = sinkSites,
            unknownCallPropagations = unknownCallPropagations,
            truncations = truncations,
            skips = skips,
            diagnostics = diagnostics.sortedWith(Diagnostic.COMPARATOR),
            summaries = allSummaries,
            sccsProcessed = summaryResult.sccsProcessed,
            sccIterationCapHits = summaryResult.sccIterationCapHits,
            dispatchJoins = context.joinWidths.mapValues { it.value },
            suspendCrossingSlices = candidates.count { it.suspendCrossing },
            bodylessRecords = depsTier?.bodylessRecords ?: 0,
            dependencyClasses = depsTier?.classCount ?: 0,
            dependencyFunctions = depsTier?.functionCount ?: 0,
            depth = DepthStats(
                entryFactsSeeded = context.entryFactsSeeded,
                slicesDroppedUnprovable = context.slicesDroppedUnprovable,
                capAffectedSinkHits = context.capAffectedSinkHits,
                summaryMissingEvents = context.summaryMissingEvents,
                sanitizersApplied = context.sanitizersApplied.toList(),
                sourceSites = sourceSites,
                sinkSites = sinkSites,
            ),
            // P22 §0: the workspace tier's verdicts on "can taint reach the
            // return value", per function — the depth report's agreement
            // gate compares the const folder's answers against these.
            returnOpinions = ReturnOpinions(
                summaryResult.table.mapValues { (_, s) -> s.paramToReturn.isNotEmpty() || s.sourceReturns.isNotEmpty() },
            ),
        )
    }

    /**
     * Pack-derived summaries (origin=pack): for every callee the pack
     * actually moved taint for at a call site, a summary shaped by the pack
     * entries themselves. These are what `summariesByOrigin` needs a second
     * key for — and they are DATA-derived, not invented.
     */
    private fun packOriginSummaries(context: EngineContext): List<io.cdxgen.kosi.schema.FlowSummary> {
        val pack = context.pack
        val out = mutableListOf<io.cdxgen.kosi.schema.FlowSummary>()
        fun blank(fqn: String): io.cdxgen.kosi.schema.FlowSummary = io.cdxgen.kosi.schema.FlowSummary(
            functionId = fqn,
            function = fqn,
            parameterNames = emptyList(),
            parameterTypes = emptyList(),
            returnType = "",
            paramToReturn = emptyList(),
            paramToParam = emptyList(),
            paramToReceiver = emptyList(),
            paramToSink = emptyMap(),
            sourceReturns = emptyList(),
            sanitizes = emptyList(),
            accessPaths = emptyMap(),
            origin = SummaryOrigin.PACK,
        )
        for (fqn in context.packAppliedSources) {
            val source = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, fqn) } ?: continue
            out.add(blank(fqn).copy(sourceReturns = listOf(source.category)))
        }
        for (fqn in context.packAppliedPassthroughs) {
            val passthrough = pack.passthroughs.firstOrNull { PatternMatcher.matches(it.pattern, fqn) } ?: continue
            val tos = sortedSetOf<String>()
            val receivers = sortedSetOf<String>()
            for (flow in passthrough.flows) {
                if (flow.size < 2) continue
                if (flow[1] != -1) continue // result-ward flows only
                val from = "p${flow[0]}"
                tos.add(from)
            }
            val effects = pack.effects.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
            if (effects != null) {
                for (index in effects.writesToArguments) receivers.add("p$index")
            }
            val summary = blank(fqn).copy(
                paramToReturn = tos.toList(),
                paramToReceiver = receivers.toList(),
                accessPaths = if (receivers.isEmpty()) emptyMap() else receivers.associateWith { "[]" },
            )
            if (summary.paramToReturn.isNotEmpty() || summary.paramToReceiver.isNotEmpty()) out.add(summary)
        }
        return out
    }

    // ---- the per-function worklist --------------------------------------------

    private class SinkHit(val sinkSite: Int, val argIndex: Int, val key: TaintKey, val facts: Set<TaintFact>)

    /**
     * An interprocedural sink hit: the caller's facts on an argument reached
     * a sink INSIDE the callee through [effect]'s recorded path.
     */
    private class InterSinkHit(
        val callSite: Int,
        val argKey: TaintKey,
        val facts: Set<TaintFact>,
        val effect: SummarySinkEffect,
        val origin: String,
    )

    private class FunctionOutcome(
        val capHit: Boolean,
        val sourceSites: Int,
        val sinkSites: Int,
        val unknownCallPropagations: Int,
        /** Post-fixpoint intraprocedural sink hits, with the exact facts live. */
        val hits: List<SinkHit>,
        /** Post-fixpoint interprocedural sink hits (sinks inside callees). */
        val interHits: List<InterSinkHit>,
        /** The fixpoint provenance chains the traces walk. */
        val chain: HashMap<ChainKey<TaintFact>, Move>,
    )

    private fun analyseFunction(compiled: CompiledFunction, context: EngineContext): FunctionOutcome {
        val chain = HashMap<ChainKey<TaintFact>, Move>()
        val host = ReportingHost(context, compiled, chain)
        val flowTransfer = FlowTransfer(host, chain)
        val blocks = compiled.blocks

        val fixpoint = flowTransfer.runFixpoint(blocks, compiled.sitesByBlock, compiled.successors, compiled.predecessors)
        val capHit = fixpoint?.capHit ?: false
        val outStates = fixpoint?.outStates ?: emptyMap()

        // Final sweep at fixpoint: one canonical pass in block order records
        // every sink hit with the exact facts live at that instruction, and
        // freezes the provenance chains the traces walk.
        val events = TransferEvents()
        for (block in blocks) {
            val input = flowTransfer.inputForBlock(block.id, outStates, compiled.predecessors)
            flowTransfer.transfer(compiled.sitesByBlock.getValue(block.id), input, events)
        }
        return FunctionOutcome(
            capHit = capHit,
            sourceSites = events.sourceSites,
            sinkSites = events.sinkSites,
            unknownCallPropagations = events.unknownPropagations,
            hits = events.sinkHits.sortedWith(compareBy({ it.sinkSite }, { it.argIndex }, { it.key })),
            interHits = events.interHits.sortedWith(
                compareBy({ it.callSite }, { it.effect.sinkSite }, { it.effect.paramIndex }, { it.effect.sinkCategory }),
            ),
            chain = chain,
        )
    }

    private class TransferEvents {
        var sourceSites = 0
        var sinkSites = 0
        var unknownPropagations = 0
        val sinkHits = mutableListOf<SinkHit>()
        val interHits = mutableListOf<InterSinkHit>()
    }

    /**
     * The reporting engine's half of the ONE shared transfer: all the
     * decisions that are genuinely ours — what is counted, which facts a
     * sink hit carries, how callee summaries are applied under the dispatch
     * modes — supplied to [FlowTransfer] as callbacks. The opcode handling
     * itself is not ours to change (R65).
     */
    private class ReportingHost(
        val context: EngineContext,
        val compiled: CompiledFunction,
        val chain: HashMap<ChainKey<TaintFact>, Move>,
    ) : TransferHost<TaintFact, TransferEvents> {
        override val ops = TaintFactOps
        override val pack: ModelPack get() = context.pack
        override val unknownCallPropagate: Boolean get() = context.options.unknownCallPropagate
        override val fieldSensitive: Boolean get() = context.options.accessPathDepth > 0

        /**
         * P24 §2: this function's alias classes, from the allocation-site
         * fixpoint over the same CFG (the final summary table feeding it —
         * the reporting engine runs after the summariser converged).
         */
        private val aliases: AliasAnalysis by lazy {
            AliasAnalysis(compiled) { ins -> summaryForCall(ins) }.also { it.run() }
        }

        override fun aliasClass(register: String): Set<String> = aliases.aliasClass(register)

        override fun lambdaTargets(register: String): List<String> = aliases.lambdaTargets(register)

        /** One summary lookup for a call site (the alias feed; may-union across targets). */
        private fun summaryForCall(ins: KirCall): FunctionSummary? {
            if (ins.callee.kind == CallKind.CONSTRUCTOR) {
                val name = ins.callee.fqn + ".<init>"
                var joined: FunctionSummary? = null
                for ((key, summary) in context.table) {
                    if (key.substringBefore('\u0000') != name) continue
                    joined = if (joined == null) summary else joined.join(summary)
                }
                return joined
            }
            val targets = context.callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)
            var joined: FunctionSummary? = null
            for (target in targets) {
                val summary = context.table[functionKey(target)] ?: continue
                joined = if (joined == null) summary else joined.join(summary)
            }
            return joined
        }

        override fun birthFact(site: Int, category: String): TaintFact = TaintFact(site, category)

        override fun packMoveOrigin(): String? = SummaryOrigin.PACK

        override fun onSanitizerSurvived(site: Int, survived: Set<String>, collect: TransferEvents?) {
            context.recordSanitizerSurvived(site, survived)
        }

        override fun onSourceApplied(fqn: String, site: Int, fact: TaintFact, resultKey: TaintKey, collect: TransferEvents?) {
            if (collect != null) {
                collect.sourceSites += 1
                context.recordPackSource(fqn)
            }
        }

        override fun onSanitizerCleared(fqn: String, cleared: List<String>, collect: TransferEvents?) {
            if (collect != null) context.recordSanitizerApplied(fqn)
        }

        override fun onPackPassthroughApplied(fqn: String, collect: TransferEvents?) {
            if (collect != null) context.recordPackPassthrough(fqn)
        }

        /**
         * P26 §1.3: mark the deserializer's result facts FIELD-BEARING —
         * every field read of the produced object derives them. The variant
         * facts take over the key, and each inherits the chain entry of the
         * fact it replaced (a replaced identity without an entry dead-ends
         * the backward walk at exactly this call).
         */
        override fun onDeserializerResult(
            result: String?,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ) {
            if (result == null) return
            val key = TaintKey(result, "")
            val facts = state.factsOf(key).toList()
            if (facts.isEmpty()) return
            val bearing = java.util.TreeSet(facts.map { it.asFieldBearing() })
            state.setFacts(key, bearing)
            for (original in facts) {
                val variant = original.asFieldBearing()
                val chainKey = ChainKey(variant, key)
                if (chain[chainKey] == null) {
                    chain[chainKey] = chain[ChainKey(original, key)]
                        ?: Move(site, null, "deserializer", packMoveOrigin())
                }
            }
        }

        override fun onSinkMatched(collect: TransferEvents?) {
            collect?.let { it.sinkSites += 1 }
        }

        /**
         * P26 §1.1: the callee names a bodyless INTERFACE method whose
         * declaration matches a pack interfaceSinks row — a Spring Data
         * repository method (derived query or @Query) or a Room DAO query.
         * Every argument is relevant: the method's parameters ARE the
         * query's bind values.
         */
        override fun interfaceSink(ins: KirCall): io.cdxgen.kosi.models.SinkPattern? =
            InterfaceSinks.sinkPatternFor(context.callIndex, pack, ins)

        override fun onResolvedCall(ins: KirCall, site: Int, collect: TransferEvents?) {}

        override fun onSinkRead(
            sink: io.cdxgen.kosi.models.SinkPattern,
            fqn: String,
            site: Int,
            argIndex: Int,
            argKey: TaintKey,
            facts: Set<TaintFact>,
            collect: TransferEvents?,
        ) {
            collect?.sinkHits?.add(SinkHit(site, argIndex, argKey, facts))
        }

        override fun onEffectWritten(
            fqn: String,
            valueReg: String,
            receiverKey: TaintKey,
            facts: Set<TaintFact>,
            site: Int,
            collect: TransferEvents?,
        ) {}

        override fun onFieldWriteEscape(receiver: String, valueReg: String, suffix: String, facts: Set<TaintFact>, collect: TransferEvents?) {}

        override fun onReturn(ins: KirReturn, site: Int, state: FlowState<TaintFact>, collect: TransferEvents?) {}

        override fun onDynamicCall(ins: KirDynamicCall, site: Int, collect: TransferEvents?) {}

        override fun onUnknownPropagation(collect: TransferEvents?) {
            collect?.let { it.unknownPropagations += 1 }
        }

        private val literalMatchers: List<Pair<Regex, String>> =
            context.pack.literalSources.map { Regex(it.namePattern) to it.category }

        override fun literalSourceCategory(name: String): String? =
            literalMatchers.firstOrNull { (regex, _) -> regex.matches(name) }?.second

        /**
         * P20 §1: the source is a PARAMETER, not a function. The facts are
         * computed once per function (the transfer asks on every block
         * input) and cached — the same list the depth report counts as
         * `entryFactsSeeded`. `#N` indexes the handler's VALUE parameters
         * (the receiver is not an input), matching the pack's argument
         * convention.
         */
        private val seededEntryFacts: List<Pair<String, TaintFact>> by lazy {
            val handler = compiled.function.canonicalName
            val category = context.options.endpointSources[handler] ?: return@lazy emptyList()
            val valueParams = compiled.function.params.filter { !it.receiver }
            val annotations = context.options.endpointParameterAnnotations
            val framework = context.options.endpointHandlerFrameworks[handler]
            val facts = when (context.options.endpointHandlerInput[framework]) {
                // The framework names its transports: seed exactly those —
                // including nothing, when a handler takes only injected
                // collaborators. Each seeded parameter carries its OWN
                // category and its index, so the slice can say which
                // parameter and which transport it entered through.
                "annotated" -> valueParams.mapIndexed { index, param ->
                    val matched = param.annotations.firstNotNullOfOrNull { annotation ->
                        annotations.entries.firstOrNull { (pattern, _) ->
                            PatternMatcher.matches(pattern, annotation)
                        }?.value
                    }
                    matched?.let { param.register to TaintFact(SummaryAnalysis.ENTRY_SITE, it.category, index) }
                }

                // P27 §2: the framework names SOME transports and binds
                // whatever else is not one of its own collaborators. Spring
                // MVC's command object is this: `processFindForm(owner:
                // Owner, result: BindingResult, model: Map)` annotates
                // nothing, and `owner` is the submitted form. Seeding only
                // the annotated parameters read three flows out of
                // spring-petclinic and missed the six handlers whose whole
                // input arrives this way.
                //
                // An annotated parameter keeps ITS transport and category; an
                // unannotated one is data unless its TYPE is a declared
                // context type. Matching is on the RESOLVED type by suffix
                // segment, the rule every other type match here follows, and
                // a parameter whose type did not resolve is treated as data
                // — the direction that produces a finding to triage rather
                // than a silence.
                io.cdxgen.kosi.models.HANDLER_INPUT_ANNOTATED_OR_BOUND -> {
                    val contextTypes = context.options.endpointContextParameterTypes[framework].orEmpty()
                    val nonInput = context.options.endpointNonInputAnnotations[framework].orEmpty()
                    val simpleTypes = context.options.endpointSimpleParameterTypes[framework].orEmpty()
                    valueParams.mapIndexed { index, param ->
                        val matched = param.annotations.firstNotNullOfOrNull { annotation ->
                            annotations.entries.firstOrNull { (pattern, _) ->
                                PatternMatcher.matches(pattern, annotation)
                            }?.value
                        }
                        when {
                            matched != null -> param.register to TaintFact(
                                SummaryAnalysis.ENTRY_SITE,
                                matched.category,
                                index,
                                fieldBearing = matched.kind in OBJECT_TRANSPORTS,
                            )

                            // Only a declared NON-INPUT annotation excludes
                            // a parameter. `@Valid` is not one: Spring binds
                            // a validated command object exactly as it binds
                            // a bare one, and treating any annotation as
                            // injection dropped most of spring-petclinic's
                            // form handlers.
                            param.annotations.any { annotation ->
                                nonInput.any { annotation == it || annotation.endsWith(".$it") }
                            } -> null

                            isContextType(param.resolvedType, contextTypes) -> null

                            // P27 §2, Spring's own fallback rule: "if it is
                            // a simple type it is resolved as a
                            // @RequestParam, otherwise as a @ModelAttribute".
                            // Either way it is request data; the type decides
                            // the TRANSPORT.
                            //
                            // A command object is bound as a WHOLE OBJECT, so
                            // the request's data sits on its FIELDS —
                            // `owner.lastName`, never `owner` — and a bare
                            // fact derives nothing on a field read. That is
                            // the shape P26 gave a deserializer's result, for
                            // the same reason: no code the engine can see
                            // wrote those fields, so there is no per-field
                            // key to find. Without it the seed is real and
                            // every USE of it is invisible, which is how
                            // `processFindForm(owner)` reaching
                            // `findByLastName(owner.lastName)` — the plainest
                            // flow in spring-petclinic — went unreported.
                            else -> param.register to TaintFact(
                                SummaryAnalysis.ENTRY_SITE,
                                category,
                                index,
                                fieldBearing = !isSimpleType(param.resolvedType, simpleTypes),
                            )
                        }
                    }
                }

                // The parameter is a request CONTEXT, not data. Its reader
                // methods are the modelled sources; seeding the context
                // itself would taint the response object handed in beside
                // it, and every unrelated value reachable through it.
                "context" -> valueParams.map { null }

                // P28 §2: `all` means the parameter IS the payload — but the
                // docs of the `all` frameworks themselves name collaborators
                // handed in BESIDE it (AWS Lambda's runtime Context is "the
                // second argument", gRPC's StreamObserver carries responses
                // OUT, Android's onReceive Context is the framework's own).
                // A declared context type is excluded under `all` exactly as
                // under annotated-or-bound; a type not listed stays data —
                // the same triage-over-silence direction.
                //
                // An OBJECT payload seeds FIELD-BEARING (the P27 §2 rule for
                // Spring's command objects, and for the same measured
                // reason): a gRPC request message, a Lambda event POJO, an
                // Android Bundle all carry the request on their FIELDS, and
                // a bare fact derives nothing on `request.name` — the
                // plainest flow in any grpc service would be invisible.
                else -> {
                    val contextTypes = context.options.endpointContextParameterTypes[framework].orEmpty()
                    valueParams.mapIndexed { index, param ->
                        when {
                            isContextType(param.resolvedType, contextTypes) -> null
                            else -> param.register to TaintFact(
                                SummaryAnalysis.ENTRY_SITE,
                                category,
                                index,
                                fieldBearing = !isSimpleType(param.resolvedType, ALL_PAYLOAD_SIMPLE_TYPES),
                            )
                        }
                    }
                }
            }.filterNotNull()
            context.recordEntryFacts(facts.size)
            facts
        }

        /**
         * P27 §2: is this parameter's type one the framework hands the
         * handler rather than one it binds from the request?
         *
         * A generic type matches on its RAW name (`kotlin.collections.Map`
         * covers a model map spelled `MutableMap<String, Any>`), and an
         * unresolved type is NOT treated as context: the framework's
         * collaborator list is short and known, so an unknown type is far
         * more likely to be a command object than a missing context class,
         * and a false finding is triageable where a silence is not.
         */
        private fun isContextType(resolved: String?, contextTypes: List<String>): Boolean {
            if (contextTypes.isEmpty()) return false
            val type = resolved?.substringBefore('<') ?: return false
            return contextTypes.any { type == it || type.endsWith(".$it") }
        }

        /**
         * P27 §2: Spring's `BeanUtils.isSimpleProperty` — a simple value type
         * or an ARRAY of one. An unresolved type is not simple, so it is
         * treated as a command object: the direction that produces a finding
         * to triage rather than a silence.
         */
        private fun isSimpleType(resolved: String?, simpleTypes: Collection<String>): Boolean {
            if (simpleTypes.isEmpty()) return false
            val type = (resolved ?: return false).substringBefore('<').removeSuffix("[]")
            return simpleTypes.any { type == it || type.endsWith(".$it") }
        }

        override fun entryBindings(): List<Pair<String, TaintFact>> = seededEntryFacts

        private companion object {
            /**
             * P27 §2: transports that bind a whole OBJECT, whose fields
             * therefore carry the request's data. A path or query parameter
             * is a scalar and a field read of it means nothing.
             */
            val OBJECT_TRANSPORTS = setOf("body", "form")
        }

        override fun entryBlockId(): String? = compiled.blocks.firstOrNull()?.id

        fun moveChain(
            state: FlowState<TaintFact>,
            from: TaintKey,
            to: TaintKey,
            site: Int,
            kind: String,
            origin: String?,
        ): Boolean {
            val facts = state.factsOf(from)
            if (facts.isEmpty()) return false
            state.addFacts(to, facts)
            for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind, origin)
            return true
        }

        /**
         * Applies the JOIN of the dispatch targets' summaries at one call site.
         * Returns false when no target had a summary to apply (the shared
         * unknown default runs). `paramToSink` effects materialise as
         * INTERPROCEDURAL sink hits whose traces stitch the caller's chain to
         * the callee's recorded path; `paramToReturn`/`paramToParam`/
         * `paramToReceiver`/`sourceReturns` move the caller's facts with the
         * summary's origin stamped on every boundary move.
         *
         * P24 adds the object-identity channels: constructor calls apply the
         * class's `<init>` summary with the NEW OBJECT as the receiver; calls
         * through a KNOWN function value apply the target body's summary;
         * field-write effects fan out through the argument's alias class;
         * source-born field writes and invoke binds complete the circuits the
         * register-keyed engine could not express.
         */
        override fun applyCalleeSummaries(
            ins: KirCall,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ): Boolean {
            val options = context.options

            // P24 §2d: a call through a function value this body DEFINED (or
            // copied) — the value is an object whose target is known at its
            // allocation site, and the invoke resolves to that target.
            if (ins.callee.fqn.endsWith(".invoke") && ins.receiver != null) {
                if (applyLambdaInvoke(ins, site, state, chain, collect)) return true
            }

            // P24 §2b: a constructor applies the class's `<init>` summary —
            // the constructor is a function that writes the object's fields,
            // so `Job(tainted)` taints `job.command` through the same
            // paramFieldWrites channel every member function uses. The NEW
            // OBJECT (the call's result) is the receiver.
            if (ins.callee.kind == CallKind.CONSTRUCTOR) {
                val ctor = constructorSummary(ins)
                if (ctor != null) {
                    currentCallArgs = ins.args
                    applyOne(ctor, ins.result, ins.result, site, state, chain, collect)
                    return true
                }
                return false
            }

            var targets = context.callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)
            if (targets.size > 1 && (options.dispatchMode == "vta" || options.dispatchMode == "auto")) {
                // VTA narrows by the receiver's known construction types before
                // the summary JOIN — the same positive-evidence-only refinement
                // the P3 graph applies.
                targets = context.callIndex.narrowByReceiverType(compiled.function, ins.receiver, targets)
            }
            // Keyed by FUNCTION, not name: a descriptor-narrowed call site
            // must meet its own overload's summary — the name-keyed lookup
            // answered one overload's question with a namesake's effects,
            // a missed flow one way and a confident wrong one the other
            // (P22 §1, R133's shape in the summary table).
            val applicable = targets.mapNotNull { target -> context.table[functionKey(target)]?.let { target to it } }.toMutableList()
            // P9 boundary: when no WORKSPACE target has a summary, the `--deps`
            // tier may have one. The per-summary application below is shared
            // verbatim — a dependency summary is applied exactly like a
            // workspace one, with its own origin (`bytecode`) stamped on every
            // boundary move and its `paramToSink` effects materialising as
            // interprocedural sink hits whose traces walk into the jar.
            var depOnly = false
            if (applicable.isEmpty()) {
                val dep = context.deps?.summaries(ins.callee.fqn)
                if (dep == null) {
                    // P20 §0: a call into a function whose summary is
                    // MISSING (a budget skipped it) that carries facts on
                    // its arguments is a sink this run cannot see — its
                    // paramToSink effects died with the summary. Counted,
                    // never silent.
                    if (ins.callee.fqn in context.missingSummaries) {
                        val carries = ins.args.any { arg -> state.factsOf(TaintKey(arg, "")).isNotEmpty() } ||
                            (ins.receiver?.let { state.factsOf(TaintKey(it, "")).isNotEmpty() } ?: false)
                        if (carries) context.recordSummaryMissing()
                    }
                    return false
                }
                applicable.add(dep.function to dep)
                depOnly = true
            }

            val width = applicable.size
            context.recordJoin(width)
            if (width > options.dispatchJoinBudget) context.recordJoinOverrun()
            // P24 §3: the per-hop dispatch evidence the frames read — what
            // was CONSIDERED, what was APPLIED, and what narrowed it.
            // P26 §2: a binding that leaves TWO managed implementations is
            // still the binding's decision — `di-binding` names the evidence
            // (the container's wiring), not the count, and it outranks the
            // blander width-based labels at every width.
            val narrowedBy = when {
                context.callIndex.narrowedByDiBinding(ins.callee.fqn) -> "di-binding"

                targets.size > 1 && (options.dispatchMode == "vta" || options.dispatchMode == "auto") ->
                    if (targets.size > applicable.size + 0 && applicable.size == 1) "vta" else null

                targets.size == 1 -> "single-impl"
                else -> null
            }
            context.recordDispatch(site, targets.size, applicable.map { it.first.canonicalName }, narrowedBy)
            if (ins.callee.kind == CallKind.VIRTUAL) {
                context.recordDispatchWidth(targets.size)
            }
            var moved = false
            currentCallArgs = ins.args

            for ((target, summary) in applicable.sortedBy { it.first.canonicalName }) {
                moved = applyOne(summary, ins.receiver, ins.result, site, state, chain, collect) || moved
            }
            // The applied-summary publication (P9 gate denominator) counts
            // dependency summaries that MOVED something at a workspace call
            // site, never every jar function that happened to be summarised.
            if (depOnly && moved) {
                applicable.filter { it.second.origin == SummaryOrigin.BYTECODE }
                    .forEach { context.recordBytecodeApplied(it.second.function.canonicalName) }
            }
            return true
        }

        /** The class's `<init>` summary for a constructor call, may-unioned across overloads. */
        private fun constructorSummary(ins: KirCall): FunctionSummary? {
            val name = ins.callee.fqn + ".<init>"
            var joined: FunctionSummary? = null
            for ((key, summary) in context.table) {
                if (key.substringBefore('\u0000') != name) continue
                joined = if (joined == null) summary else joined.join(summary)
            }
            return joined
        }

        /**
         * P24 §2d: an invoke whose receiver holds KNOWN lambda objects — the
         * bodies defined in this function. Their summaries apply with the
         * invoke's arguments bound to the bodies' value parameters and the
         * capture registers bound from the KirLambda site.
         */
        private fun applyLambdaInvoke(
            ins: KirCall,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ): Boolean {
            val targets = lambdaTargets(ins.receiver!!)
            if (targets.isEmpty()) return false
            var applied = false
            for (canonical in targets) {
                // A lambda's key is name-only; a DECLARED function used as a
                // value (`::sink`, an anonymous `fun`, a bound reference)
                // carries a descriptor and is found through the canonical
                // index. Its receiver, where it has one, is already bound,
                // so its parameters shift exactly as a lambda's captures do.
                val declared = context.functionValues[canonical]
                val byName = context.table[functionKeyByName(canonical)]
                val lambdaSummary = byName ?: declared?.let { context.table[it.summaryKey] } ?: continue
                val captured = if (byName == null && declared != null) {
                    List(declared.receiverOffset) { "" }
                } else {
                    context.captures[functionKey(compiled.function)]?.get(canonical).orEmpty()
                }
                val hit = applyOneWithBinding(lambdaSummary, { index ->
                    if (index < captured.size) captured[index] else ins.args.getOrNull(index - captured.size)
                }, ins.result, site, state, chain, collect)
                applied = hit || applied
            }
            return applied
        }

        /** The call-site application of one summary (receiver/args mapping). */
        private fun applyOne(
            summary: FunctionSummary,
            receiver: String?,
            result: String?,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ): Boolean {
            val callerThis = callerThisRegister(compiled)
            val receiverIndex = summary.function.params.indexOfFirst { it.receiver }
            val args = currentCallArgs
            return applyOneWithBinding(summary, { index ->
                when {
                    receiverIndex >= 0 && index == 0 -> receiver ?: callerThis
                    receiverIndex >= 0 -> args.getOrNull(index - 1)
                    else -> args.getOrNull(index)
                }
            }, result, site, state, chain, collect)
        }

        /** The args of the call being applied — set by [applyCalleeSummaries] around [applyOne]. */
        private var currentCallArgs: List<String> = emptyList()

        /**
         * One summary applied over an explicit PARAMETER BINDING (a call
         * site's receiver/args, or a lambda invoke's captures/args). Returns
         * whether anything moved.
         */
        private fun applyOneWithBinding(
            summary: FunctionSummary,
            binding: (Int) -> String?,
            result: String?,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ): Boolean {
            var moved = false
            val origin = summary.origin
            val callerThis = callerThisRegister(compiled)
            val capturedHere = context.captures[functionKey(compiled.function)].orEmpty()

            fun bindLambdaArg(lambdaCanonical: String, valueIndex: Int): String? {
                val captures = capturedHere[lambdaCanonical].orEmpty()
                return if (valueIndex < captures.size) captures[valueIndex] else null
            }

            // paramToReturn: the caller's facts move onto the result — fact
            // identity preserved, so the caller's trace keeps walking.
            if (result != null) {
                val resultKey = TaintKey(result, "")
                for (param in summary.paramToReturn.sorted()) {
                    val from = binding(param) ?: continue
                    val fromKey = TaintKey(from, "")
                    val facts = state.factsOf(fromKey)
                    if (facts.isEmpty()) continue
                    state.addFacts(resultKey, facts)
                    moved = true
                    // P24 §3: the callee-internal witness splices into the
                    // boundary move, so the frames name the callee's hops.
                    val via = summary.paramToReturnPaths[param].orEmpty()
                    for (fact in facts) {
                        chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "summary", origin, via)
                    }
                }
                // P27 §1 (R171): the argument's FIELD becomes a FIELD of the
                // result — the mapper shape, where both sides carry a path.
                for ((param, moves) in summary.paramPathToReturnPath) {
                    val from = binding(param) ?: continue
                    for (move in moves.sorted()) {
                        val fromPath = move.substringBefore('\u0000')
                        val toPath = move.substringAfter('\u0000')
                        // ALIAS-AWARE on the read side: the argument's object
                        // may be named by any register of its alias class
                        // (the call temp the value was stored from, another
                        // local holding the same object). Reading the raw
                        // argument register found the mapper's own result
                        // only when nothing had stored it first.
                        val facts = readReportingPath(state, aliasClass(from), fromPath)
                        if (facts.isNotEmpty()) {
                            val toKey = TaintKey(result, toPath)
                            state.addFacts(toKey, facts)
                            moved = true
                            for (fact in facts) {
                                chain[ChainKey(fact, toKey)] =
                                    Move(site, TaintKey(from, fromPath), "summary", origin)
                            }
                        }
                    }
                }
                // P27 §1 (R171): the argument's FIELD becomes the result —
                // the getter channel. `val body get() = raw` is this shape,
                // and so is every generated delegation forwarder, which
                // reads the delegate field and returns what it answers.
                // Read the argument at the recorded SUFFIX; its bare key is
                // empty when the object carries its taint in a field.
                for ((param, suffixes) in summary.paramFieldToReturn) {
                    val from = binding(param) ?: continue
                    for (suffix in suffixes.sorted()) {
                        val facts = readReportingPath(state, aliasClass(from), suffix)
                        if (facts.isEmpty()) continue
                        val fromKey = TaintKey(from, suffix)
                        state.addFacts(resultKey, facts)
                        moved = true
                        val via = summary.paramFieldToReturnPaths["$param\u0000$suffix"].orEmpty()
                        for (fact in facts) {
                            chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "summary", origin, via)
                        }
                    }
                }
                // sourceReturns: taint born at a source INSIDE the callee
                // comes back through the return; the caller's birth site is
                // this call, and the callee's path is prepended at slice
                // build so the trace still starts at the real source.
                for ((category, path) in summary.sourceReturns) {
                    val fact = TaintFact(site, category)
                    context.recordSourceReturn(fact, path)
                    state.addFacts(resultKey, listOf(fact))
                    moved = true
                    chain[ChainKey(fact, resultKey)] = Move(site, null, "source-return", origin)
                }
                // P26 §0 (R161): the source-return FIELD channel — same
                // birth, but the callee stored it into the returned object's
                // FIELD, so the caller's result carries it at that access
                // path. The field read finds it; the ALIAS class fans it
                // across the caller's names of the object.
                for ((category, suffixes) in summary.sourceReturnFields) {
                    for (suffix in suffixes.sorted()) {
                        val fact = TaintFact(site, category)
                        context.recordSourceReturn(fact, summary.sourceReturnFieldPaths["$category\u0000$suffix"].orEmpty())
                        val key = TaintKey(result, suffix)
                        state.addFacts(key, listOf(fact))
                        moved = true
                        chain[ChainKey(fact, key)] = Move(site, null, "source-return-field", origin)
                    }
                }
                // P24 §2: the field channel — the callee stored param i's
                // VALUE into the returned object's field, so the argument's
                // BASE taint reaches the result's FIELD.
                for ((param, suffixes) in summary.paramToReturnFields) {
                    val from = binding(param) ?: continue
                    for (suffix in suffixes.sorted()) {
                        val via = summary.paramToReturnFieldPaths["$param\u0000$suffix"].orEmpty()
                        val facts = state.factsOf(TaintKey(from, ""))
                        if (facts.isEmpty()) continue
                        state.addFacts(TaintKey(result, suffix), facts)
                        moved = true
                        for (fact in facts) {
                            chain[ChainKey(fact, TaintKey(result, suffix))] = Move(site, TaintKey(from, ""), "summary", origin, via)
                        }
                    }
                }
            }

            // P24 §2c: source-born FIELD WRITES — the caller's argument
            // carries the write after the call, on every name of the object.
            for ((category, writes) in summary.sourceFieldWrites) {
                for (write in writes.sortedWith(compareBy({ it.paramIndex }, { it.suffix }))) {
                    val toReg = binding(write.paramIndex) ?: continue
                    for (base in aliasClass(toReg).sorted()) {
                        val fact = TaintFact(site, category)
                        context.recordSourceReturn(fact, write.path)
                        val key = TaintKey(base, write.suffix)
                        state.addFacts(key, listOf(fact))
                        moved = true
                        chain[ChainKey(fact, key)] = Move(site, null, "source-field-write", origin)
                    }
                }
            }

            // paramToParam: write effects — argument i's taint lands on
            // argument j's register after the call.
            for ((from, tos) in summary.paramToParam) {
                val fromReg = binding(from) ?: continue
                for (to in tos.sorted()) {
                    val toReg = binding(to) ?: continue
                    moved = moveChain(state, TaintKey(fromReg, ""), TaintKey(toReg, ""), site, "summary", origin) || moved
                }
            }

            // Field write effects: parameter i's taint stored into
            // parameter j's object (the receiver case included), field-
            // sensitive through the recorded access-path suffixes.
            // P24 §2: the write lands on every name of the object the
            // caller named — the alias class of the bound argument.
            for ((from, tos) in summary.paramFieldWrites) {
                val fromReg = binding(from) ?: continue
                // P27 §1 (R171): the argument's own tainted SUB-PATHS travel
                // with it. `W(R(raw))` stores the argument into `inner`, and
                // the argument is an object whose taint sits at `.raw` — so
                // the receiver carries it at `inner.raw`. Reading only the
                // argument's bare key lost every wrapper-of-a-wrapper, which
                // is the shape a decorator chain is made of.
                val fromBases = aliasClass(fromReg)
                val carriedPaths = state.map.keys
                    .filter { it.base in fromBases && it.path.isNotEmpty() }
                    .map { it.path }
                    .distinct()
                    .sorted()
                for ((to, suffixes) in tos) {
                    val toReg = binding(to) ?: continue
                    for (suffix in suffixes.sorted()) {
                        for (base in aliasClass(toReg).sorted()) {
                            moved = moveChain(state, TaintKey(fromReg, ""), TaintKey(base, suffix), site, "summary", origin) || moved
                            for (carried in carriedPaths) {
                                for (fromBase in fromBases.sorted()) {
                                moved = moveChain(
                                    state,
                                    TaintKey(fromBase, carried),
                                    TaintKey(base, capPath("$suffix.$carried")),
                                    site,
                                    "summary",
                                    origin,
                                ) || moved
                                }
                            }
                        }
                    }
                }
            }

            // paramToSink: interprocedural sink hits — the facts live on the
            // caller's argument NOW, the sink site is inside the callee.
            // FIELD-SENSITIVE at the boundary: the effect carries the access
            // path from the callee's parameter to the sunk value, so the
            // caller's taint must sit on the SAME path of its argument —
            // taint on `job.command` cannot reach a callee that sinks
            // `job.label`.
            for (effect in summary.sinkEffects.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }))) {
                val fromReg = binding(effect.paramIndex) ?: continue
                val argKey = TaintKey(fromReg, effect.paramPath)
                // P27 §1: alias-aware, and aware of FIELD-BEARING facts — a
                // DTO straight out of a deserializer carries its taint on
                // the bare key with no per-field key, so the keyed probe
                // alone lost every `@RequestBody` that reached a sink
                // through a mapper.
                val facts = readReportingPath(state, aliasClass(fromReg), effect.paramPath)
                if (facts.isEmpty()) continue
                moved = true
                collect?.interHits?.add(InterSinkHit(site, argKey, java.util.TreeSet(facts), effect, origin))
            }

            // Function-valued parameters the callee invokes: apply the
            // PASSED lambda's summary with the captures bound from the
            // caller's registers (the lambda body is just another function
            // whose capture parameters carry the closure's taint).
            for (param in summary.invokedParams.sorted()) {
                val argReg = binding(param) ?: continue
                // The syntactic def map first (a lambda written at the call),
                // then P24's alias analysis, which knows the function values
                // an object's field or a collection element may hold — the
                // spellings §0's sweep found dead: a function stored in a
                // field, put in a list, or assigned through another object.
                // Several candidates are a MAY set and each is applied, the
                // same treatment a virtual call's targets get.
                val syntactic = context.lambdaDefs[functionKey(compiled.function)]?.get(argReg)
                val candidates = if (syntactic != null) listOf(syntactic) else lambdaTargets(argReg)
                if (candidates.isEmpty()) {
                    // No extracted body and no tracked function value: no
                    // summary — counted, never silent.
                    collect?.let { context.recordLambdaUnresolved() }
                    continue
                }
                for (lambdaCanonical in candidates) {
                // Lambdas carry no descriptor; the lowering's module-wide
                // ordinal makes the name unique, so the name-only key is
                // the function's (P22 §1). A function value that names a
                // DECLARED function — every `::reference` and anonymous
                // `fun` since P25 §0 — has a descriptor and is found
                // through the canonical index instead.
                val declaredTarget = context.functionValues[lambdaCanonical]
                val lambdaSummary = context.table[functionKeyByName(lambdaCanonical)]
                    ?: declaredTarget?.let { context.table[it.summaryKey] }
                    ?: run {
                        collect?.let { context.recordLambdaUnresolved() }
                        continue
                    }
                // A declared target's own parameters play the part the
                // lambda's captures play: a bound reference has its receiver
                // already bound, so the invocation's argument 0 addresses
                // the callee's parameter 1.
                val lambdaCaptured = if (declaredTarget != null && context.table[functionKeyByName(lambdaCanonical)] == null) {
                    List(declaredTarget.receiverOffset) { "" }
                } else {
                    context.captures[functionKey(compiled.function)]?.get(lambdaCanonical).orEmpty()
                }
                val lambdaOrigin = lambdaSummary.origin
                for (effect in lambdaSummary.sinkEffects.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }))) {
                    if (effect.paramIndex < lambdaCaptured.size) {
                        // A capture-parameter effect: the closure's own taint.
                        val captureReg = lambdaCaptured[effect.paramIndex]
                        val captureKey = TaintKey(captureReg, effect.paramPath)
                        val facts = state.factsOf(captureKey)
                        if (facts.isEmpty()) continue
                        moved = true
                        collect?.interHits?.add(InterSinkHit(site, captureKey, java.util.TreeSet(facts), effect, lambdaOrigin))
                    }
                    // P24 §2d: a VALUE-parameter effect — the argument the
                    // CALLEE passed at the invocation, recorded as a bind.
                    // The lambda's value parameters follow its captures, so
                    // the bind's argIndex addresses the effect's paramIndex
                    // minus the capture count.
                    val bindArgIndex = effect.paramIndex - lambdaCaptured.size
                    if (bindArgIndex < 0) continue
                    val bind = summary.invokedBinds.firstOrNull {
                        it.invokedParam == param && it.argIndex == bindArgIndex
                    } ?: continue
                    // The value physically transited the callee (to the
                    // invoke site) and then the lambda body: the stitched
                    // walk is the bind's path through the callee followed by
                    // the lambda's effect path, so the frames name BOTH the
                    // invoking function and the body.
                    val stitched = effect.copy(
                        path = bind.path + effect.path,
                        elided = effect.elided,
                    )
                    when {
                        // The callee passed MY argument's taint into the
                        // lambda: the caller's facts at the bound register.
                        bind.fromParam != null -> {
                            val sourceReg = binding(bind.fromParam) ?: continue
                            val sourceKey = TaintKey(sourceReg, bind.fromParamPath)
                            val facts = state.factsOf(sourceKey)
                            if (facts.isEmpty()) continue
                            moved = true
                            collect?.interHits?.add(InterSinkHit(site, sourceKey, java.util.TreeSet(facts), stitched, lambdaOrigin))
                        }

                        // The callee passed a source born INSIDE it: birth
                        // the fact here and stitch the callee's walk.
                        bind.category != null -> {
                            val fact = TaintFact(site, bind.category)
                            context.recordSourceReturn(fact, bind.path)
                            moved = true
                            collect?.interHits?.add(
                                InterSinkHit(site, TaintKey(argReg, ""), java.util.TreeSet(setOf(fact)), stitched, lambdaOrigin),
                            )
                        }
                    }
                }
                }
            }
            return moved
        }
    }

    /** The analysed function's own `this` register (its param store), when it has one. */
    private fun callerThisRegister(compiled: CompiledFunction): String? {
        val receiverParam = compiled.function.params.firstOrNull { it.receiver } ?: return null
        for (block in compiled.blocks) {
            for (ins in block.instructions) {
                if (ins is KirStore && ins.value == receiverParam.register) return ins.target
            }
        }
        return receiverParam.register
    }

    // ---- slices, traces, evidence ------------------------------------------

    private class SliceCandidate(
        val crossesModuleFlag: Boolean,
        val crossesDependencyFlag: Boolean,
        val flowKey: String,
        val sourceSite: Int,
        val sinkSite: Int,
        val sourceCategory: String,
        val sinkCategory: String,
        val severity: String,
        val sourceName: String,
        val sinkName: String,
        val sourceFunction: String,
        val sinkFunction: String,
        val sourceModulePath: String,
        val sinkModulePath: String,
        val sourcePurl: String,
        val sinkPurl: String,
        val argIndex: Int,
        val accessPath: String,
        val origins: List<String>,
        val suspendCrossing: Boolean,
        val modulePath: String,
        val purl: String,
        val nodes: List<NodeInfo>,
        val elided: Boolean,
        /** P20 §1: the endpoint value-parameter the flow entered through, when it did. */
        val sourceParameter: String? = null,
        val sourceTransport: String? = null,
        /** P24 §3: the named hops, source to sink. */
        val frames: List<FlowFrame> = emptyList(),
        /** P24 §3: the cap that cut the frame list, when it did. */
        val framesCutBy: String? = null,
    )

    private class NodeInfo(val sortKey: String, val builder: (String) -> FlowNode)

    /**
     * Interleaves SUSPEND BOUNDARIES into an assembled trace: a suspend
     * point records no data move of its own, so it never lands on the
     * provenance walk — but "the source and sink are separated by a suspend
     * boundary" is exactly the P6 report, and a boundary nobody can see is
     * a boundary nobody counted. Between two consecutive trace sites of the
     * SAME function, any suspend point at an intervening site id belongs on
     * the trace (site ids are contiguous within a function and ascending in
     * program order).
     */
    private fun withSuspendBoundaries(
        traceSites: List<Int>,
        siteIndex: Map<Int, Pair<CompiledFunction, Site>>,
    ): List<Int> {
        if (traceSites.size < 2) return traceSites
        val out = mutableListOf(traceSites.first())
        for (i in 1 until traceSites.size) {
            val a = traceSites[i - 1]
            val b = traceSites[i]
            val fa = siteIndex[a]?.first
            val fb = siteIndex[b]?.first
            if (fa != null && fb != null && fa === fb) {
                val lo = minOf(a, b)
                val hi = maxOf(a, b)
                for (id in (lo + 1) until hi) {
                    val ref = siteIndex[id]
                    if (ref != null && ref.first === fa && ref.second.ins is KirSuspendPoint) out.add(id)
                }
            }
            out.add(b)
        }
        return out
    }

    /** One validated source birth feeding an interprocedural hit. */
    private class SourceRef(
        val fact: TaintFact,
        val ref: Pair<CompiledFunction, Site>,
        val pattern: String,
        val upstream: List<Int>,
    )

    /**
     * P24 §3: the frame list of one trace — every hop named with its
     * function, file, line and role. Roles resolve in a fixed order
     * (source/sink first, then dispatch evidence, then summary boundaries,
     * returns, surviving sanitizers, calls, and moves), so a hop has
     * exactly one role however many things happened at it.
     */
    private fun buildFrames(
        traceSites: List<Int>,
        sourceNodeSite: Int,
        sinkSite: Int,
        moves: List<Move>,
        context: EngineContext,
        attribution: Attribution,
        elided: Boolean,
    ): Pair<List<FlowFrame>, String?> {
        val moveBySite = HashMap<Int, Move>()
        for (move in moves) moveBySite[move.site] = move
        val siteIndex = context.siteIndex
        val frames = mutableListOf<FlowFrame>()
        for (siteId in traceSites) {
            val ref = siteIndex[siteId] ?: continue
            val fn = ref.first.function
            val (filePath, _) = attribution.byAbsoluteFilePath[fn.file] ?: (fn.file to "")
            val site = ref.second
            val dispatch = context.dispatchBySite[siteId]
            val role = when {
                siteId == sourceNodeSite -> FrameRole.SOURCE
                siteId == sinkSite -> FrameRole.SINK
                dispatch != null && dispatch.considered > 1 -> FrameRole.DISPATCH
                moveBySite[siteId]?.origin != null -> FrameRole.SUMMARY
                site.ins is KirReturn -> FrameRole.RETURN
                siteId in context.sanitizerSurvivedBySite -> FrameRole.SANITIZER_NOT_APPLIED
                site.ins is KirCall || site.ins is KirDynamicCall -> FrameRole.CALL
                else -> FrameRole.MOVE
            }
            val line = when (val ins = site.ins) {
                is KirCall -> if (ins.line > 0) ins.line else fn.line
                is KirDynamicCall -> if (ins.line > 0) ins.line else fn.line
                is KirNew -> if (ins.line > 0) ins.line else fn.line
                else -> fn.line
            }
            frames.add(
                FlowFrame(
                    function = fn.canonicalName,
                    file = filePath,
                    line = line,
                    role = role,
                    dispatchWidth = dispatch?.considered,
                    dispatchTargets = dispatch?.applied.orEmpty(),
                    dispatchNarrowedBy = dispatch?.narrowedBy,
                ),
            )
        }
        // A cut walk names the cap that cut it (the PARTIAL contract, frame
        // form); a complete walk names nothing.
        val cutBy = if (elided) "trace-nodes" else null
        return frames to cutBy
    }

    /**
     * P20 §1: the parameter identity of an ENDPOINT-PARAMETER birth — the
     * `#N` index over the handler's VALUE parameters and the transport the
     * parameter's annotation names. Null for every other birth.
     */
    private fun entryParameterInfo(context: EngineContext, compiled: CompiledFunction, fact: TaintFact): Pair<String, String?>? {
        if (fact.site != SummaryAnalysis.ENTRY_SITE || fact.param < 0) return null
        val valueParams = compiled.function.params.filter { !it.receiver }
        val param = valueParams.getOrNull(fact.param) ?: return null
        val annotations = context.options.endpointParameterAnnotations
        val transport = param.annotations.firstNotNullOfOrNull { annotation ->
            annotations.entries.firstOrNull { (pattern, _) -> PatternMatcher.matches(pattern, annotation) }?.value?.kind
        }
        return "#${fact.param}" to transport
    }

    private fun buildSlice(
        compiled: CompiledFunction,
        context: EngineContext,
        chain: HashMap<ChainKey<TaintFact>, Move>,
        hit: SinkHit,
        fact: TaintFact,
        attribution: Attribution,
    ): SliceCandidate? {
        val options = context.options
        val pack = context.pack
        val siteIndex = context.siteIndex
        // A fact born at the synthetic entry site is an ENDPOINT-PARAMETER
        // source (P7): the analysed function is the handler and its entry
        // site is the trace head. A fact born at a STORE is a literal source
        // (the pack's name rule): the store is the birth. Everything else is
        // a pack source call, validated against the pack as always.
        val entryFact = fact.site == SummaryAnalysis.ENTRY_SITE
        val sourceRef = siteIndex[fact.site]
        val sourceSite = sourceRef?.second
        val sourceIns = sourceSite?.ins as? KirCall
        val sinkRef = siteIndex[hit.sinkSite] ?: return null
        val sinkIns = sinkRef.second.ins as? KirCall ?: return null
        val sourcePattern = sourceIns?.let { ins ->
            pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, ins.callee.fqn) }
        }
        val literalBirth = !entryFact && sourceSite?.ins is KirStore
        // P9: a source-return birth from the --deps tier was born at a call
        // that RETURNED jar-sourced taint — the real source call sits at the
        // head of the recorded upstream path (inside the jar), so the birth
        // site itself need not match the pack. The head is validated below
        // before the slice is allowed to stand.
        val upstreamSites = context.sourceReturnPaths[fact].orEmpty()
        val upstreamBirth = upstreamSites.isNotEmpty() && sourcePattern == null
        if (upstreamBirth) {
            val head = siteIndex[upstreamSites.first()] ?: return null
            val headIns = head.second.ins as? KirCall ?: return null
            val headSource = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, headIns.callee.fqn) }
            if (headSource == null || headSource.category != fact.category) return null
        }
        if (!entryFact && !literalBirth && sourcePattern == null && !upstreamBirth) return null
        if (sourceIns != null && sourcePattern != null && fact.category != sourcePattern.category) return null
        if (!entryFact && !literalBirth && sourceRef == null) return null
        // P26 §1.1: a hit whose callee has no pack row may be an
        // interface-declared sink (the host's interfaceSink arm produced it).
        val sinkPattern = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, sinkIns.callee.fqn) }
            ?: InterfaceSinks.sinkPatternFor(context.callIndex, pack, sinkIns)
            ?: return null

        // The upstream path of a source-return birth: taint that came back
        // from a callee's internal source starts its trace THERE, not at the
        // call that returned it.

        // Walk the provenance chain from the sink back to the source. The
        // chain is the fixpoint's last-move graph: guarded against cycles and
        // capped at the trace limit, with any elision dropping the MIDDLE of
        // the walk (never the endpoints — the source site is always
        // prepended and the sink always appended) behind an explicit elided
        // edge, so the emitted trace stays a connected path.
        val visited = HashSet<ChainKey<TaintFact>>()
        val moves = mutableListOf<Move>()
        var elided = false
        var reachedBirth = false
        var current = hit.key
        while (true) {
            if (!visited.add(ChainKey(fact, current))) {
                elided = true
                break
            }
            val move = chain[ChainKey(fact, current)] ?: break
            moves.add(move)
            if (move.prevKey == null) {
                // The birth move: this fact was created here, at the source.
                reachedBirth = true
                break
            }
            if (moves.size > options.maxTraceNodes) {
                elided = true
                break
            }
            current = move.prevKey
        }
        // Backwards moves -> forward trace. The endpoints are GUARANTEED,
        // not hoped for: the sink instruction is appended last, and when the
        // walk did not reach the birth move — a cap, a cycle, or a transfer
        // that moved a fact without recording provenance — the source site
        // is prepended and the slice is marked elided, so a truncated trace
        // is visible as a truncated trace instead of one that quietly starts
        // in the middle (R54). P24 §3: a boundary move's viaSites splice the
        // callee-internal hops in, so the walk names where the VALUE went.
        val walked = moves.reversed()
            .flatMap { it.viaSites + listOf(it.site) }
            .filter { it != SummaryAnalysis.ENTRY_SITE }
        val handlerEntrySite = compiled.blocks.firstOrNull()
            ?.let { compiled.sitesByBlock[it.id]?.firstOrNull()?.id }
        val traceSites = when {
            upstreamSites.isNotEmpty() -> upstreamSites + walked + listOf(hit.sinkSite)
            entryFact -> {
                // The handler's signature is the flow's origin: its entry
                // site opens the trace; the seed move carries no instruction.
                if (handlerEntrySite != null) {
                    listOf(handlerEntrySite) + walked + listOf(hit.sinkSite)
                } else {
                    elided = true
                    walked + listOf(hit.sinkSite)
                }
            }

            reachedBirth || walked.firstOrNull() == fact.site -> walked + hit.sinkSite
            else -> {
                elided = true
                listOfNotNull(fact.site.takeIf { it != SummaryAnalysis.ENTRY_SITE }) + walked + listOf(hit.sinkSite)
            }
        }
        // The trace's SOURCE node is the pack-source call — inside a callee
        // for a source-return birth, the call site itself otherwise. An
        // endpoint-rooted flow starts at the handler's entry site; a literal
        // source at its store.
        val sourceNodeSite = upstreamSites.firstOrNull()
            ?: (if (entryFact) handlerEntrySite else null)
            ?: fact.site.takeIf { siteIndex.containsKey(it) }
            ?: walked.firstOrNull()
            ?: hit.sinkSite
        val origins = moves.mapNotNull { it.origin }.distinct().sorted()
        val tracedWithSuspend = withSuspendBoundaries(traceSites, siteIndex)
        val suspendCrossing = tracedWithSuspend.any { siteIndex[it]?.second?.ins is KirSuspendPoint }
        val traceNodesInput = tracedWithSuspend

        val sourceFunction = sourceRef?.first?.function ?: compiled.function
        val (sourceFilePath, sourceModulePath) = attribution.byAbsoluteFilePath[sourceFunction.file] ?: (sourceFunction.file to "")
        val sourcePurl = attribution.purlByModulePath[sourceModulePath].takeUnless { it.isNullOrEmpty() } ?: sourceFunction.purl
        val sinkFunction = sinkRef.first.function
        val (sinkFilePath, sinkModulePath) = attribution.byAbsoluteFilePath[sinkFunction.file] ?: (sinkFunction.file to "")
        val sinkPurl = attribution.purlByModulePath[sinkModulePath].takeUnless { it.isNullOrEmpty() } ?: sinkFunction.purl

        data class TraceNode(val kind: String, val name: String, val line: Int, val site: Int, val filePath: String, val modulePath: String, val purl: String, val functionLine: Int)

        val traceNodes = traceNodesInput.map { siteId ->
            val ref = siteIndex.getValue(siteId)
            val fn = ref.first.function
            val (filePath, modulePath) = attribution.byAbsoluteFilePath[fn.file] ?: (fn.file to "")
            val purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: fn.purl
            val site = ref.second
            TraceNode(
                when (val ins = site.ins) {
                    is KirCall -> when {
                        siteId == sourceNodeSite -> "source"
                        siteId == hit.sinkSite -> "sink"
                        else -> "call"
                    }

                    is KirStore -> if (siteId == sourceNodeSite) "source" else "assign"
                    is KirSuspendPoint -> "suspend"
                    is KirDynamicCall -> "propagate"
                    is KirStringConcat -> "concat"
                    is KirFieldGet -> "field"
                    is KirFieldSet -> "field"
                    is KirIndexGet -> "index"
                    is KirIndexSet -> "index"
                    is KirStore -> "assign"
                    is KirAssign -> "assign"
                    is KirPhi -> "phi"
                    is KirElvis -> "elvis"
                    is KirNew -> "new"
                    else -> "assign"
                },
                when (val ins = site.ins) {
                    is KirCall -> ins.callee.fqn
                    is KirDynamicCall -> ins.name
                    is KirNew -> ins.type
                    is KirStore -> "store " + ins.target
                    is KirAssign -> "assign " + ins.result
                    is KirPhi -> "phi " + ins.result
                    is KirElvis -> "elvis " + ins.result
                    else -> "data"
                },
                when (val ins = site.ins) {
                    is KirCall -> if (ins.line > 0) ins.line else fn.line
                    is KirDynamicCall -> if (ins.line > 0) ins.line else fn.line
                    is KirNew -> if (ins.line > 0) ins.line else fn.line
                    else -> fn.line
                },
                siteId,
                filePath,
                modulePath,
                purl,
                fn.line,
            )
        }

        // The source display name: the handler's parameter list for
        // endpoint-rooted flows, the material's local name for literal
        // births, and the callee fqn for pack-source calls.
        val sourceDisplayName = when {
            entryFact -> "endpoint-params " + compiled.function.canonicalName
            literalBirth -> (sourceSite?.ins as? KirStore)?.let { "literal " + it.target.removePrefix("v") }
                ?: "literal"
            else -> sourceIns?.callee?.fqn ?: sourcePattern?.pattern ?: "source"
        }
        val entryParam = entryParameterInfo(context, compiled, fact)

        val frames = buildFrames(traceNodesInput, sourceNodeSite, hit.sinkSite, moves, context, attribution, elided)
        val flowKey = sha256(
            listOf(
                sourceIns?.callee?.fqn ?: sourceDisplayName,
                fact.category,
                sinkIns.callee.fqn,
                sinkPattern.category,
                hit.argIndex.toString(),
                hit.key.render(),
                traceSites.joinToString(","),
                entryParam?.first ?: "",
            ).joinToString("|"),
        )

        // crossModule compares the two ENDS' module paths. crossesDependency
        // is NOT its twin (the P5/P6 caveat resolved in P9): it is set when
        // the TRACE enters a real external jar — a dependency purl the --deps
        // tier was lowered from — and stays false for a slice that only
        // crosses workspace modules, whose Gradle purls differ per module.
        val crossesModule = sourceModulePath.isNotEmpty() && sinkModulePath.isNotEmpty() && sourceModulePath != sinkModulePath
        val depPurls = context.deps?.purls ?: emptySet()
        val crossesDependency = depPurls.isNotEmpty() && traceNodes.any { it.purl in depPurls }

        return SliceCandidate(
            flowKey = flowKey,
            sourceSite = fact.site,
            sinkSite = hit.sinkSite,
            sourceCategory = fact.category,
            sinkCategory = sinkPattern.category,
            severity = sinkPattern.severity,
            sourceName = sourceDisplayName,
            sinkName = sinkIns.callee.fqn,
            sourceFunction = sourceFunction.canonicalName,
            sinkFunction = sinkFunction.canonicalName,
            sourceModulePath = sourceModulePath,
            sinkModulePath = sinkModulePath,
            sourcePurl = sourcePurl,
            sinkPurl = sinkPurl,
            argIndex = hit.argIndex,
            accessPath = hit.key.render(),
            origins = origins,
            suspendCrossing = suspendCrossing,
            modulePath = sinkModulePath,
            purl = sinkPurl,
            elided = elided,
            nodes = traceNodes.map { node ->
                NodeInfo(sortKey = "${node.filePath}|${node.line}|${node.kind}|${node.name}|${node.site}") { id ->
                    FlowNode(
                        id = id,
                        name = node.name,
                        kind = node.kind,
                        modulePath = node.modulePath,
                        purl = node.purl,
                        filePath = node.filePath,
                        position = Position(node.filePath, node.line, node.functionLine),
                    )
                }
            },
            // crossModule flags ride along for materialise.
            crossesModuleFlag = crossesModule,
            crossesDependencyFlag = crossesDependency,
            sourceParameter = entryParam?.first,
            sourceTransport = entryParam?.second,
            frames = frames.first,
            framesCutBy = frames.second,
        )
    }

    /**
     * An interprocedural slice: the caller's chain from its source to the
     * call site, then the callee's recorded path from the boundary to the
     * sink inside it. The endpoint guarantee travels: if either segment was
     * cut, the source site is prepended and the slice is marked elided.
     */
    private fun buildInterproceduralSlice(
        compiled: CompiledFunction,
        context: EngineContext,
        chain: HashMap<ChainKey<TaintFact>, Move>,
        hit: InterSinkHit,
        attribution: Attribution,
    ): SliceCandidate? {
        val pack = context.pack
        val siteIndex = context.siteIndex
        val effect = hit.effect
        val sinkRef = siteIndex[effect.sinkSite] ?: return null
        val sinkIns = sinkRef.second.ins as? KirCall ?: return null
        // P26 §1.1: a hit whose callee has no pack row may be an
        // interface-declared sink (the host's interfaceSink arm produced it).
        val sinkPattern = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, sinkIns.callee.fqn) }
            ?: InterfaceSinks.sinkPatternFor(context.callIndex, pack, sinkIns)
            ?: return null
        // The fact must have been born at a REAL source — a pack source call,
        // a call whose callee RETURNED source taint (the source-return birth:
        // the real source lives at the head of the recorded upstream path,
        // often in another module), an endpoint parameter (P7), or a literal
        // store the pack's name rule claimed (P8).
        val sourceRefs = hit.facts.mapNotNull { fact ->
            val entryFact = fact.site == SummaryAnalysis.ENTRY_SITE &&
                context.options.endpointSources.containsKey(compiled.function.canonicalName)
            val ref = siteIndex[fact.site]
            val literalBirth = ref?.second?.ins is KirStore
            if (entryFact || literalBirth) {
                return@mapNotNull SourceRef(fact, ref ?: Pair(compiled, compiled.sitesByBlock.values.first().first()), "", emptyList())
            }
            ref?.let { r ->
                val ins = r.second.ins as? KirCall ?: return@mapNotNull null
                val direct = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, ins.callee.fqn) }
                val upstream = context.sourceReturnPaths[fact]
                when {
                    direct != null && direct.category == fact.category ->
                        SourceRef(fact, r, direct.pattern, upstream.orEmpty())

                    upstream != null && upstream.isNotEmpty() -> {
                        // Validate the upstream head against the pack: a
                        // source-return birth is only as good as the real
                        // source call its path starts at.
                        val head = siteIndex[upstream.first()] ?: return@mapNotNull null
                        val headIns = head.second.ins as? KirCall ?: return@mapNotNull null
                        val headSource = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, headIns.callee.fqn) }
                        if (headSource != null && headSource.category == fact.category) {
                            SourceRef(fact, r, headSource.pattern, upstream)
                        } else {
                            null
                        }
                    }

                    else -> null
                }
            }
        }
        if (sourceRefs.isEmpty()) return null

        // The effect's own elision travels with the slice: the composed path
        // was capped INSIDE the summary (stabilize keeps the sink end), so
        // the published trace's middle is cut even when this caller-side
        // walk is complete. Before P22 this flag was read nowhere — the
        // second half of the composed-path defect (the first half was
        // toSummary publishing path-stripped keys), and the reason an
        // over-cap composed trace could never publish PARTIAL.
        var elided = hit.effect.elided
        val traceSegments = mutableListOf<List<Int>>()
        val origins = sortedSetOf(hit.origin)
        var sourceNodeSite = -1
        val allMovesCollected = mutableListOf<Move>()
        for (sourceRef in sourceRefs.sortedBy { it.fact.site }) {
            val fact = sourceRef.fact
            // Walk the caller's chain from the argument register back to the birth.
            val visited = HashSet<ChainKey<TaintFact>>()
            val moves = mutableListOf<Move>()
            var current = hit.argKey
            var reachedBirth = false
            while (true) {
                if (!visited.add(ChainKey(fact, current))) {
                    elided = true
                    break
                }
                val move = chain[ChainKey(fact, current)] ?: break
                moves.add(move)
                if (move.prevKey == null) {
                    reachedBirth = true
                    break
                }
                if (moves.size > context.options.maxTraceNodes) {
                    elided = true
                    break
                }
                current = move.prevKey
            }
            origins.addAll(moves.mapNotNull { it.origin })
            allMovesCollected.addAll(moves)
            val entryFact = fact.site == SummaryAnalysis.ENTRY_SITE
            // P24 §3: callee-internal hops splice in at every boundary move.
            val walked = moves.reversed()
                .flatMap { it.viaSites + listOf(it.site) }
                .filter { it != SummaryAnalysis.ENTRY_SITE }
            if (sourceRef.upstream.isNotEmpty()) {
                // The real source call sits in the callee that RETURNED the
                // taint: its path opens the trace.
                traceSegments.add(sourceRef.upstream)
                sourceNodeSite = sourceRef.upstream.first()
            }
            if (entryFact) {
                // An endpoint-rooted interprocedural flow opens at the
                // handler's entry site; the seed move carries no instruction.
                compiled.sitesByBlock[compiled.blocks.first().id]?.firstOrNull()?.let { first ->
                    traceSegments.add(listOf(first.id))
                    if (sourceNodeSite == -1) sourceNodeSite = first.id
                }
            } else if (reachedBirth && walked.firstOrNull() == fact.site) {
                traceSegments.add(walked)
                if (sourceNodeSite == -1) sourceNodeSite = fact.site
            } else {
                elided = true
                traceSegments.add(walked)
            }
            traceSegments.add(listOf(hit.callSite))
            traceSegments.add(effect.path + listOf(effect.sinkSite))
        }
        if (sourceNodeSite == -1) {
            sourceNodeSite = sourceRefs.minByOrNull { it.fact.site }!!.fact.site
                .takeIf { it != SummaryAnalysis.ENTRY_SITE && siteIndex.containsKey(it) }
                ?: hit.callSite
        }
        val allMoves = allMovesCollected
        val traceSites = traceSegments.flatten().filter { it != SummaryAnalysis.ENTRY_SITE }.distinct()
        // The SOURCE END's facts (file, module, purl) come from the function
        // holding the SOURCE NODE — for a source-return birth that is the
        // callee that read the source, not the caller that consumed it. The
        // cross-module flags are computed from these ends, so reading them
        // from the birth site would report the crossing the trace actually
        // makes as none.
        val sourceRefForEnds = siteIndex[sourceNodeSite] ?: Pair(compiled, compiled.sitesByBlock.values.first().first())
        val suspendCrossing = traceSites.any { siteIndex[it]?.second?.ins is KirSuspendPoint }

        val sourceFunction = sourceRefForEnds.first.function
        val sinkFunction = sinkRef.first.function
        val (sourceFilePath, sourceModulePath) = attribution.byAbsoluteFilePath[sourceFunction.file] ?: (sourceFunction.file to "")
        val sourcePurl = attribution.purlByModulePath[sourceModulePath].takeUnless { it.isNullOrEmpty() } ?: sourceFunction.purl
        val (sinkFilePath, sinkModulePath) = attribution.byAbsoluteFilePath[sinkFunction.file] ?: (sinkFunction.file to "")
        val sinkPurl = attribution.purlByModulePath[sinkModulePath].takeUnless { it.isNullOrEmpty() } ?: sinkFunction.purl

        val firstRef = sourceRefs.minByOrNull { it.fact.site }!!
        val sourcePattern = SourcePattern(firstRef.pattern, firstRef.fact.category)
        val fact = firstRef.fact
        val entryParam = entryParameterInfo(context, compiled, fact)
        val frames = buildFrames(traceSites, sourceNodeSite, effect.sinkSite, allMovesCollected, context, attribution, elided)

        data class TraceNode(val kind: String, val name: String, val line: Int, val site: Int, val filePath: String, val modulePath: String, val purl: String, val functionLine: Int)

        val traceNodes = traceSites.map { siteId ->
            val ref = siteIndex.getValue(siteId)
            val fn = ref.first.function
            val (filePath, modulePath) = attribution.byAbsoluteFilePath[fn.file] ?: (fn.file to "")
            val purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: fn.purl
            val site = ref.second
            TraceNode(
                when (val ins = site.ins) {
                    is KirCall -> when {
                        siteId == sourceNodeSite -> "source"
                        siteId == effect.sinkSite -> "sink"
                        else -> "call"
                    }

                    is KirStore -> if (siteId == sourceNodeSite) "source" else "assign"
                    is KirSuspendPoint -> "suspend"
                    is KirDynamicCall -> "propagate"
                    is KirStringConcat -> "concat"
                    is KirFieldGet -> "field"
                    is KirFieldSet -> "field"
                    is KirIndexGet -> "index"
                    is KirIndexSet -> "index"
                    is KirStore -> "assign"
                    is KirAssign -> "assign"
                    is KirPhi -> "phi"
                    is KirElvis -> "elvis"
                    is KirNew -> "new"
                    else -> "assign"
                },
                when (val ins = site.ins) {
                    is KirCall -> ins.callee.fqn
                    is KirDynamicCall -> ins.name
                    is KirNew -> ins.type
                    is KirStore -> "store " + ins.target
                    is KirAssign -> "assign " + ins.result
                    is KirPhi -> "phi " + ins.result
                    is KirElvis -> "elvis " + ins.result
                    else -> "data"
                },
                when (val ins = site.ins) {
                    is KirCall -> if (ins.line > 0) ins.line else fn.line
                    is KirDynamicCall -> if (ins.line > 0) ins.line else fn.line
                    is KirNew -> if (ins.line > 0) ins.line else fn.line
                    else -> fn.line
                },
                siteId,
                filePath,
                modulePath,
                purl,
                fn.line,
            )
        }

        val flowKey = sha256(
            listOf(
                sourcePattern.pattern,
                fact.category,
                sinkIns.callee.fqn,
                sinkPattern.category,
                effect.sinkArgumentIndex.toString(),
                effect.sinkAccessPath,
                traceSites.joinToString(","),
                entryParam?.first ?: "",
            ).joinToString("|"),
        )

        // Same provenance rule as the intraprocedural slice (P9): the flags
        // are computed from what the trace actually touches — crossModule
        // from the two ends' module paths, crossesDependency from the trace
        // entering a jar the --deps tier was lowered from.
        val crossesModule = sourceModulePath.isNotEmpty() && sinkModulePath.isNotEmpty() && sourceModulePath != sinkModulePath
        val depPurls = context.deps?.purls ?: emptySet()
        val crossesDependency = depPurls.isNotEmpty() && traceNodes.any { it.purl in depPurls }

        return SliceCandidate(
            flowKey = flowKey,
            sourceSite = fact.site,
            sinkSite = effect.sinkSite,
            sourceCategory = fact.category,
            sinkCategory = sinkPattern.category,
            severity = sinkPattern.severity,
            sourceName = (siteIndex[sourceNodeSite]?.second?.ins as? KirCall)?.callee?.fqn
                ?: sourcePattern.pattern.ifEmpty {
                    if (fact.site == SummaryAnalysis.ENTRY_SITE) {
                        "endpoint-params " + compiled.function.canonicalName
                    } else {
                        "literal"
                    }
                },
            sinkName = sinkIns.callee.fqn,
            sourceFunction = sourceFunction.canonicalName,
            sinkFunction = sinkFunction.canonicalName,
            sourceModulePath = sourceModulePath,
            sinkModulePath = sinkModulePath,
            sourcePurl = sourcePurl,
            sinkPurl = sinkPurl,
            argIndex = effect.sinkArgumentIndex,
            accessPath = effect.sinkAccessPath,
            origins = origins.sorted(),
            suspendCrossing = suspendCrossing,
            modulePath = sinkModulePath,
            purl = sinkPurl,
            elided = elided,
            nodes = traceNodes.map { node ->
                NodeInfo(sortKey = "${node.filePath}|${node.line}|${node.kind}|${node.name}|${node.site}") { id ->
                    FlowNode(
                        id = id,
                        name = node.name,
                        kind = node.kind,
                        modulePath = node.modulePath,
                        purl = node.purl,
                        filePath = node.filePath,
                        position = Position(node.filePath, node.line, node.functionLine),
                    )
                }
            },
            crossesModuleFlag = crossesModule,
            crossesDependencyFlag = crossesDependency,
            sourceParameter = entryParam?.first,
            sourceTransport = entryParam?.second,
            frames = frames.first,
            framesCutBy = frames.second,
        )
    }

    private fun materialise(
        candidates: List<SliceCandidate>,
        nodeInfos: java.util.TreeSet<NodeInfo>,
        pack: ModelPack,
        options: Options,
        summaries: List<io.cdxgen.kosi.schema.FlowSummary>,
        context: EngineContext,
        bytecodeSummaryCount: Int,
    ): DataFlowEvidence {
        // Deterministic ids: nodes sorted by (file, line, kind, name, site),
        // edges deduplicated by (from, to, kind), slices ordered by source
        // then sink site.
        val nodeIdBySortKey = HashMap<String, String>()
        val nodes = mutableListOf<FlowNode>()
        for ((index, info) in nodeInfos.withIndex()) {
            val id = "dfn-" + (index + 1).toString().padStart(6, '0')
            nodeIdBySortKey[info.sortKey] = id
            nodes.add(info.builder(id))
        }

        data class EdgeKey(val from: String, val to: String, val kind: String)

        val edgeKeyToId = LinkedHashMap<EdgeKey, String>()
        val edges = mutableListOf<FlowEdge>()
        for (candidate in candidates.sortedWith(
            compareBy({ it.sourceSite }, { it.sinkSite }, { it.sourceCategory }, { it.sinkCategory }, { it.flowKey }),
        )) {
            val nodeIds = candidate.nodes.map { nodeIdBySortKey.getValue(it.sortKey) }
            for (i in 0 until nodeIds.size - 1) {
                // The elided edge is the FIRST one: elision cut the middle of
                // the walk between the source and the kept suffix.
                val kind = if (candidate.elided && i == 0) "elided" else "data"
                val key = EdgeKey(nodeIds[i], nodeIds[i + 1], kind)
                if (key !in edgeKeyToId) {
                    val id = "dfe-" + (edgeKeyToId.size + 1).toString().padStart(6, '0')
                    edgeKeyToId[key] = id
                    edges.add(FlowEdge(id, key.from, key.to, key.kind))
                }
            }
        }

        val edgesById = edges.associateBy { it.id }
        // P22 §2: every published slice names what its trace IS — complete,
        // partial (elided), or symbol-only — computed by the same rule the
        // depth report's reachability table reads (the two must not drift).
        val kindById = nodes.associate { it.id to it.kind }
        val slicesOut = candidates.sortedWith(
            compareBy({ it.sourceSite }, { it.sinkSite }, { it.sourceCategory }, { it.sinkCategory }, { it.flowKey }),
        ).mapIndexed { index, candidate ->
            val nodeIds = candidate.nodes.map { nodeIdBySortKey.getValue(it.sortKey) }
            val pathKind = when {
                candidate.elided -> PathKind.PARTIAL
                nodeIds.size >= 2 &&
                    kindById[nodeIds.first()] == "source" &&
                    kindById[nodeIds.last()] == "sink" -> PathKind.COMPLETE

                else -> PathKind.SYMBOL_ONLY
            }
            val edgeIds = (0 until nodeIds.size - 1).map { i ->
                val kind = if (candidate.elided && i == 0) "elided" else "data"
                edgeKeyToId.getValue(EdgeKey(nodeIds[i], nodeIds[i + 1], kind))
            }
            val crossingOrigins = candidate.origins.filter { it != SummaryOrigin.PACK }
            FlowSlice(
                id = "slice-" + (index + 1).toString().padStart(6, '0'),
                sourceId = nodeIds.first(),
                sinkId = nodeIds.last(),
                sourceName = candidate.sourceName,
                sinkName = candidate.sinkName,
                sourceFunction = candidate.sourceFunction,
                sinkFunction = candidate.sinkFunction,
                sourceModulePath = candidate.sourceModulePath,
                sinkModulePath = candidate.sinkModulePath,
                sourcePurl = candidate.sourcePurl,
                targetPurl = candidate.sinkPurl,
                purls = listOfNotNull(candidate.sourcePurl.takeIf { it.isNotEmpty() }, candidate.sinkPurl.takeIf { it.isNotEmpty() }).distinct(),
                sourceCategory = candidate.sourceCategory,
                sinkCategory = candidate.sinkCategory,
                taintKinds = listOf(candidate.sourceCategory),
                nodeIds = nodeIds,
                edgeIds = edgeIds,
                pathLength = edgeIds.size,
                elided = if (candidate.elided) true else null,
                sanitizerNodeIds = emptyList(),
                sinkArgumentIndex = candidate.argIndex,
                accessPath = candidate.accessPath,
                // Computed from the two ENDS (module paths and purls of the
                // source and sink functions) — real comparisons now that a
                // slice can span a call boundary, not the structural false
                // the intraprocedural engine had to publish (R55).
                crossesModule = candidate.crossesModuleFlag,
                crossesDependency = candidate.crossesDependencyFlag,
                pathKind = pathKind,
                frames = candidate.frames,
                framesCutBy = candidate.framesCutBy,
                ruleId = "taint/${candidate.sourceCategory}-to-${candidate.sinkCategory}",
                ruleName = "${candidate.sourceCategory} to ${candidate.sinkCategory}",
                description = "Value from ${candidate.sourceCategory} (${candidate.sourceName}) reaches " +
                    "${candidate.sinkCategory} sink ${candidate.sinkName} (argument ${candidate.argIndex}) in " +
                    candidate.sinkFunction,
                severity = candidate.severity,
                confidence = "high",
                riskScore = riskScoreOf(candidate.severity),
                flowKey = candidate.flowKey,
                origins = candidate.origins,
                sourceParameter = candidate.sourceParameter,
                sourceTransport = candidate.sourceTransport,
            )
        }

        val nodesById = nodes.associateBy { it.id }
        val integrity = slicesOut.count { slice -> !invariantsHold(slice, edgesById, nodesById) }
        val connectivity = if (slicesOut.isEmpty()) {
            1.0
        } else {
            slicesOut.count { slice -> isConnected(slice, edgesById) }.toDouble() / slicesOut.size
        }
        // A slice "crosses a summary boundary" when its trace carries a
        // boundary origin: `computed`, `default` or `recursive-approx`. The
        // `pack` origin on a source birth is PROVENANCE (where the taint
        // came from), not a boundary — counting it would make every
        // pack-sourced slice a crossing and dilute the default-origin
        // denominator into meaninglessness.
        val crossing = { origins: List<String> -> origins.filter { it != SummaryOrigin.PACK } }
        val summaryCrossing = slicesOut.count { crossing(it.origins).isNotEmpty() }
        val defaultOnly = slicesOut.count { slice ->
            val boundary = crossing(slice.origins)
            boundary.isNotEmpty() && boundary.all { it == SummaryOrigin.DEFAULT }
        }
        return DataFlowEvidence(
            mode = options.mode,
            patterns = ModelPackRef(
                builtin = listOf(pack.name),
                user = emptyList(),
                sourceCount = pack.sources.size,
                sinkCount = pack.sinks.size,
                passthroughCount = pack.passthroughs.size,
                sanitizerCount = pack.sanitizers.size,
                effectCount = pack.effects.size,
            ),
            nodes = nodes,
            edges = edges,
            slices = slicesOut,
            summaries = summaries,
            stats = DataFlowStats(
                sliceCount = slicesOut.size,
                uniqueFlows = slicesOut.map { it.flowKey }.toSortedSet().size,
                crossDependencySlices = slicesOut.count { it.crossesDependency },
                crossModuleSlices = slicesOut.count { it.crossesModule },
                // ALWAYS 0 here, in every mode, and the mode is deliberately
                // not consulted: this engine has no call graph, so it cannot
                // know whether any slice is root-reachable. The intersection
                // lives in the Analyzer, which overwrites this field with the
                // kept count when it runs. P22 §2's first version keyed the
                // count off `mode == "reachable"` and published
                // `slicesOut.size` — but the mode says only what was ASKED
                // for, and `--dataflow reachable --callgraph none` asks
                // without a graph: the intersection never ran and the stat
                // claimed every slice reachable. On taint-sanitizer that read
                // 2 where the real intersection keeps 0 (the P22 review's
                // R137) — R117's rule, broken inside the change that was
                // applying it: a field that never varies is a schema lie, and
                // one that varies WRONGLY is a worse one.
                reachableSlices = 0,
                connectivity = connectivity,
                integrityViolations = integrity,
                summariesComputed = summaries.count { it.origin == SummaryOrigin.COMPUTED || it.origin == SummaryOrigin.RECURSIVE_APPROX },
                summariesByOrigin = summaries.groupingBy { it.origin }.eachCount(),
                defaultOriginSlices = defaultOnly,
                summaryCrossingSlices = summaryCrossing,
                suspendCrossingSlices = slicesOut.count { slice ->
                    slice.nodeIds.any { nodesById[it]?.kind == "suspend" }
                },
                dispatchJoins = context.joinWidths.mapValues { it.value }.mapKeys { it.key.toString() },
                maxObservedDepth = slicesOut.maxOfOrNull { it.frames.size } ?: 0,
                depthHistogram = slicesOut.groupingBy { it.frames.size.toString() }.eachCount(),
                dispatchWidthHistogram = context.dispatchWidths.mapValues { it.value }.mapKeys { it.key.toString() },
                bytecodeSummaries = bytecodeSummaryCount,
                crossDependencyBytecodeSlices = slicesOut.count {
                    it.crossesDependency && SummaryOrigin.BYTECODE in it.origins
                },
            ),
            diagnostics = emptyList(),
        )
    }

    private fun isConnected(slice: FlowSlice, edgesById: Map<String, FlowEdge>): Boolean {
        val nodeIds = slice.nodeIds.toSet()
        if (slice.sourceId !in nodeIds || slice.sinkId !in nodeIds) return false
        if (slice.edgeIds.isEmpty()) return slice.sourceId == slice.sinkId
        var current = slice.sourceId
        for (edgeId in slice.edgeIds) {
            val edge = edgesById[edgeId] ?: return false
            if (edge.sourceId != current) return false
            current = edge.targetId
        }
        return current == slice.sinkId
    }

    /**
     * The integrity check, and the one with teeth. [isConnected] walks the
     * emitted edge list, which `materialise` builds from consecutive trace
     * nodes — so it is 1.000 by construction and can only catch a defect in
     * the id assignment itself. The ENDPOINT check is independent of it: the
     * node the slice calls its source must actually be a source node and the
     * node it calls its sink an actual sink node. That is the property R54
     * broke — 3 of 11 fixture slices carried a trace beginning at a field
     * write while reporting connectivity 1.000 and 0 integrity violations —
     * and it is the property that fails if a trace loses an endpoint again.
     * P5 extends it across the call boundary: a cross-function slice's
     * endpoints live in DIFFERENT functions, and the walk must still reach
     * both — a stitched trace that lost its bridge fails here.
     */
    private fun invariantsHold(
        slice: FlowSlice,
        edgesById: Map<String, FlowEdge>,
        nodesById: Map<String, FlowNode>,
    ): Boolean =
        isConnected(slice, edgesById) &&
            nodesById[slice.sourceId]?.kind == "source" &&
            nodesById[slice.sinkId]?.kind == "sink" &&
            // A cross-function slice must actually NAME two functions.
            (!crossFunction(slice) || (slice.sourceFunction.isNotBlank() && slice.sinkFunction.isNotBlank() &&
                slice.sourceFunction != slice.sinkFunction || slice.crossesModule || slice.crossesDependency)) &&
            slice.ruleId.isNotBlank() && slice.severity.isNotBlank() &&
            slice.confidence.isNotBlank() && slice.riskScore.isNotBlank() && slice.flowKey.isNotBlank()

    private fun crossFunction(slice: FlowSlice): Boolean = slice.sourceFunction != slice.sinkFunction

    private fun riskScoreOf(severity: String): String = when (severity) {
        "critical" -> "9.0"
        "high" -> "7.0"
        "medium" -> "5.0"
        "low" -> "3.0"
        else -> "5.0"
    }

    private fun sha256(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
