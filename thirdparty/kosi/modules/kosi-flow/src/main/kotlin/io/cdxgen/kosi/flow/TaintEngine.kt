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
import io.cdxgen.kosi.kir.KirSafeCall
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
import io.cdxgen.kosi.schema.FlowNode
import io.cdxgen.kosi.schema.FlowSlice
import io.cdxgen.kosi.schema.ModelPackRef
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


/** A taint fact: born at the source call [site], carrying [category]. */
internal data class TaintFact(val site: Int, val category: String) : Comparable<TaintFact> {
    override fun compareTo(other: TaintFact): Int = compareValuesBy(this, other, { it.site }, { it.category })
}

/** Reporting facts carry paths on STATE KEYS, so a field read derives nothing. */
private object TaintFactOps : FactOps<TaintFact> {
    override fun categoryOf(fact: TaintFact): String = fact.category
    override fun deriveOnFieldRead(fact: TaintFact, suffix: String): TaintFact? = null
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
         * P7 endpoint-rooted taint, when the run asks for it: handler
         * canonical name -> the category its parameters carry. Seeds live
         * at the synthetic entry site (-1) so endpoint-rooted slices walk
         * from the handler's own signature.
         */
        val endpointSources: Map<String, String> = emptyMap(),
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
    )

    // ---- the per-run context --------------------------------------------------

    /**
     * What every per-function analysis needs beyond its own CFG: the
     * module-wide site table (site ids are GLOBAL, so one trace can span
     * functions), the resolved callee sets, and the converged summaries.
     */
    internal class EngineContext(
        val pack: ModelPack,
        val siteIndex: Map<Int, Pair<CompiledFunction, Site>>,
        val callIndex: CallIndex,
        val table: Map<String, FunctionSummary>,
        val lambdaDefs: Map<String, Map<String, String>>,
        val captures: Map<String, Map<String, List<String>>>,
        val options: Options,
    ) {
        var joinOverruns: Int = 0
        var lambdaUnresolved: Int = 0
        val joinWidths: java.util.TreeMap<Int, Int> = java.util.TreeMap()
        /** Callee FQNs where a pack entry actually moved taint (pack-origin summaries). */
        val packAppliedSources = sortedSetOf<String>()
        val packAppliedPassthroughs = sortedSetOf<String>()
        /** source-return births: the caller fact -> the callee's internal source path. */
        val sourceReturnPaths = HashMap<TaintFact, List<Int>>()
    }

    fun analyze(module: KirModule, pack: ModelPack, attribution: Attribution, options: Options): Result {
        val diagnostics = mutableListOf<Diagnostic>()
        val truncations = java.util.TreeMap<String, Int>()
        val candidates = mutableListOf<SliceCandidate>()
        val nodeInfos = java.util.TreeSet<NodeInfo>(compareBy { it.sortKey })
        var functionsAnalysed = 0
        var fixpointCapHits = 0
        var sourceSites = 0
        var sinkSites = 0
        var unknownCallPropagations = 0
        var sliceCapReported = false

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
        val callIndex = CallIndex(compiled, options.dispatchMode)
        val summarizer = Summarizer(compiled, callIndex, pack, options)
        val summaryResult = summarizer.compute()
        for ((kind, count) in summaryResult.skipped) {
            truncations.merge(kind, count, Int::plus)
        }

        val lambdaDefs = compiled.associate { it.function.canonicalName to lambdaDefsOf(it) }
        val captures = compiled.associate { cf ->
            cf.function.canonicalName to buildMap {
                for (block in cf.blocks) {
                    for (ins in block.instructions) {
                        if (ins is KirLambda) put(ins.function, ins.captures)
                    }
                }
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
        )

        // ---- the per-function main analysis ----------------------------------
        for (cf in compiled) {
            val function = cf.function
            if (options.skipGenerated && function.syntheticCause != null) {
                truncations.merge("generated-functions", 1, Int::plus)
                continue
            }
            val instructionCount = cf.sitesByBlock.values.sumOf { it.size }
            if (instructionCount > options.maxFunctionInstructions) {
                truncations.merge("function-instructions", 1, Int::plus)
                continue
            }
            functionsAnalysed++
            val outcome = analyseFunction(cf, context)
            if (outcome.capHit) fixpointCapHits++
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
                    }
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
                }
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

        val allSummaries = buildList {
            addAll(summaryResult.table.values.map { it.toSchema() })
            addAll(packOriginSummaries(context))
        }.sortedBy { it.functionId }

        return Result(
            evidence = materialise(candidates, nodeInfos, pack, options, allSummaries, context),
            functionsAnalysed = functionsAnalysed,
            fixpointCapHits = fixpointCapHits,
            sourceSites = sourceSites,
            sinkSites = sinkSites,
            unknownCallPropagations = unknownCallPropagations,
            truncations = truncations,
            diagnostics = diagnostics.sortedWith(Diagnostic.COMPARATOR),
            summaries = allSummaries,
            sccsProcessed = summaryResult.sccsProcessed,
            sccIterationCapHits = summaryResult.sccIterationCapHits,
            dispatchJoins = context.joinWidths.mapValues { it.value },
            suspendCrossingSlices = candidates.count { it.suspendCrossing },
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

        override fun birthFact(site: Int, category: String): TaintFact = TaintFact(site, category)

        override fun packMoveOrigin(): String? = SummaryOrigin.PACK

        override fun onSourceApplied(fqn: String, site: Int, fact: TaintFact, resultKey: TaintKey, collect: TransferEvents?) {
            if (collect != null) {
                collect.sourceSites += 1
                context.packAppliedSources.add(fqn)
            }
        }

        override fun onSanitizerCleared(cleared: List<String>, collect: TransferEvents?) {}

        override fun onPackPassthroughApplied(fqn: String, collect: TransferEvents?) {
            if (collect != null) context.packAppliedPassthroughs.add(fqn)
        }

        override fun onSinkMatched(collect: TransferEvents?) {
            collect?.let { it.sinkSites += 1 }
        }

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

        override fun entryBindings(): List<Pair<String, TaintFact>> {
            val category = context.options.endpointSources[compiled.function.canonicalName] ?: return emptyList()
            return compiled.function.params.filter { !it.receiver }
                .map { it.register to TaintFact(SummaryAnalysis.ENTRY_SITE, category) }
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
         */
        override fun applyCalleeSummaries(
            ins: KirCall,
            site: Int,
            state: FlowState<TaintFact>,
            chain: HashMap<ChainKey<TaintFact>, Move>,
            collect: TransferEvents?,
        ): Boolean {
            val options = context.options
            var targets = context.callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)
            if (targets.size > 1 && (options.dispatchMode == "vta" || options.dispatchMode == "auto")) {
                // VTA narrows by the receiver's known construction types before
                // the summary JOIN — the same positive-evidence-only refinement
                // the P3 graph applies.
                targets = context.callIndex.narrowByReceiverType(compiled.function.canonicalName, ins.receiver, targets)
            }
            val applicable = targets.mapNotNull { target -> context.table[target.canonicalName]?.let { target to it } }
            if (applicable.isEmpty()) return false

            val width = applicable.size
            context.joinWidths.merge(width, 1, Int::plus)
            if (width > options.dispatchJoinBudget) context.joinOverruns += 1

            // Summary parameter index -> the caller's register. A receiver-less
            // call to a member function binds its implicit this to the CALLER's
            // own receiver so member-to-member effects compose.
            val callerThis = callerThisRegister(compiled)
            fun mapParam(summary: FunctionSummary, index: Int): String? {
                val receiverIndex = summary.function.params.indexOfFirst { it.receiver }
                return if (receiverIndex >= 0 && index == 0) {
                    ins.receiver ?: callerThis
                } else if (receiverIndex >= 0) {
                    ins.args.getOrNull(index - 1)
                } else {
                    ins.args.getOrNull(index)
                }
            }

            for ((target, summary) in applicable.sortedBy { it.first.canonicalName }) {
                val origin = summary.origin

                // paramToReturn: the caller's facts move onto the result — fact
                // identity preserved, so the caller's trace keeps walking.
                val result = ins.result
                if (result != null) {
                    val resultKey = TaintKey(result, "")
                    for (param in summary.paramToReturn.sorted()) {
                        val from = mapParam(summary, param) ?: continue
                        val fromKey = TaintKey(from, "")
                        val facts = state.factsOf(fromKey)
                        if (facts.isEmpty()) continue
                        state.addFacts(resultKey, facts)
                        for (fact in facts) {
                            chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "summary", origin)
                        }
                    }
                    // sourceReturns: taint born at a source INSIDE the callee
                    // comes back through the return; the caller's birth site is
                    // this call, and the callee's path is prepended at slice
                    // build so the trace still starts at the real source.
                    for ((category, path) in summary.sourceReturns) {
                        val fact = TaintFact(site, category)
                        context.sourceReturnPaths[fact] = path
                        state.addFacts(resultKey, listOf(fact))
                        chain[ChainKey(fact, resultKey)] = Move(site, null, "source-return", origin)
                    }
                }

                // paramToParam: write effects — argument i's taint lands on
                // argument j's register after the call.
                for ((from, tos) in summary.paramToParam) {
                    val fromReg = mapParam(summary, from) ?: continue
                    for (to in tos.sorted()) {
                        val toReg = mapParam(summary, to) ?: continue
                        moveChain(state, TaintKey(fromReg, ""), TaintKey(toReg, ""), site, "summary", origin)
                    }
                }

                // Field write effects: parameter i's taint stored into
                // parameter j's object (the receiver case included), field-
                // sensitive through the recorded access-path suffixes.
                for ((from, tos) in summary.paramFieldWrites) {
                    val fromReg = mapParam(summary, from) ?: continue
                    for ((to, suffixes) in tos) {
                        val toReg = mapParam(summary, to) ?: continue
                        for (suffix in suffixes.sorted()) {
                            moveChain(state, TaintKey(fromReg, ""), TaintKey(toReg, suffix), site, "summary", origin)
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
                    val fromReg = mapParam(summary, effect.paramIndex) ?: continue
                    val argKey = TaintKey(fromReg, effect.paramPath)
                    val facts = state.factsOf(argKey)
                    if (facts.isEmpty()) continue
                    collect?.interHits?.add(InterSinkHit(site, argKey, java.util.TreeSet(facts), effect, origin))
                }

                // Function-valued parameters the callee invokes: apply the
                // PASSED lambda's summary with the captures bound from the
                // caller's registers (the lambda body is just another function
                // whose capture parameters carry the closure's taint).
                for (param in summary.invokedParams.sorted()) {
                    val argReg = mapParam(summary, param) ?: continue
                    val lambdaCanonical = context.lambdaDefs[compiled.function.canonicalName]?.get(argReg)
                    if (lambdaCanonical == null) {
                        // A callable reference or local function: no extracted
                        // body, so no summary — counted, never silent.
                        collect?.let { context.lambdaUnresolved += 1 }
                        continue
                    }
                    val lambdaSummary = context.table[lambdaCanonical] ?: continue
                    val lambdaCaptured = context.captures[compiled.function.canonicalName]?.get(lambdaCanonical).orEmpty()
                    val lambdaOrigin = lambdaSummary.origin
                    for (effect in lambdaSummary.sinkEffects.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }))) {
                        if (effect.paramIndex >= lambdaCaptured.size) continue // a value-parameter effect cannot be bound here
                        val captureReg = lambdaCaptured[effect.paramIndex]
                        val captureKey = TaintKey(captureReg, effect.paramPath)
                        val facts = state.factsOf(captureKey)
                        if (facts.isEmpty()) continue
                        collect?.interHits?.add(InterSinkHit(site, captureKey, java.util.TreeSet(facts), effect, lambdaOrigin))
                    }
                }
            }
            return true
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
        if (!entryFact && sourcePattern == null) return null
        if (sourceIns != null && sourcePattern != null && fact.category != sourcePattern.category) return null
        val literalBirth = !entryFact && sourceSite?.ins is KirStore
        if (!entryFact && !literalBirth && sourceRef == null) return null
        val sinkPattern = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, sinkIns.callee.fqn) } ?: return null

        // The upstream path of a source-return birth: taint that came back
        // from a callee's internal source starts its trace THERE, not at the
        // call that returned it.
        val upstreamSites = context.sourceReturnPaths[fact].orEmpty()

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
        // in the middle (R54).
        val walked = moves.map { it.site }.reversed().filter { it != SummaryAnalysis.ENTRY_SITE }
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

        val flowKey = sha256(
            listOf(
                sourceIns?.callee?.fqn ?: sourceDisplayName,
                fact.category,
                sinkIns.callee.fqn,
                sinkPattern.category,
                hit.argIndex.toString(),
                hit.key.render(),
                traceSites.joinToString(","),
            ).joinToString("|"),
        )

        val crossesModule = sourceModulePath.isNotEmpty() && sinkModulePath.isNotEmpty() && sourceModulePath != sinkModulePath
        val crossesDependency = sourcePurl.isNotEmpty() && sinkPurl.isNotEmpty() && sourcePurl != sinkPurl

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
        val sinkPattern = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, sinkIns.callee.fqn) } ?: return null
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

        var elided = false
        val traceSegments = mutableListOf<List<Int>>()
        val origins = sortedSetOf(hit.origin)
        var sourceNodeSite = -1
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
            val entryFact = fact.site == SummaryAnalysis.ENTRY_SITE
            val walked = moves.map { it.site }.reversed().filter { it != SummaryAnalysis.ENTRY_SITE }
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
            ).joinToString("|"),
        )

        val crossesModule = sourceModulePath.isNotEmpty() && sinkModulePath.isNotEmpty() && sourceModulePath != sinkModulePath
        val crossesDependency = sourcePurl.isNotEmpty() && sinkPurl.isNotEmpty() && sourcePurl != sinkPurl

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
        )
    }

    private fun materialise(
        candidates: List<SliceCandidate>,
        nodeInfos: java.util.TreeSet<NodeInfo>,
        pack: ModelPack,
        options: Options,
        summaries: List<io.cdxgen.kosi.schema.FlowSummary>,
        context: EngineContext,
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
        val slicesOut = candidates.sortedWith(
            compareBy({ it.sourceSite }, { it.sinkSite }, { it.sourceCategory }, { it.sinkCategory }, { it.flowKey }),
        ).mapIndexed { index, candidate ->
            val nodeIds = candidate.nodes.map { nodeIdBySortKey.getValue(it.sortKey) }
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
                reachableFromRoots = false,
                rootWitness = null,
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
                reachableSlices = slicesOut.count { it.reachableFromRoots },
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
