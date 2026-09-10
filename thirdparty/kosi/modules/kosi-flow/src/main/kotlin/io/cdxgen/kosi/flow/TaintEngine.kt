package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
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

/**
 * The P4 taint engine (02-ARCHITECTURE.md §6, intraprocedural half): forward,
 * field-sensitive taint over each function's CFG, iterated with a worklist to
 * a real fixpoint — never a fixed pass count. Everything that decides what is
 * a source, a sink, a passthrough, a sanitizer or an effect comes from the
 * [ModelPack]; the engine hard-codes no rule about categories.
 *
 * Precision contract: taint is tracked on ACCESS PATHS `(base, field*)`, so
 * writing `obj.query` never taints `obj.column` — the corpus's clean-sibling
 * negative pins this, and `Options.accessPathDepth = 0` collapses every path
 * to its base register, which is the field-INsensitive engine that negative
 * must be able to switch on.
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
    )

    // ---- lattice ------------------------------------------------------------

    /** A taint fact: born at the source call [site], carrying [category]. */
    private data class TaintFact(val site: Int, val category: String) : Comparable<TaintFact> {
        override fun compareTo(other: TaintFact): Int = compareValuesBy(this, other, { it.site }, { it.category })
    }

    /** One slot of the function's abstract memory: a register plus its path suffix. */
    private data class TaintKey(val base: String, val path: String) : Comparable<TaintKey> {
        override fun compareTo(other: TaintKey): Int = compareValuesBy(this, other, { it.base }, { it.path })

        fun render(): String = if (path.isEmpty()) base else "$base::$path"
    }

    /** How a fact last moved into a key: at [site], from [prevKey], via [kind]. */
    private data class Move(val site: Int, val prevKey: TaintKey?, val kind: String)

    private data class ChainKey(val fact: TaintFact, val key: TaintKey)

    private class State {
        val map = java.util.TreeMap<TaintKey, java.util.TreeSet<TaintFact>>()

        fun factsOf(key: TaintKey): java.util.TreeSet<TaintFact> = map[key] ?: EMPTY

        fun setFacts(key: TaintKey, facts: java.util.TreeSet<TaintFact>) {
            if (facts.isEmpty()) map.remove(key) else map[key] = facts
        }

        fun addFacts(key: TaintKey, facts: Collection<TaintFact>) {
            if (facts.isEmpty()) return
            val existing = map[key]
            if (existing == null) map[key] = java.util.TreeSet(facts) else existing.addAll(facts)
        }

        fun removeKey(key: TaintKey) {
            map.remove(key)
        }

        fun copy(): State {
            val out = State()
            for ((k, v) in map) out.map[k] = java.util.TreeSet(v)
            return out
        }

        /** In-place union, used for joins over predecessors. */
        fun mergeFrom(other: State) {
            for ((key, facts) in other.map) addFacts(key, facts)
        }

        fun join(other: State): State {
            val out = copy()
            for ((key, facts) in other.map) {
                val existing = out.map[key]
                if (existing == null) out.map[key] = java.util.TreeSet(facts) else existing.addAll(facts)
            }
            return out
        }

        override fun equals(other: Any?): Boolean = other is State && map == other.map

        override fun hashCode(): Int = map.hashCode()

        companion object {
            private val EMPTY = java.util.TreeSet<TaintFact>()
        }
    }

    // ---- per-function compilation ---------------------------------------------

    /** One executable program point: instruction [ins] of block [blockId], flat id [id]. */
    private data class Site(val id: Int, val blockId: String, val indexInBlock: Int, val ins: KirIns)

    private class CompiledFunction(
        val function: KirFunction,
        val blocks: List<KirBlock>,
        val sitesByBlock: Map<String, List<Site>>,
        val siteById: Map<Int, Site>,
        val successors: Map<String, List<String>>,
        val predecessors: Map<String, List<String>>,
    )

    private fun compile(function: KirFunction): CompiledFunction? {
        val body = function.body ?: return null
        if (body.blocks.isEmpty()) return null
        var nextSite = 0
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

    // ---- analysis ------------------------------------------------------------

    private data class SinkHit(val sinkSite: Int, val argIndex: Int, val key: TaintKey, val facts: Set<TaintFact>)

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

        val functions = module.functions
            .filter { it.body != null }
            .sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }))

        for (function in functions) {
            if (options.skipGenerated && function.syntheticCause != null) {
                truncations.merge("generated-functions", 1, Int::plus)
                continue
            }
            val compiled = compile(function) ?: continue
            val instructionCount = compiled.sitesByBlock.values.sumOf { it.size }
            if (instructionCount > options.maxFunctionInstructions) {
                truncations.merge("function-instructions", 1, Int::plus)
                continue
            }
            functionsAnalysed++
            val outcome = analyseFunction(compiled, pack, options)
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
                    buildSlice(function, compiled, pack, outcome.chain, hit, fact, attribution, options)?.let { candidate ->
                        candidates.add(candidate)
                        nodeInfos.addAll(candidate.nodes)
                    }
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

        return Result(
            evidence = materialise(candidates, nodeInfos, pack, options),
            functionsAnalysed = functionsAnalysed,
            fixpointCapHits = fixpointCapHits,
            sourceSites = sourceSites,
            sinkSites = sinkSites,
            unknownCallPropagations = unknownCallPropagations,
            truncations = truncations,
            diagnostics = diagnostics,
        )
    }

    // ---- the per-function worklist ---------------------------------------------

    private class FunctionOutcome(
        val capHit: Boolean,
        val sourceSites: Int,
        val sinkSites: Int,
        val unknownCallPropagations: Int,
        /** Post-fixpoint sink hits, each carrying the exact facts that reached it. */
        val hits: List<SinkHit>,
        /** The fixpoint provenance chains the traces walk. */
        val chain: HashMap<ChainKey, Move>,
    )

    private fun analyseFunction(compiled: CompiledFunction, pack: ModelPack, options: Options): FunctionOutcome {
        val chain = HashMap<ChainKey, Move>()
        val blocks = compiled.blocks

        var capHit = false
        val outStates = HashMap<String, State>()
        val work = ArrayDeque(blocks.map { it.id })
        val queued = work.toHashSet()
        // The budget is generous and deterministic: a monotone framework over
        // finitely many facts converges well inside it on real code. Hitting
        // it is a `fixpoint-cap` diagnostic over the analysed-function count,
        // never a silent truncation.
        val budget = 64 + 16 * blocks.size
        var rounds = 0
        while (work.isNotEmpty()) {
            if (rounds++ > budget) {
                capHit = true
                break
            }
            val blockId = work.removeFirst()
            queued.remove(blockId)
            val input = joinPredecessors(compiled, blockId, outStates)
            val output = transfer(compiled.sitesByBlock.getValue(blockId), input, chain, pack, options, collect = null)
            val previous = outStates[blockId]
            if (previous == null || output != previous) {
                outStates[blockId] = output
                for (succ in compiled.successors[blockId].orEmpty()) {
                    if (queued.add(succ)) work.addLast(succ)
                }
            }
        }

        // Final sweep at fixpoint: one canonical pass in block order records
        // every sink hit with the exact facts live at that instruction, and
        // freezes the provenance chains the traces walk.
        val events = TransferEvents()
        for (block in blocks) {
            val input = joinPredecessors(compiled, block.id, outStates)
            transfer(compiled.sitesByBlock.getValue(block.id), input, chain, pack, options, collect = events)
        }
        return FunctionOutcome(
            capHit = capHit,
            sourceSites = events.sourceSites,
            sinkSites = events.sinkSites,
            unknownCallPropagations = events.unknownPropagations,
            hits = events.sinkHits.sortedWith(compareBy({ it.sinkSite }, { it.argIndex }, { it.key })),
            chain = chain,
        )
    }

    private fun joinPredecessors(
        compiled: CompiledFunction,
        blockId: String,
        outStates: Map<String, State>,
    ): State {
        val joined = State()
        for (pred in compiled.predecessors[blockId].orEmpty()) {
            outStates[pred]?.let { base -> joined.mergeFrom(base) }
        }
        return joined
    }

    private class TransferEvents {
        var sourceSites = 0
        var sinkSites = 0
        var unknownPropagations = 0
        val sinkHits = mutableListOf<SinkHit>()
    }

    /** The worklist's transfer function over one block's sites. */
    private fun transfer(
        sites: List<Site>,
        input: State,
        chain: HashMap<ChainKey, Move>,
        pack: ModelPack,
        options: Options,
        collect: TransferEvents?,
    ): State {
        val state = input.copy()
        val fieldSensitive = options.accessPathDepth > 0

        fun pathSuffix(path: AccessPath?): String =
            if (!fieldSensitive || path == null) {
                ""
            } else {
                path.elements.joinToString(".") { element ->
                    when (element) {
                        is AccessPath.Element.Field -> element.name
                        AccessPath.Element.Index -> "[]"
                        AccessPath.Element.Star -> "*"
                    }
                }
            }

        fun reg(register: String): TaintKey = TaintKey(register, "")

        fun moveAll(from: TaintKey, to: TaintKey, site: Int, kind: String, replace: Boolean) {
            val facts = state.factsOf(from)
            if (facts.isEmpty()) {
                if (replace) state.removeKey(to)
                return
            }
            if (replace) state.setFacts(to, java.util.TreeSet(facts)) else state.addFacts(to, facts)
            for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind)
        }

        /**
         * A join over several operand registers (concat, phi, elvis): the
         * union of their facts, with provenance recorded PER FACT against
         * the operand that actually carried it. Blaming the first non-empty
         * operand for every fact sends the backward walk into a register
         * that never held it, and the walk then dead-ends — the trace ends
         * up starting in the middle of the flow with nothing marking it
         * (R54).
         */
        fun joinInto(result: String, operands: List<String>, site: Int, kind: String) {
            val merged = java.util.TreeSet<TaintFact>()
            val origin = HashMap<TaintFact, TaintKey>()
            for (operand in operands) {
                val operandKey = reg(operand)
                for (fact in state.factsOf(operandKey)) {
                    merged.add(fact)
                    origin.putIfAbsent(fact, operandKey)
                }
            }
            val resultKey = reg(result)
            state.setFacts(resultKey, merged)
            for (fact in merged) chain[ChainKey(fact, resultKey)] = Move(site, origin.getValue(fact), kind)
        }

        for (site in sites) {
            when (val ins = site.ins) {
                is KirAssign -> moveAll(reg(ins.source), reg(ins.result), site.id, "assign", replace = true)

                is KirStore -> moveAll(reg(ins.value), reg(ins.target), site.id, "assign", replace = true)

                is KirLoad -> state.removeKey(reg(ins.result))

                is KirNew -> state.removeKey(reg(ins.result))

                is KirLambda -> state.removeKey(reg(ins.result))

                is KirStringConcat -> joinInto(ins.result, ins.parts, site.id, "concat")

                is KirPhi -> joinInto(ins.result, ins.inputs.values.toList(), site.id, "phi")

                // Elvis merged the facts and recorded NO move, so the
                // backward walk dead-ended at every `x ?: y` on a taint
                // path: the emitted trace then began in the middle of the
                // flow, unmarked, and the integrity check could not see it
                // because it validates the emitted list against itself (R54).
                is KirElvis -> joinInto(ins.result, listOf(ins.value, ins.fallback), site.id, "elvis")

                is KirCast -> moveAll(reg(ins.value), reg(ins.result), site.id, "assign", replace = true)

                is KirTypeCheck -> state.removeKey(reg(ins.result))

                is KirFieldGet -> {
                    val sourceKey = TaintKey(ins.receiver, pathSuffix(ins.path))
                    moveAll(sourceKey, reg(ins.result), site.id, "field", replace = true)
                }

                is KirSafeCall -> {
                    val sourceKey = TaintKey(ins.receiver, pathSuffix(ins.path))
                    moveAll(sourceKey, reg(ins.result), site.id, "field", replace = true)
                }

                is KirFieldSet -> {
                    val targetKey = TaintKey(ins.receiver, pathSuffix(ins.path))
                    moveAll(reg(ins.value), targetKey, site.id, "field", replace = true)
                }

                is KirIndexGet -> {
                    // An element read sees the collection's element state AND
                    // any taint carried by the collection value itself (a
                    // passthrough like listOf taints the result register).
                    val elementKey = TaintKey(ins.receiver, if (fieldSensitive) "[]" else "")
                    val wholeKey = reg(ins.receiver)
                    val merged = java.util.TreeSet<TaintFact>()
                    merged.addAll(state.factsOf(elementKey))
                    merged.addAll(state.factsOf(wholeKey))
                    val resultKey = reg(ins.result)
                    state.setFacts(resultKey, merged)
                    if (merged.isNotEmpty()) {
                        val fromKey = if (state.factsOf(elementKey).isNotEmpty()) elementKey else wholeKey
                        for (fact in merged) chain[ChainKey(fact, resultKey)] = Move(site.id, fromKey, "index")
                    }
                }

                is KirIndexSet ->
                    moveAll(reg(ins.value), TaintKey(ins.receiver, if (fieldSensitive) "[]" else ""), site.id, "index", replace = false)

                is KirSuspendPoint -> {}

                is KirBranch, is KirReturn, is KirThrow -> {}

                is KirCall -> handleCall(ins, site.id, state, chain, pack, options, collect)

                is KirDynamicCall ->
                    handleUnknown(ins.result, ins.receiver, ins.args, site.id, state, chain, options, collect)
            }
        }
        return state
    }

    /**
     * One resolved call, classified by the PACK (data, not code): sink,
     * source, sanitizer, passthrough — and only when nothing matched, the
     * configurable unknown-call default.
     */
    private fun handleCall(
        ins: KirCall,
        site: Int,
        state: State,
        chain: HashMap<ChainKey, Move>,
        pack: ModelPack,
        options: Options,
        collect: TransferEvents?,
    ) {
        val fqn = ins.callee.fqn
        val result = ins.result
        val receiver = ins.receiver

        // The pack's argument-position sequence: the receiver when present,
        // then the arguments (the convention documented on ModelPack).
        fun registerAt(index: Int): String? {
            if (index < 0) return null
            return if (receiver != null) {
                if (index == 0) receiver else ins.args.getOrNull(index - 1)
            } else {
                ins.args.getOrNull(index)
            }
        }

        var matched = false

        // SINK first, on the pre-call state: the sink reads its arguments.
        val sink = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sink != null) {
            matched = true
            collect?.let { it.sinkSites += 1 }
            for (argIndex in sink.relevantArguments.sorted()) {
                val register = registerAt(argIndex) ?: continue
                val argKey = TaintKey(register, "")
                val facts = state.factsOf(argKey)
                if (facts.isNotEmpty()) {
                    collect?.sinkHits?.add(SinkHit(site, argIndex, argKey, java.util.TreeSet(facts)))
                }
            }
        }

        // SOURCE: the result register becomes tainted with this site's fact.
        val source = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (source != null && result != null) {
            matched = true
            collect?.let { it.sourceSites += 1 }
            val fact = TaintFact(site, source.category)
            val resultKey = TaintKey(result, "")
            state.addFacts(resultKey, listOf(fact))
            chain[ChainKey(fact, resultKey)] = Move(site, null, "source")
        }

        // SANITIZER: the named categories are cleared on the RESULT only — a
        // sanitizer must not hide the taint that stays behind in memory.
        val sanitizer = pack.sanitizers.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sanitizer != null && result != null) {
            matched = true
            val resultKey = TaintKey(result, "")
            val remaining = state.factsOf(resultKey).filter { it.category !in sanitizer.clears }
            state.setFacts(resultKey, java.util.TreeSet(remaining))
        }

        // PASSTHROUGH: data-driven flows over the argument-position sequence.
        val passthrough = pack.passthroughs.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (passthrough != null) {
            matched = true
            for (flow in passthrough.flows) {
                if (flow.size < 2) continue
                val from = registerAt(flow[0])
                val to = if (flow[1] == -1) result else registerAt(flow[1])
                if (from == null || to == null) continue
                moveChain(state, chain, TaintKey(from, ""), TaintKey(to, ""), site, "call")
            }
        }

        // EFFECT: a call that WRITES memory — argument taint flows into the
        // receiver's element state (`xs.add(tainted)` taints xs's contents).
        val effect = pack.effects.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (effect != null && receiver != null) {
            matched = true
            val fieldSensitive = options.accessPathDepth > 0
            for (writeIndex in effect.writesToArguments) {
                // Index 0 IS the receiver: a self-write carries nothing new.
                if (writeIndex <= 0) continue
                val register = registerAt(writeIndex) ?: continue
                moveChain(
                    state,
                    chain,
                    TaintKey(register, ""),
                    TaintKey(receiver, if (fieldSensitive) "[]" else ""),
                    site,
                    "effect",
                )
            }
        }

        if (!matched) handleUnknown(result, receiver, ins.args, site, state, chain, options, collect)
    }

    private fun moveChain(
        state: State,
        chain: HashMap<ChainKey, Move>,
        from: TaintKey,
        to: TaintKey,
        site: Int,
        kind: String,
    ) {
        val facts = state.factsOf(from)
        if (facts.isEmpty()) return
        state.addFacts(to, facts)
        for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind)
    }

    private fun handleUnknown(
        result: String?,
        receiver: String?,
        args: List<String>,
        site: Int,
        state: State,
        chain: HashMap<ChainKey, Move>,
        options: Options,
        collect: TransferEvents?,
    ) {
        if (result == null) return
        if (!options.unknownCallPropagate) {
            state.removeKey(TaintKey(result, ""))
            return
        }
        // Sound-leaning default: receiver and argument taint reach the result.
        // Counted per call where taint actually moved, so precision loss is a
        // number, not a shrug.
        val resultKey = TaintKey(result, "")
        val incoming = java.util.TreeSet<TaintFact>()
        var fromKey: TaintKey? = null
        for (sourceReg in listOfNotNull(receiver) + args) {
            val sourceKey = TaintKey(sourceReg, "")
            val facts = state.factsOf(sourceKey)
            if (facts.isNotEmpty()) {
                incoming.addAll(facts)
                if (fromKey == null) fromKey = sourceKey
            }
        }
        if (incoming.isEmpty()) {
            state.removeKey(resultKey)
            return
        }
        collect?.let { it.unknownPropagations += 1 }
        state.addFacts(resultKey, incoming)
        for (fact in incoming) chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "propagate")
    }

    // ---- slices, traces, evidence ------------------------------------------

    private class SliceCandidate(
        val flowKey: String,
        val sourceSite: Int,
        val sinkSite: Int,
        val sourceCategory: String,
        val sinkCategory: String,
        val severity: String,
        val sourceName: String,
        val sinkName: String,
        val argIndex: Int,
        val accessPath: String,
        val function: String,
        val modulePath: String,
        val purl: String,
        val nodes: List<NodeInfo>,
        val elided: Boolean,
    )

    private class NodeInfo(val sortKey: String, val builder: (String) -> FlowNode)

    private fun buildSlice(
        function: KirFunction,
        compiled: CompiledFunction,
        pack: ModelPack,
        chain: HashMap<ChainKey, Move>,
        hit: SinkHit,
        fact: TaintFact,
        attribution: Attribution,
        options: Options,
    ): SliceCandidate? {
        val sourceSite = compiled.siteById[fact.site] ?: return null
        val sourceIns = sourceSite.ins as? KirCall ?: return null
        val sinkIns = compiled.siteById[hit.sinkSite]?.ins as? KirCall ?: return null
        val sourcePattern = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, sourceIns.callee.fqn) } ?: return null
        val sinkPattern = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, sinkIns.callee.fqn) } ?: return null
        if (fact.category != sourcePattern.category) return null

        // Walk the provenance chain from the sink back to the source. The
        // chain is the fixpoint's last-move graph: guarded against cycles and
        // capped at the trace limit, with any elision dropping the MIDDLE of
        // the walk (never the endpoints — the source site is always
        // prepended and the sink always appended) behind an explicit elided
        // edge, so the emitted trace stays a connected path.
        val visited = HashSet<ChainKey>()
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
        val walked = moves.reversed().map { it.site }
        val traceSites = when {
            reachedBirth || walked.firstOrNull() == fact.site -> walked
            else -> {
                elided = true
                listOf(fact.site) + walked
            }
        } + hit.sinkSite

        val (filePath, modulePath) = attribution.byAbsoluteFilePath[function.file] ?: (function.file to "")
        val purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: function.purl

        data class TraceNode(val kind: String, val name: String, val line: Int, val site: Int)

        val traceNodes = traceSites.map { siteId ->
            val site = compiled.siteById.getValue(siteId)
            when (val ins = site.ins) {
                is KirCall -> TraceNode(
                    when {
                        siteId == fact.site -> "source"
                        siteId == hit.sinkSite -> "sink"
                        else -> "call"
                    },
                    ins.callee.fqn,
                    if (ins.line > 0) ins.line else function.line,
                    siteId,
                )

                is KirDynamicCall -> TraceNode("propagate", ins.name, if (ins.line > 0) ins.line else function.line, siteId)
                is KirStringConcat -> TraceNode("concat", "concat", function.line, siteId)
                is KirFieldGet -> TraceNode("field", "field read", function.line, siteId)
                is KirFieldSet -> TraceNode("field", "field write", function.line, siteId)
                is KirIndexGet -> TraceNode("index", "index read", function.line, siteId)
                is KirIndexSet -> TraceNode("index", "index write", function.line, siteId)
                is KirStore -> TraceNode("assign", "store " + ins.target, function.line, siteId)
                is KirAssign -> TraceNode("assign", "assign " + ins.result, function.line, siteId)
                is KirPhi -> TraceNode("phi", "phi " + ins.result, function.line, siteId)
                is KirElvis -> TraceNode("elvis", "elvis " + ins.result, function.line, siteId)
                is KirNew -> TraceNode("new", ins.type, if (ins.line > 0) ins.line else function.line, siteId)
                else -> TraceNode("assign", "data", function.line, siteId)
            }
        }

        return SliceCandidate(
            flowKey = sha256(
                listOf(
                    sourceIns.callee.fqn,
                    fact.category,
                    sinkIns.callee.fqn,
                    sinkPattern.category,
                    hit.argIndex.toString(),
                    hit.key.render(),
                    traceSites.joinToString(","),
                ).joinToString("|"),
            ),
            sourceSite = fact.site,
            sinkSite = hit.sinkSite,
            sourceCategory = fact.category,
            sinkCategory = sinkPattern.category,
            severity = sinkPattern.severity,
            sourceName = sourceIns.callee.fqn,
            sinkName = sinkIns.callee.fqn,
            argIndex = hit.argIndex,
            accessPath = hit.key.render(),
            function = function.canonicalName,
            modulePath = modulePath,
            purl = purl,
            elided = elided,
            nodes = traceNodes.map { node ->
                NodeInfo(sortKey = "$filePath|${node.line}|${node.kind}|${node.name}|${node.site}") { id ->
                    FlowNode(
                        id = id,
                        name = node.name,
                        kind = node.kind,
                        modulePath = modulePath,
                        purl = purl,
                        filePath = filePath,
                        position = Position(filePath, node.line, function.column),
                    )
                }
            },
        )
    }

    private fun materialise(
        candidates: List<SliceCandidate>,
        nodeInfos: java.util.TreeSet<NodeInfo>,
        pack: ModelPack,
        options: Options,
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
            FlowSlice(
                id = "slice-" + (index + 1).toString().padStart(6, '0'),
                sourceId = nodeIds.first(),
                sinkId = nodeIds.last(),
                sourceName = candidate.sourceName,
                sinkName = candidate.sinkName,
                sourceFunction = candidate.function,
                sinkFunction = candidate.function,
                sourceModulePath = candidate.modulePath,
                sinkModulePath = candidate.modulePath,
                sourcePurl = candidate.purl,
                targetPurl = candidate.purl,
                purls = listOfNotNull(candidate.purl.takeIf { it.isNotEmpty() }),
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
                // Both ends of an intraprocedural slice are one function, so
                // these are false for a structural reason, not a measured
                // one. `dependency-crossing-flows` therefore reports
                // NOT_EVALUATED, not PASS: a check that cannot fail must not
                // claim to have checked anything (R55). It becomes a real
                // comparison in P5, when summaries give a slice two ends.
                crossesModule = false,
                crossesDependency = false,
                reachableFromRoots = false,
                rootWitness = null,
                ruleId = "taint/${candidate.sourceCategory}-to-${candidate.sinkCategory}",
                ruleName = "${candidate.sourceCategory} to ${candidate.sinkCategory}",
                description = "Value from ${candidate.sourceCategory} (${candidate.sourceName}) reaches " +
                    "${candidate.sinkCategory} sink ${candidate.sinkName} (argument ${candidate.argIndex}) " +
                    "within ${candidate.function}",
                severity = candidate.severity,
                confidence = "high",
                riskScore = riskScoreOf(candidate.severity),
                flowKey = candidate.flowKey,
            )
        }

        val nodesById = nodes.associateBy { it.id }
        val integrity = slicesOut.count { slice -> !invariantsHold(slice, edgesById, nodesById) }
        val connectivity = if (slicesOut.isEmpty()) {
            1.0
        } else {
            slicesOut.count { slice -> isConnected(slice, edgesById) }.toDouble() / slicesOut.size
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
            summaries = emptyList(),
            stats = DataFlowStats(
                sliceCount = slicesOut.size,
                uniqueFlows = slicesOut.map { it.flowKey }.toSortedSet().size,
                // Counted from the slices, never written as the literal the
                // gate then reads back. `dependency-crossing-flows` FAILs on
                // any nonzero, so a hard-coded 0 here made the check unable
                // to fail for a reason that had nothing to do with the
                // engine being intraprocedural — numerator and denominator
                // from the same place, one module apart (R55).
                crossDependencySlices = slicesOut.count { it.crossesDependency },
                reachableSlices = slicesOut.count { it.reachableFromRoots },
                connectivity = connectivity,
                integrityViolations = integrity,
                summariesComputed = 0,
                summariesByOrigin = emptyMap(),
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
     */
    private fun invariantsHold(
        slice: FlowSlice,
        edgesById: Map<String, FlowEdge>,
        nodesById: Map<String, FlowNode>,
    ): Boolean =
        isConnected(slice, edgesById) &&
            nodesById[slice.sourceId]?.kind == "source" &&
            nodesById[slice.sinkId]?.kind == "sink" &&
            slice.ruleId.isNotBlank() && slice.severity.isNotBlank() &&
            slice.confidence.isNotBlank() && slice.riskScore.isNotBlank() && slice.flowKey.isNotBlank()

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
