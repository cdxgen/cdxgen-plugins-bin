package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBranch
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.defs
import io.cdxgen.kosi.kir.KirCast
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirElvis
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirLoad
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
import io.cdxgen.kosi.models.SinkPattern

/**
 * The ONE transfer over the KIR (R65). `TaintEngine`'s reporting analysis and
 * `SummaryAnalysis`'s summary computation used to be two ~700-line copies of
 * the same function over two fact types; R62 was found in one of the four
 * merges and fixed in two, because the copies had to be compared by eye. This
 * file is the shared machinery — abstract state, the opcode switch, the
 * merges, the pack classification, the unknown-call default — written once
 * against a fact type [F] and an engine callback set [TransferHost].
 *
 * What genuinely differs between the engines lives in [TransferHost], as
 * callbacks, not flags: how a fact is BORN at a pack source, what is
 * RECORDED at a sink, which parameter facts a field read derives, what a
 * parameter entry binds, and how an unmatched call applies callee summaries.
 * Everything else — the joins, field/index moves, suspend transparency, the
 * field-write policy, provenance blame, the worklist — is this one
 * implementation, so the engines cannot drift again by learning an opcode or
 * a merge fix in one file only.
 */
internal interface FactOps<F> {
    /** The category a fact carries (the sanitizer's clear list reads it). */
    fun categoryOf(fact: F): String

    /**
     * The path-carrying derivation of [fact] read through [suffix], when the
     * fact type derives facts on field reads of parameter roots. Reporting
     * facts keep paths on STATE KEYS, so a field read derives nothing and
     * this returns null for every fact; summary facts extend their paramPath.
     */
    fun deriveOnFieldRead(fact: F, suffix: String): F?
}

/**
 * One slot of the function's abstract memory: a register plus its path
 * suffix. Paths on keys are the field sensitivity both engines share; the
 * summary engine ADDITIONALLY carries paths on its parameter-rooted facts,
 * which is what its derivations extend.
 */
internal data class TaintKey(val base: String, val path: String) : Comparable<TaintKey> {
    override fun compareTo(other: TaintKey): Int = compareValuesBy(this, other, { it.base }, { it.path })

    fun render(): String = if (path.isEmpty()) base else "$base::$path"
}

/**
 * How a fact last moved into a key: at [site], from [prevKey], via [kind].
 * [origin] is non-null exactly at interprocedural boundaries — the summary
 * origin (`computed`, `pack`, `default`, `recursive-approx`) that moved the
 * fact — and a slice collects the origins of the boundary moves its trace
 * passed through, which is how a reviewer tells a computed summary from
 * blanket propagation (the R54 rule: the label has a producer per side).
 */
internal data class Move(val site: Int, val prevKey: TaintKey?, val kind: String, val origin: String? = null)

internal data class ChainKey<F>(val fact: F, val key: TaintKey)

/** The worklist's outcome: converged out-states and whether the budget was hit. */
internal class FixpointResult<F>(
    val outStates: Map<String, FlowState<F>>,
    val capHit: Boolean,
)

/** The abstract state: sorted maps and sorted sets, for deterministic joins. */
internal class FlowState<F> {
    val map = java.util.TreeMap<TaintKey, java.util.TreeSet<F>>()

    fun factsOf(key: TaintKey): java.util.TreeSet<F> = map[key] ?: java.util.TreeSet<F>()    fun setFacts(key: TaintKey, facts: java.util.TreeSet<F>) {
        if (facts.isEmpty()) map.remove(key) else map[key] = facts
    }

    fun addFacts(key: TaintKey, facts: Collection<F>) {
        if (facts.isEmpty()) return
        val existing = map[key]
        if (existing == null) map[key] = java.util.TreeSet(facts) else existing.addAll(facts)
    }

    fun removeKey(key: TaintKey) {
        map.remove(key)
    }

    fun copy(): FlowState<F> {
        val out = FlowState<F>()
        for ((k, v) in map) out.map[k] = java.util.TreeSet(v)
        return out
    }

    fun mergeFrom(other: FlowState<F>) {
        for ((key, facts) in other.map) addFacts(key, facts)
    }

    /** Registers x facts, the summary state budget's unit. */
    fun entryCount(): Int = map.entries.sumOf { (1 + it.value.size) }

    override fun equals(other: Any?): Boolean = other is FlowState<*> && map == other.map

    override fun hashCode(): Int = map.hashCode()
}

/**
 * The per-engine decisions. Every member is a place where the two former
 * copies genuinely disagreed or recorded engine-private evidence; everything
 * NOT here is shared and can no longer drift.
 */
internal interface TransferHost<F, C> {
    val ops: FactOps<F>

    val pack: ModelPack

    /** `--unknown-call propagate|drop` (02-ARCHITECTURE.md §6). */
    val unknownCallPropagate: Boolean

    /** `Options.accessPathDepth > 0`: paths on keys are tracked, not collapsed. */
    val fieldSensitive: Boolean

    /** A fact born at a pack source call [site] with [category]. */
    fun birthFact(site: Int, category: String): F

    /** The origin stamped on pack-driven moves (reporting: `pack`; summary: none). */
    fun packMoveOrigin(): String?

    /** Called when a pack source actually created a fact (counting, provenance). */
    fun onSourceApplied(fqn: String, site: Int, fact: F, resultKey: TaintKey, collect: C?)

    /** Called when a pack sanitizer cleared categories (the summary's `sanitizes` record). */
    fun onSanitizerCleared(cleared: List<String>, collect: C?)

    /** Called when a pack passthrough actually moved taint (counting, provenance). */
    fun onPackPassthroughApplied(fqn: String, collect: C?)

    /** A pack sink matched: the sink read its arguments (the reporting engine counts the site). */
    fun onSinkMatched(collect: C?)

    /** A resolved call, before pack classification (the summary engine records `.invoke` of parameters). */
    fun onResolvedCall(ins: KirCall, site: Int, collect: C?)

    /**
     * A pack sink read facts on argument [argIndex] at [argKey]. The reporting
     * engine raises a sink hit; the summary engine records an escape with the
     * walk back to the fact's birth.
     */
    fun onSinkRead(
        sink: SinkPattern,
        fqn: String,
        site: Int,
        argIndex: Int,
        argKey: TaintKey,
        facts: Set<F>,
        collect: C?,
    )

    /**
     * A pack effect wrote [facts] from argument [valueReg] into the
     * receiver's element state [receiverKey]. The summary engine records a
     * field-write escape here.
     */
    fun onEffectWritten(
        fqn: String,
        valueReg: String,
        receiverKey: TaintKey,
        facts: Set<F>,
        site: Int,
        collect: C?,
    )

    /** A field write into a parameter-rooted object is a summary escape. */
    fun onFieldWriteEscape(
        receiver: String,
        valueReg: String,
        suffix: String,
        facts: Set<F>,
        collect: C?,
    )

    /** A return instruction, at fixpoint (the summary engine records escapes). */
    fun onReturn(ins: KirReturn, site: Int, state: FlowState<F>, collect: C?)

    /** A dynamic call (the summary engine records function-valued parameter invocations). */
    fun onDynamicCall(ins: KirDynamicCall, site: Int, collect: C?)

    /**
     * The category a string literal stored into the NAMED local [name]
     * births (the pack's `literalSources` name rule), or null when this
     * engine tracks no literal sources.
     */
    fun literalSourceCategory(name: String): String? = null

    /** An unknown call moved taint (the reporting engine counts the precision loss). */
    fun onUnknownPropagation(collect: C?)

    /**
     * An unmatched call: apply callee summaries. Returns false when no target
     * had a summary to apply, so the shared unknown default runs (the
     * reporting engine narrows by dispatch mode and budgets the join width;
     * the summary engine joins every dispatch target).
     */
    fun applyCalleeSummaries(
        ins: KirCall,
        site: Int,
        state: FlowState<F>,
        chain: HashMap<ChainKey<F>, Move>,
        collect: C?,
    ): Boolean

    /** Entry bindings: (register, fact) seeded at the function's entry (the summary parameters). */
    fun entryBindings(): List<Pair<String, F>> = emptyList()

    /** The block whose input the entry bindings merge into, when any. */
    fun entryBlockId(): String? = null

    /** True when [state] blew past the engine's state budget and the analysis must stop. */
    fun stateOverBudget(state: FlowState<F>): Boolean = false
}

/**
 * The shared transfer: the worklist driver plus the one opcode switch. One
 * instance per analysed function; [chain] is the fixpoint's last-move graph
 * the traces walk.
 */
internal class FlowTransfer<F, C>(
    private val host: TransferHost<F, C>,
    private val chain: HashMap<ChainKey<F>, Move>,
) {

    /**
     * The worklist to fixpoint. Returns the out-states plus whether the
     * iteration budget was hit; null when the engine's state budget was hit
     * (the caller drops the whole analysis — R58's rule: a budget drops the
     * SUMMARY, never publishes half of one).
     */
    fun runFixpoint(
        blocks: List<KirBlock>,
        sitesByBlock: Map<String, List<Site>>,
        successors: Map<String, List<String>>,
        predecessors: Map<String, List<String>>,
    ): FixpointResult<F>? {
        val entryBlockId = host.entryBlockId()
        val outStates = HashMap<String, FlowState<F>>()
        val work = ArrayDeque(blocks.map { it.id })
        val queued = work.toHashSet()
        // The budget is generous and deterministic: a monotone framework over
        // finitely many facts converges well inside it on real code. Hitting
        // it is a `fixpoint-cap` diagnostic over the analysed-function count,
        // never a silent truncation.
        val budget = 64 + 16 * blocks.size
        var rounds = 0
        var capHit = false
        while (work.isNotEmpty()) {
            if (rounds++ > budget) {
                capHit = true
                break
            }
            val blockId = work.removeFirst()
            queued.remove(blockId)
            val input = inputForBlock(blockId, outStates, predecessors)
            val output = transfer(sitesByBlock.getValue(blockId), input, collect = null)
            if (host.stateOverBudget(output)) {
                return null
            }
            val previous = outStates[blockId]
            if (previous == null || output != previous) {
                outStates[blockId] = output
                for (succ in successors[blockId].orEmpty()) {
                    if (queued.add(succ)) work.addLast(succ)
                }
            }
        }
        return FixpointResult(outStates, capHit)
    }

    /** One block's input: the predecessor union, plus the entry bindings on the entry block. */
    fun inputForBlock(
        blockId: String,
        outStates: Map<String, FlowState<F>>,
        predecessors: Map<String, List<String>>,
    ): FlowState<F> {
        val joined = FlowState<F>()
        for (pred in predecessors[blockId].orEmpty()) {
            outStates[pred]?.let { joined.mergeFrom(it) }
        }
        if (blockId == host.entryBlockId()) {
            // Entry bindings are JOINED INTO the entry block's input on every
            // pass — the entry block may also carry loop predecessors, and
            // the seeds must survive both; seeding the state directly would
            // be erased by the next transfer's copy of its input.
            for ((reg, fact) in host.entryBindings()) {
                val key = TaintKey(reg, "")
                joined.addFacts(key, listOf(fact))
                chain[ChainKey(fact, key)] = Move(SummaryAnalysis.ENTRY_SITE, null, "param")
            }
        }
        return joined
    }

    /** The transfer function over one block's sites. */
    fun transfer(sites: List<Site>, input: FlowState<F>, collect: C?): FlowState<F> {
        val state = input.copy()
        val fieldSensitive = host.fieldSensitive

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

        /** True when [register] was loaded from a string literal above [upto] in this block. */
        fun isLiteralLoad(sites: List<Site>, upto: Int, register: String): Boolean {
            for (j in upto - 1 downTo 0) {
                val ins = sites[j].ins
                if (ins is KirLoad && ins.result == register) {
                    return ins.constant is KirConstant.Str
                }
                if (ins.defs.contains(register)) return false
            }
            return false
        }

        /**
         * A join over several operand registers (concat, phi, elvis): the
         * union of their facts, with provenance recorded PER FACT against
         * the operand that actually carried it. Blaming the first non-empty
         * operand for every fact sends the backward walk into a register
         * that never held it, and the walk then dead-ends — the trace ends
         * up starting in the middle of the flow with nothing marking it
         * (R54). Fixed at every merge of this shape (R62): the joins, the
         * index read, the unknown call.
         */
        fun joinInto(result: String, operands: List<String>, site: Int, kind: String) {
            val merged = java.util.TreeSet<F>()
            val blame = HashMap<F, TaintKey>()
            for (operand in operands) {
                val operandKey = reg(operand)
                for (fact in state.factsOf(operandKey)) {
                    merged.add(fact)
                    blame.putIfAbsent(fact, operandKey)
                }
            }
            val resultKey = reg(result)
            state.setFacts(resultKey, merged)
            for (fact in merged) chain[ChainKey(fact, resultKey)] = Move(site, blame.getValue(fact), kind)
        }

        for ((sitePos, site) in sites.withIndex()) {
            when (val ins = site.ins) {
                is KirAssign -> moveAll(reg(ins.source), reg(ins.result), site.id, "assign", replace = true)

                is KirStore -> {
                    moveAll(reg(ins.value), reg(ins.target), site.id, "assign", replace = true)
                    // A hardcoded secret/key material has no source CALL to
                    // hang a fact on — the pack's literalSources name rule
                    // births one at the store instead, so crypto-flow slices
                    // run through the same machinery as every other flow.
                    if (ins.target.startsWith("v")) {
                        val category = host.literalSourceCategory(ins.target.removePrefix("v"))
                        if (category != null && isLiteralLoad(sites, sitePos, ins.value)) {
                            val fact = host.birthFact(site.id, category)
                            val targetKey = reg(ins.target)
                            state.addFacts(targetKey, listOf(fact))
                            chain[ChainKey(fact, targetKey)] = Move(site.id, null, "literal-source", host.packMoveOrigin())
                        }
                    }
                }

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
                    moveAll(TaintKey(ins.receiver, pathSuffix(ins.path)), reg(ins.result), site.id, "field", replace = true)
                    // Parameter-rooted facts derive along the read — the
                    // summary engine's field sensitivity AT THE FACT, so
                    // `fun sink(job: Job) = exec(job.command)` records the
                    // extended path while `job.label` (the clean sibling)
                    // stays clean. Key-path facts were already moved above.
                    deriveFieldRead(ins.receiver, pathSuffix(ins.path), ins.result, state, site.id)
                }

                is KirSafeCall -> {
                    moveAll(TaintKey(ins.receiver, pathSuffix(ins.path)), reg(ins.result), site.id, "field", replace = true)
                    deriveFieldRead(ins.receiver, pathSuffix(ins.path), ins.result, state, site.id)
                }

                is KirFieldSet -> {
                    // A field write is a STRONG update in both engines: the
                    // written value replaces the key's prior facts at the
                    // intra-block level (the fixpoint's out-state merge is
                    // what unions across paths and iterations). The summary
                    // engine used to weak-update here — an undocumented
                    // disagreement with the reporting engine (R65).
                    val targetKey = TaintKey(ins.receiver, pathSuffix(ins.path))
                    moveAll(reg(ins.value), targetKey, site.id, "field", replace = true)
                    host.onFieldWriteEscape(ins.receiver, ins.value, pathSuffix(ins.path), state.factsOf(reg(ins.value)), collect)
                }

                is KirIndexGet -> {
                    // An element read sees the collection's element state AND
                    // any taint carried by the collection value itself (a
                    // passthrough like listOf taints the result register).
                    // Per-fact blame, like every other merge: a fact carried
                    // only by the collection VALUE must not be blamed on the
                    // element key it was never in, or the backward walk
                    // dead-ends there (R54's shape, R62).
                    val elementKey = TaintKey(ins.receiver, if (fieldSensitive) "[]" else "")
                    val wholeKey = reg(ins.receiver)
                    val merged = java.util.TreeSet<F>()
                    val blame = HashMap<F, TaintKey>()
                    for (sourceKey in listOf(elementKey, wholeKey)) {
                        for (fact in state.factsOf(sourceKey)) {
                            merged.add(fact)
                            blame.putIfAbsent(fact, sourceKey)
                        }
                    }
                    val resultKey = reg(ins.result)
                    state.setFacts(resultKey, merged)
                    for (fact in merged) chain[ChainKey(fact, resultKey)] = Move(site.id, blame.getValue(fact), "index")
                }

                is KirIndexSet ->
                    moveAll(reg(ins.value), TaintKey(ins.receiver, if (fieldSensitive) "[]" else ""), site.id, "index", replace = false)

                is KirSuspendPoint -> {
                    // A suspend boundary is TRANSPARENT to a may-analysis:
                    // the value crossing it is the value the suspending call
                    // just produced, and coroutine suspension does not
                    // launder taint. Not an omission — the P6 report counts
                    // how many slices cross these boundaries, which requires
                    // the facts to persist across them. Both engines share
                    // this now: the summary engine used to drop the call's
                    // result register here, contradicting its own comment
                    // and under-reporting suspend-crossing escapes.
                }

                is KirBranch, is KirThrow -> {}

                is KirReturn -> host.onReturn(ins, site.id, state, collect)

                is KirCall -> handleCall(ins, site.id, state, chain, collect)

                is KirDynamicCall -> {
                    host.onDynamicCall(ins, site.id, collect)
                    handleUnknown(ins.result, ins.receiver, ins.args, site.id, state, chain, collect)
                }
            }
        }
        return state
    }

    /** The derivation half of a field read (summary facts only; reporting facts derive nothing). */
    private fun deriveFieldRead(receiver: String, suffix: String, result: String, state: FlowState<F>, site: Int) {
        if (suffix.isEmpty()) return
        val baseKey = TaintKey(receiver, "")
        val resultKey = TaintKey(result, "")
        for (fact in state.factsOf(baseKey).toList()) {
            val derived = host.ops.deriveOnFieldRead(fact, suffix) ?: continue
            state.addFacts(resultKey, listOf(derived))
            chain[ChainKey(derived, resultKey)] = Move(site, baseKey, "field")
        }
    }

    /**
     * One resolved call, classified in a FIXED order (02-ARCHITECTURE.md §6,
     * P5 restatement): the PACK first — sink, source, sanitizer,
     * passthrough, effect — and it stays authoritative; then a COMPUTED
     * summary of a dispatch target when nothing matched; then the
     * `--unknown-call` default. Every move names which of the three acted.
     */
    private fun handleCall(
        ins: KirCall,
        site: Int,
        state: FlowState<F>,
        chain: HashMap<ChainKey<F>, Move>,
        collect: C?,
    ) {
        val pack = host.pack
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

        host.onResolvedCall(ins, site, collect)

        // SINK first, on the pre-call state: the sink reads its arguments.
        val sink = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sink != null) {
            matched = true
            host.onSinkMatched(collect)
            for (argIndex in sink.relevantArguments.sorted()) {
                val register = registerAt(argIndex) ?: continue
                val argKey = TaintKey(register, "")
                val facts = state.factsOf(argKey)
                if (facts.isNotEmpty()) {
                    host.onSinkRead(sink, fqn, site, argIndex, argKey, java.util.TreeSet(facts), collect)
                }
            }
        }

        // SOURCE: the result register becomes tainted with this site's fact.
        val source = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (source != null && result != null) {
            matched = true
            val fact = host.birthFact(site, source.category)
            val resultKey = TaintKey(result, "")
            state.addFacts(resultKey, listOf(fact))
            chain[ChainKey(fact, resultKey)] = Move(site, null, "source", host.packMoveOrigin())
            host.onSourceApplied(fqn, site, fact, resultKey, collect)
        }

        // SANITIZER: the named categories are cleared on the RESULT only — a
        // sanitizer must not hide the taint that stays behind in memory.
        val sanitizer = pack.sanitizers.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sanitizer != null && result != null) {
            matched = true
            val resultKey = TaintKey(result, "")
            val before = state.factsOf(resultKey)
            val remaining = before.filter { host.ops.categoryOf(it) !in sanitizer.clears }
            if (remaining.size != before.size) {
                host.onSanitizerCleared(sanitizer.clears, collect)
            }
            state.setFacts(resultKey, java.util.TreeSet(remaining))
        }

        // PASSTHROUGH: data-driven flows over the argument-position sequence.
        val passthrough = pack.passthroughs.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (passthrough != null) {
            matched = true
            var moved = false
            for (flow in passthrough.flows) {
                if (flow.size < 2) continue
                val from = registerAt(flow[0])
                val to = if (flow[1] == -1) result else registerAt(flow[1])
                if (from == null || to == null) continue
                moved = moveChain(state, chain, TaintKey(from, ""), TaintKey(to, ""), site, "call", host.packMoveOrigin()) || moved
            }
            // Element flows: index 0 reads the receiver's ELEMENT state.
            for (flow in passthrough.elementFlows) {
                if (flow.size < 2) continue
                val to = if (flow[1] == -1) result else registerAt(flow[1])
                if (to == null) continue
                val fromKey = TaintKey(receiver ?: continue, if (host.fieldSensitive) "[]" else "")
                moved = moveChain(state, chain, fromKey, TaintKey(to, ""), site, "call", host.packMoveOrigin()) || moved
            }
            if (moved) host.onPackPassthroughApplied(fqn, collect)
        }

        // EFFECT: a call that WRITES memory — argument taint flows into the
        // receiver's element state (`xs.add(tainted)` taints xs's contents).
        val effect = pack.effects.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (effect != null && receiver != null) {
            matched = true
            for (writeIndex in effect.writesToArguments) {
                // Index 0 IS the receiver: a self-write carries nothing new.
                if (writeIndex <= 0) continue
                val register = registerAt(writeIndex) ?: continue
                val facts = state.factsOf(TaintKey(register, ""))
                val receiverKey = TaintKey(receiver, if (host.fieldSensitive) "[]" else "")
                moveChain(state, chain, TaintKey(register, ""), receiverKey, site, "effect", host.packMoveOrigin())
                if (facts.isNotEmpty()) {
                    host.onEffectWritten(fqn, register, receiverKey, facts, site, collect)
                }
            }
        }

        if (matched) return

        // ---- summary application (P5) ------------------------------------
        if (host.applyCalleeSummaries(ins, site, state, chain, collect)) {
            return
        }

        handleUnknown(result, receiver, ins.args, site, state, chain, collect)
    }

    private fun moveChain(
        state: FlowState<F>,
        chain: HashMap<ChainKey<F>, Move>,
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

    private fun handleUnknown(
        result: String?,
        receiver: String?,
        args: List<String>,
        site: Int,
        state: FlowState<F>,
        chain: HashMap<ChainKey<F>, Move>,
        collect: C?,
    ) {
        if (result == null) return
        if (!host.unknownCallPropagate) {
            state.removeKey(TaintKey(result, ""))
            return
        }
        // Sound-leaning default: receiver and argument taint reach the result.
        // Counted per call where taint actually moved, so precision loss is a
        // number, not a shrug. The move's origin is `default` — the label a
        // slice collects when its existence rests on blanket propagation.
        val resultKey = TaintKey(result, "")
        val incoming = java.util.TreeSet<F>()
        // Per-fact blame: an argument's fact is attributed to THAT argument,
        // not to whichever operand happened to be non-empty first (R62).
        val blame = HashMap<F, TaintKey>()
        for (sourceReg in listOfNotNull(receiver) + args) {
            val sourceKey = TaintKey(sourceReg, "")
            for (fact in state.factsOf(sourceKey)) {
                incoming.add(fact)
                blame.putIfAbsent(fact, sourceKey)
            }
        }
        if (incoming.isEmpty()) {
            state.removeKey(resultKey)
            return
        }
        host.onUnknownPropagation(collect)
        state.addFacts(resultKey, incoming)
        for (fact in incoming) {
            chain[ChainKey(fact, resultKey)] = Move(site, blame.getValue(fact), "propagate", SummaryOrigin.DEFAULT)
        }
    }
}
