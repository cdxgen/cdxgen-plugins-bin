package io.cdxgen.kosi.kir

/**
 * Const-folding over the KIR for the evidence consumers: what a call
 * argument's register provably contains, from the module alone plus the
 * caller-supplied workspace `const val` table and config table. A value that
 * cannot be proved is [ValueStatus.UNRESOLVED], never a guess — the
 * consumers report what the code says and mark the rest unresolved.
 *
 * Folding is a BACKWARD scan within the argument's own block: the lowering
 * defines a value register at most once per block on the straight-line path
 * to its use, so the nearest prior definition is the value.
 *
 * extended the fold ACROSS BLOCKS along the dominator chain, with the
 * conservative join the project's temperament demands:
 *
 *  - a definition in a strict dominator D of the use block folds when EVERY
 *    definition of the register in the function sits on the dominator chain
 *    between D and the use — the chain is totally ordered and carries only
 *    strong updates, so the nearest dominating definition is the value on
 *    all paths. A definition anywhere OFF the chain (an if-arm, a loop
 *    body) makes the value path-dependent and the fold gives up rather
 *    than guess;
 *  - a phi folds only when every non-back-edge arm folds to the SAME value;
 *    arms that disagree are unresolved — not a guess, not the first arm;
 *  - a back edge (a phi input from a block the phi's own block dominates —
 *    a loop latch) is unresolved: loop-carried values have no single
 *    provenance the KIR can name.
 *
 * instruments WHY a fold fails. A claim about precision without a
 * denominator is the thing this project does not do: [FoldFailure] names the
 * four ways a value stays unresolved (cross-block, the depth budget, a
 * parameter, a producer the folder cannot see through), and [FoldStats]
 * counts them so the depth report can say which reason dominates and what a
 * widening bought.
 *
 * widened the PRODUCER bucket, the largest one every measurement this
 * project has taken: a register defined by a call now folds when the callee
 * is in the workspace and EVERY return site of EVERY candidate body folds to
 * the same constant. Conservative by construction: disagreeing returns,
 * an unprovable return, an open (non-exact) virtual target and recursion all
 * stay [FoldFailure.PRODUCER]; the call's arguments are never folded THROUGH
 * (a function returning its parameter is not a constant function); and the
 * workspace walk consumes the same depth budget as every other hop, so a
 * call chain that outruns it is named [FoldFailure.DEPTH_CAP], never a
 * silent stop.
 */
class KirValueFolder(
    module: KirModule,
    /**
     * Workspace `const val` NAME -> value, only when the name maps to a
     * UNIQUE value workspace-wide (an ambiguous name never folds). Built by
     * the consumer from source text; the KIR does not carry property
     * initializers.
     */
    private val constValues: Map<String, String> = emptyMap(),
    /** Config-reader callee FQN -> argument index (the config table's key). */
    configReaders: List<Pair<String, Int>> = emptyList(),
    private val envReaders: Set<String> = DEFAULT_ENV_READERS,
    configTable: Map<String, String> = emptyMap(),
    /**
     * Cross-block folding off restores the earlier block-local scan
     * exactly — the restored-defect proof for every cross-block behaviour,
     * and the depth report's baseline column (the same fixtures measured
     * both ways in one run).
     */
    private val crossBlock: Boolean = true,
    /**
     * When non-null, every [valueAt] outcome is counted here — the
     * depth report's value-resolution table. Production passes null and
     * pays nothing.
     */
    private val statsSink: FoldStats? = null,
) {
    /**
     * Provenance of a folded value. FOLDED_CONST and FOLDED_TEMPLATE both
     * publish as the report's `folded` resolution; the finer distinction is
     * the crypto gate's per-FORM denominator (a `const val` read and a
     * string-template concat are different syntactic shapes).
     *
     * NULL is the one status whose VALUE is absent on purpose: a null
     * literal is not the four characters "null" (made it visible to
     * the fold), and a consumer must be able to tell "the register
     * provably holds null" from "the value could not be proved" — the
     * route-path and outbound-URL consumers branch on exactly that
     * difference.
     */
    enum class ValueStatus { LITERAL, FOLDED_CONST, FOLDED_TEMPLATE, CONFIG, ENV, NULL, UNRESOLVED }

    /**
     * WHY a value did not fold. The breakdown is the design input
     * for widening the fold — a [PARAMETER] population is not a folding
     * problem at all, a [DEPTH_CAP] population is a budget question, and a
     * [CROSS_BLOCK] one is the folding frontier itself.
     */
    enum class FoldFailure { CROSS_BLOCK, DEPTH_CAP, PARAMETER, PRODUCER }

    /** Per-folder counters, supplied by the depth report's run. */
    class FoldStats {
        var asked: Int = 0
        var folded: Int = 0
        var crossBlock: Int = 0
        var depthCap: Int = 0
        var parameter: Int = 0
        var producer: Int = 0
        /**
         * Cross-block hops whose folding was refused by the conservative
         * rules — the §2 verdict's refusal half, published in the depth
         * report (a counter FoldStats kept but the report
         * never showed was the unread-vocabulary shape).
         */
        var crossBlockRefused: Int = 0
        /** Values resolved by walking the dominator chain (zero when disabled). */
        var crossBlockResolved: Int = 0
        /**
         * The workspace call sites whose return the folder FOLDED,
         * as `fqn\0descriptor` keys, in fold order. The depth report asks
         * the flow module's summaries about exactly these callees — the
         * agreement gate. Bounded by the folded-site count; production
         * consumers (crypto) pass no statsSink and pay nothing.
         */
        val workspaceFolds: MutableList<String> = mutableListOf()
        /**
         * The producer bucket BY CALLEE ARM. A bucket with a total
         * is a number; a bucket with a breakdown is a design input —
         * `dependency-call` (out of scope by construction), the workspace
         * refusal arms, and the shapes the folder does not recognise.
         * Recorded where the arm is decided; the counts ride the statsSink
         * (null in production) exactly like every other counter.
         */
        val producerArms: java.util.TreeMap<String, Int> = java.util.TreeMap()

        /**
         * Whether the ask in flight has already been classified. The arms
         * are recorded where the refusal is decided — at every depth of the
         * walk — and `producer` counts one per top-level ask, so without
         * this latch a nested refusal and its caller's re-refusal both
         * counted and the breakdown over-ran the bucket it explains. Null
         * between asks; the innermost arm wins, because it is the one that
         * names the shape.
         */
        private var armRecorded: Boolean = false
        private var armLatched: Boolean = false

        fun armLatchOpen() {
            armLatched = true
            armRecorded = false
        }

        fun armLatchClose() {
            armLatched = false
            armRecorded = false
        }

        fun recordProducer(arm: String) {
            if (armLatched) {
                if (armRecorded) return
                armRecorded = true
            }
            producerArms.merge(arm, 1, Int::plus)
        }

        fun snapshot(): Map<String, Int> = sortedMapOf(
            "asked" to asked,
            "crossBlock" to crossBlock,
            "crossBlockRefused" to crossBlockRefused,
            "crossBlockResolved" to crossBlockResolved,
            "depthCap" to depthCap,
            "folded" to folded,
            "parameter" to parameter,
            "producer" to producer,
        )
    }

    private val configReaderByFqn = configReaders.toMap()

    /** Config table keys -> values, supplied by the consumer's config scan. */
    private val configValues: Map<String, String> = configTable

    /**
     * The workspace call surface, keyed by the FQN a call site names
     * (the function's canonical name — the same key the flow engine's
     * CallIndex resolves through). Built once per folder; the folder holds
     * the whole module, so no second summary pass is needed.
     */
    private val workspaceByFqn: Map<String, List<KirFunction>> = module.functions.groupBy { it.canonicalName }

    /** Recursion guard for the workspace-return walk (see [workspaceReturnValue]). */
    private val workspaceInFlight = HashSet<String>()

    /**
     * Return sites per function. Keyed by IDENTITY, not canonical
     * name: overloads share a canonical name and must not share sites.
     */
    private val workspaceReturnSites = java.util.IdentityHashMap<KirFunction, List<Pair<KirBlock, Pair<Int, String?>>>>()

    /**
     * Registers a function defines, keyed by IDENTITY. A canonical name is
     * the package-and-member path with no descriptor, so overloads share
     * one — and `associate` kept the LAST, which is to say a function could
     * be asked about its registers and answered about its namesake's. Same
     * view, same key, everywhere: [cfgs] and [workspaceReturnSites] are
     * keyed the same way, and a later review is what happens when
     * one of the three is not (the review's rule: two maps describing the
     * same function must agree on what a function IS).
     */
    private val definedRegisters: Map<KirFunction, Set<String>> =
        java.util.IdentityHashMap<KirFunction, Set<String>>().apply {
            for (fn in module.functions) {
                put(
                    fn,
                    buildSet {
                        fn.params.forEach { add(it.register) }
                        for (block in fn.body?.blocks.orEmpty()) {
                            for (ins in block.instructions) {
                                addAll(ins.defs)
                            }
                        }
                    },
                )
            }
        }

    /**
     * Per-function CFG facts for the dominator walk, built lazily
     * and cached (fixtures and route trees are small; real repos hit this
     * only where a consumer folds, and the cache is per folder instance,
     * which lives for one analysis pass).
     */
    private class Cfg(
        val blockIds: List<String>,
        val indexOf: Map<String, Int>,
        val preds: Map<String, List<String>>,
        /** Immediate dominator by block id (entry maps to itself). */
        val idom: Map<String, String>,
        /** Transitive dominators INCLUDING the block itself. */
        val dominators: Map<String, Set<String>>,
        /** Blocks containing at least one definition of the register. */
        val defsByRegister: Map<String, Set<String>>,
        /** Blocks that can reach the use block (reflexive transitive successors). */
        val reaches: Map<String, Set<String>>,
    )

    /**
     * Keyed by IDENTITY, like [definedRegisters] and [workspaceReturnSites]:
     * overloads share a canonical name, and a name-keyed cache answers one
     * overload's dominator question with its namesake's control flow. That
     * is not a missed fold but a WRONG one — the review's probe folded
     * a value defined on one arm of a branch into a confident constant,
     * because the cached CFG said the defining block dominated the use when
     * in that body it did not.
     */
    private val cfgs = java.util.IdentityHashMap<KirFunction, Cfg?>()

    private fun cfgOf(fn: KirFunction): Cfg? {
        if (cfgs.containsKey(fn)) return cfgs[fn]
        val blocks = fn.body?.blocks ?: return null.also { cfgs[fn] = null }
        if (blocks.isEmpty()) return null.also { cfgs[fn] = null }
        val indexOf = blocks.withIndex().associate { (i, b) -> b.id to i }
        val succs = HashMap<String, MutableList<String>>()
        val preds = HashMap<String, MutableList<String>>()
        fun link(from: String, target: String) {
            if (target !in succs.getOrPut(from) { mutableListOf() }) {
                succs[from]!!.add(target)
                preds.getOrPut(target) { mutableListOf() }.add(from)
            }
        }
        for (block in blocks) {
            var terminates = false
            for (ins in block.instructions) {
                when (ins) {
                    is KirBranch -> {
                        link(block.id, ins.thenBlock)
                        link(block.id, ins.elseBlock)
                        terminates = true
                    }

                    is KirReturn, is KirThrow -> terminates = true
                    else -> {}
                }
            }
            // Fallthrough to the NEXT block in list order (KirModule's CFG contract).
            if (!terminates) {
                blocks.getOrNull((indexOf[block.id] ?: 0) + 1)?.let { link(block.id, it.id) }
            }
        }
        val order = blocks.map { it.id }
        // Iterative dominator-set computation (corpus functions are small
        // and this runs once per function per folder).
        val entry = order.first()
        val domSets = HashMap<String, MutableSet<String>>()
        domSets[entry] = mutableSetOf(entry)
        var changed = true
        while (changed) {
            changed = false
            for (id in order) {
                if (id == entry) continue
                val ready = preds[id].orEmpty().filter { domSets.containsKey(it) }
                if (ready.isEmpty()) continue
                var newDom: MutableSet<String>? = null
                for (p in ready) {
                    val pd = domSets[p] ?: mutableSetOf(entry, p)
                    newDom = if (newDom == null) pd.toMutableSet() else newDom!!.intersect(pd).toMutableSet()
                }
                newDom!!.add(id)
                val old = domSets[id]
                if (old != newDom) {
                    domSets[id] = newDom
                    changed = true
                }
            }
        }
        // The immediate dominator is the CLOSEST strict dominator: the one
        // whose own dominator set is exactly one element smaller.
        val idom = HashMap<String, String>()
        for (id in order) {
            if (id == entry) {
                idom[id] = id
                continue
            }
            val strict = domSets[id].orEmpty() - id
            idom[id] = strict.maxByOrNull { domSets[it]?.size ?: 0 } ?: entry
        }
        val defsByRegister = HashMap<String, MutableSet<String>>()
        for (block in blocks) {
            for (ins in block.instructions) {
                for (def in ins.defs) {
                    defsByRegister.getOrPut(def) { mutableSetOf() }.add(block.id)
                }
            }
        }
        // Reflexive transitive successors ("reaches"): reachable-query per pair.
        val reaches = HashMap<String, Set<String>>()
        for (id in order) {
            val seen = sortedSetOf(id)
            val work = ArrayDeque<String>()
            work.addLast(id)
            while (work.isNotEmpty()) {
                val cur = work.removeFirst()
                for (s in succs[cur].orEmpty()) {
                    if (seen.add(s)) work.addLast(s)
                }
            }
            reaches[id] = seen
        }
        val cfg = Cfg(
            blockIds = order,
            indexOf = indexOf,
            preds = preds,
            idom = idom,
            dominators = domSets,
            defsByRegister = defsByRegister,
            reaches = reaches,
        )
        cfgs[fn] = cfg
        return cfg
    }

    data class FoldedValue(
        val value: String?,
        val status: ValueStatus,
        val detail: String? = null,
        /** Why an unresolved value stayed unresolved. Null when resolved (or NULL). */
        val failure: FoldFailure? = null,
    ) {
        val resolved: Boolean get() = value != null && status != ValueStatus.UNRESOLVED
    }

    /**
     * The provable value of [register], defined at or before instruction
     * [index] of [block] in [fn]'s body. Null when the register is not a
     * string-shaped value at all (unknown). A register that PROVABLY holds
     * the null literal returns [FoldedValue] with [ValueStatus.NULL] and a
     * null value — "found null" and "could not prove" are different facts
     * and the callers that care branch on the status.
     */
    fun valueAt(fn: KirFunction, block: KirBlock, index: Int, register: String): FoldedValue? {
        // One ask, one arm. The arms are recorded wherever the
        // refusal is DECIDED, which is at every depth of the walk, while
        // `producer` counts only this top-level ask — so a nested refusal
        // that the outer frame then re-refuses recorded two arms for one
        // failure. `recursive(n)`'s inner call names `workspace-recursion`
        // and its caller then names `workspace-return-unprovable` for the
        // same ask. The gate asserted arms == producer and passed only
        // because no bundled fixture had a nested refusal; driving the
        // arms made the over-count visible at once, which is the
        // gate doing its job a change late. The INNERMOST arm wins: it is
        // the one that names the actual shape, where the outer frame can
        // only say "the callee did not fold".
        statsSink?.armLatchOpen()
        val out = fold(fn, block, index, register, depth = 0)
        statsSink?.armLatchClose()
        statsSink?.let { stats ->
            stats.asked++
            when {
                out == null -> {}
                out.resolved -> stats.folded++
                out.status == ValueStatus.NULL -> {}
                else -> when (out.failure) {
                    FoldFailure.CROSS_BLOCK -> stats.crossBlock++
                    FoldFailure.DEPTH_CAP -> stats.depthCap++
                    FoldFailure.PARAMETER -> stats.parameter++
                    FoldFailure.PRODUCER -> stats.producer++
                    null -> {}
                }
            }
        }
        return out
    }

    private fun fold(fn: KirFunction, block: KirBlock, index: Int, register: String, depth: Int): FoldedValue? {
        if (depth > MAX_DEPTH) {
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.DEPTH_CAP)
        }
        // Scan backwards for the definition of this register.
        for (i in index - 1 downTo 0) {
            val ins = block.instructions.getOrNull(i) ?: continue
            val target = defOf(ins) ?: continue
            if (target != register) continue
            return when (ins) {
                is KirLoad -> when (val constant = ins.constant) {
                    // Source string literals carry their quotes (the lowering
                    // keeps the template's source text); strip them.
                    is KirConstant.Str -> FoldedValue(constant.value.removeSurrounding("\""), ValueStatus.LITERAL)
                    is KirConstant.IntConst -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                    // Typed since a later review lowering fix: these used
                    // to arrive as Str of their source text and fold as
                    // literals, so they keep folding as literals — with the
                    // exception of Null, which is the absence of a value and
                    // must not fold to the four characters "null".
                    is KirConstant.Bool -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                    is KirConstant.FloatConst -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                    is KirConstant.Null -> FoldedValue(null, ValueStatus.NULL)
                    else -> null
                }

                is KirStringConcat -> foldConcat(fn, block, i, ins.parts, depth)

                is KirFieldGet -> {
                    // `const val` reads lower as a fieldget whose path ends in
                    // the property name; a unique workspace value folds.
                    val name = (ins.path.elements.lastOrNull() as? AccessPath.Element.Field)?.name
                    val constValue = name?.let { constValues[it] }
                    if (constValue != null) {
                        FoldedValue(constValue, ValueStatus.FOLDED_CONST)
                    } else {
                        unresolved("field-read")
                    }
                }

                is KirAssign -> fold(fn, block, i, ins.source, depth + 1)

                // The local's value is whatever was stored into it, proved
                // from ABOVE the store — a store is a strong update, so the
                // nearest one above the use is the value at the use.
                is KirStore -> fold(fn, block, i, ins.value, depth + 1)

                is KirPhi -> cfgOf(fn)?.let { foldPhi(fn, it, block, ins, depth) }
                    ?: FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)

                is KirCall -> callValue(fn, block, i, ins, depth)

                else -> unresolved("unrecognised-ins")
            }
        }
        // Not defined in this block above the use. A parameter is the
        // caller's value — a folding boundary by definition, named as its
        // own failure so the depth report never counts it as a folding
        // miss. Anything else is defined elsewhere in the
        // function: the cross-block walk.
        if (fn.params.any { it.register == register }) {
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PARAMETER)
        }
        return foldCrossBlock(fn, block, register, depth)
    }

    /**
     * A string concat folds when every register part folds; the raw
     * fragments (not registers of this function) are the lowering's literal
     * text. The FIRST failing part's failure reason is the concat's — that
     * is why the template stayed unresolved, and the depth report counts it
     * there.
     */
    private fun foldConcat(fn: KirFunction, block: KirBlock, index: Int, parts: List<String>, depth: Int): FoldedValue {
        val sb = StringBuilder()
        var status = ValueStatus.FOLDED_TEMPLATE
        var detail: String? = null
        for (part in parts) {
            val piece = if (part in (definedRegisters[fn] ?: emptySet())) {
                resolveAbove(fn, block, index, part, depth)
            } else {
                FoldedValue(part, ValueStatus.FOLDED_TEMPLATE)
            }
            if (piece?.value == null) {
                val failure = when {
                    piece == null -> FoldFailure.PARAMETER
                    piece.failure != null -> piece.failure
                    piece.status == ValueStatus.NULL -> null
                    else -> FoldFailure.PRODUCER
                }
                return FoldedValue(
                    null,
                    ValueStatus.UNRESOLVED,
                    piece?.detail?.takeIf { piece.status == ValueStatus.UNRESOLVED },
                    failure = failure,
                )
            }
            if (piece.status != ValueStatus.LITERAL &&
                piece.status != ValueStatus.FOLDED_CONST &&
                piece.status != ValueStatus.FOLDED_TEMPLATE
            ) {
                status = piece.status
                detail = piece.detail
            }
            sb.append(piece.value)
        }
        return FoldedValue(sb.toString(), status, detail)
    }

    /**
     * The fold past the block boundary, along the dominator chain.
     *
     * Sound rule: the register's definitions in this function must ALL sit
     * on the use block's dominator chain (the chain is totally ordered and
     * every def is a strong update along it, so the nearest dominating def
     * is THE value at the use on every path). Any def off the chain — an
     * if-arm, a loop body — makes the value path-dependent, and the fold
     * refuses rather than guess. Phis on the chain resolve only when every
     * non-back-edge arm folds to the same value.
     */
    private fun foldCrossBlock(fn: KirFunction, block: KirBlock, register: String, depth: Int): FoldedValue? {
        // The disabled fold refuses past the boundary with the refusal
        // NAMED — the depth report's baseline column counts exactly these,
        // which is how the §2 extension was judged. Consumers see
        // an unresolved value either way.
        if (!crossBlock) {
            statsSink?.let { it.crossBlockRefused++ }
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
        }
        if (depth > MAX_DEPTH) {
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.DEPTH_CAP)
        }
        val cfg = cfgOf(fn)
            ?: return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            .also { statsSink?.let { s -> s.crossBlockRefused++ } }
        val defBlocks = cfg.defsByRegister[register].orEmpty()
        if (defBlocks.isEmpty()) return null // never defined in this function: not a value
        val dominators = cfg.dominators[block.id]
            ?: return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            .also { statsSink?.let { s -> s.crossBlockRefused++ } }
        val offChain = defBlocks.any { it !in dominators }
        if (offChain) {
            statsSink?.let { it.crossBlockRefused++ }
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
        }
        // Walk the strict dominators from the nearest; the first one holding
        // a definition carries the live value.
        var cur: String? = cfg.idom[block.id]
        var hops = 0
        while (cur != null) {
            if (hops > MAX_DEPTH || depth > MAX_DEPTH) {
                // The budget binds: named — the valueAt accounting counts
                // it — never a silent stop.
                return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.DEPTH_CAP)
            }
            hops++
            val dBlock = fn.body?.blocks?.getOrNull(cfg.indexOf[cur] ?: -1)
            if (dBlock == null) break
            for (i in dBlock.instructions.indices.reversed()) {
                val ins = dBlock.instructions[i]
                if (defOf(ins) != register) continue
                val value = when (ins) {
                    is KirPhi -> foldPhi(fn, cfg, dBlock, ins, depth + 1)
                    else -> foldDef(fn, cfg, dBlock, i, ins, depth + 1)
                }
                if (value != null && value.resolved) statsSink?.let { it.crossBlockResolved++ }
                if (value == null) statsSink?.let { it.crossBlockRefused++ }
                return value ?: FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            }
            if (cur == cfg.idom[cur]) break // the entry
            cur = cfg.idom[cur]
        }
        // The dominator chain holds no readable definition of the register.
        statsSink?.let { it.crossBlockRefused++ }
        return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
    }

    /**
     * The conservative join: every input arm folds to the SAME value, or the
     * phi stays unresolved. An arm coming from a block the phi's own block
     * dominates is a BACK EDGE — loop-carried, no single provenance,
     * unresolved regardless of what the other arms say.
     */
    private fun foldPhi(fn: KirFunction, cfg: Cfg, block: KirBlock, phi: KirPhi, depth: Int): FoldedValue {
        if (depth > MAX_DEPTH) return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.DEPTH_CAP)
        var value: FoldedValue? = null
        // Sorted by predecessor id: the join's verdict must not depend on
        // the map's iteration order (the same-value result is order-free,
        // but the recorded detail rides the first arm).
        for ((predId, inputReg) in phi.inputs.toList().sortedBy { it.first }) {
            val predIndex = cfg.indexOf[predId] ?: return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            val predBlock = fn.body?.blocks?.getOrNull(predIndex) ?: continue
            // BACK EDGE: the phi's own block dominates its predecessor —
            // the arm is a loop latch and the value is loop-carried. No
            // single provenance, whatever the other arms say.
            if (block.id in (cfg.dominators[predId] ?: emptySet())) {
                statsSink?.let { it.crossBlockRefused++ }
                return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            }
            val arm = fold(fn, predBlock, predBlock.instructions.size, inputReg, depth + 1)
            if (arm == null || !arm.resolved) {
                statsSink?.let { it.crossBlockRefused++ }
                return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            }
            if (value == null) {
                value = arm
            } else if (value.value != arm.value || value.status != arm.status) {
                // Arms disagree: unresolved — not a guess, not the first arm.
                statsSink?.let { it.crossBlockRefused++ }
                return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
            }
        }
        return value ?: FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.CROSS_BLOCK)
    }

    /** Folds the definition instruction [ins] found in a dominator block. */
    private fun foldDef(fn: KirFunction, cfg: Cfg, block: KirBlock, index: Int, ins: KirIns, depth: Int): FoldedValue? =
        when (ins) {
            is KirLoad -> when (val constant = ins.constant) {
                is KirConstant.Str -> FoldedValue(constant.value.removeSurrounding("\""), ValueStatus.LITERAL)
                is KirConstant.IntConst -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                is KirConstant.Bool -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                is KirConstant.FloatConst -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                is KirConstant.Null -> FoldedValue(null, ValueStatus.NULL)
                else -> FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
            }

            is KirStringConcat -> foldConcat(fn, block, index, ins.parts, depth)
            is KirAssign -> fold(fn, block, index, ins.source, depth)
            is KirStore -> fold(fn, block, index, ins.value, depth)
            is KirFieldGet -> {
                val name = (ins.path.elements.lastOrNull() as? AccessPath.Element.Field)?.name
                val constValue = name?.let { constValues[it] }
                if (constValue != null) {
                    FoldedValue(constValue, ValueStatus.FOLDED_CONST)
                } else {
                    unresolved("field-read")
                }
            }

            is KirCall -> callValue(fn, block, index, ins, depth)
            else -> unresolved("unrecognised-ins")
        }

    private fun resolveAbove(fn: KirFunction, block: KirBlock, index: Int, register: String, depth: Int): FoldedValue? =
        fold(fn, block, index, register, depth + 1)

    private fun callValue(fn: KirFunction, block: KirBlock, index: Int, ins: KirCall, depth: Int): FoldedValue {
        // env readers: the VALUE is the process environment of the analysed
        // build, which kosi never reads — the key name is the evidence.
        if (ins.callee.fqn in envReaders) {
            val key = ins.args.getOrNull(0)?.let { fold(fn, block, index, it, depth + 1) }
            return FoldedValue(null, ValueStatus.ENV, key?.value ?: ins.args.getOrNull(0))
        }
        val argIndex = configReaderByFqn[ins.callee.fqn]
        if (argIndex != null) {
            val keyReg = ins.args.getOrNull(argIndex) ?: return unresolved("config-unresolved")
            val key = fold(fn, block, index, keyReg, depth + 1) ?: return unresolved("config-unresolved")
            val keyValue = key.value ?: return unresolved("config-unresolved")
            val configValue = configValues[keyValue] ?: return FoldedValue(null, ValueStatus.UNRESOLVED, keyValue)
            return FoldedValue(configValue, ValueStatus.CONFIG, keyValue)
        }
        // A workspace callee whose every return is the same provable
        // constant folds to it. The env/config arms above keep precedence —
        // a workspace function that SHADOWS a config-reader FQN is answered
        // by the config table, the arm with the older contract. No depth
        // guard here on purpose: a call reached at the budget's edge walks
        // one more hop and the nested fold's own entry check names
        // DEPTH_CAP — guarding here would misname it PRODUCER.
        workspaceReturnValue(ins, depth)?.let {
            // A FOLDED workspace return — resolved, or provably null
            // (a NULL-status value is a fact the consumers branch on). The
            // internal refusals also come back non-null (an UNRESOLVED
            // FoldedValue carrying its producer arm), and they are not
            // folds — recording one as such produced a phantom disagreement
            // with the flow summary on the very first run of this gate.
            if (it.resolved || it.status == ValueStatus.NULL) {
                statsSink?.workspaceFolds?.add(ins.callee.fqn + "\u0000" + (ins.callee.descriptor ?: ""))
            }
            return it
        }
        // The refusal's ARM is the design input: a call into a
        // constructor, into a dependency (no workspace body — out of scope
        // by construction). A workspace body that refused recorded its
        // precise arm inside [workspaceReturnValue] before this line.
        if (ins.callee.kind == CallKind.CONSTRUCTOR) {
            statsSink?.recordProducer("constructor")
        } else if (workspaceByFqn[ins.callee.fqn].orEmpty().none { it.body != null }) {
            statsSink?.recordProducer("dependency-call")
        }
        return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
    }

    private fun unresolved(arm: String): FoldedValue {
        statsSink?.recordProducer(arm)
        return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
    }

    /**
     * The value of a call whose callee is in the workspace, when that value
     * is provably constant. Null when the callee is not a workspace call at
     * all (the caller answers PRODUCER). The rule is the flow engine's
     * CallIndex narrowed to constants: candidates are the workspace bodies
     * the callee FQN (and the site's descriptor, when it carries one)
     * resolves to; a VIRTUAL call whose bodies are not EXACT — the flow
     * engine's own rule (final/private member, object/companion/enum owner,
     * or a top-level function) — may dispatch to an override kosi cannot see
     * (a dependency jar's subclass), so it refuses. Every candidate's every
     * return site must fold to the SAME value; the callee's parameters are
     * never folded through (a function returning its parameter is not a
     * constant function); a recursive cycle refuses; the depth budget binds
     * through the walk the same as through any other hop and names
     * [FoldFailure.DEPTH_CAP] when it does. --- — WHY THIS WALK IS NOT THE
     * FLOW MODULE'S SUMMARIES, decided and written here because this is the
     * only place both can be read at once. built the gate that compares this
     * walk's answer to "what does this call return" against `kosi-flow`'s
     * summaries, and published three counters. The committed result was 5
     * folded, 5 agree, 0 disagree and **0 no-opinion**, and the plan read
     * the no-opinion counter as the design input: the population one side
     * could INHERIT from the other. An empty no-opinion column was therefore
     * taken to mean "the flow module already knows about every callee this
     * walk folds — so why two walks?" That reading does not survive contact
     * with what the two analyses compute. This walk is a MUST analysis over
     * VALUES: it must come back with the string `"https://api.example.com"`
     * or refuse, because its consumers publish the value as a service name,
     * a route path, a cipher transform. A summary is a MAY analysis over
     * LABELS: it says whether taint can reach the return, and it carries no
     * value at all — there is nothing in a `FunctionSummary` from which a
     * returned constant could be recovered, for any callee, ever. The zero
     * in the no-opinion column says the flow module has an opinion about
     * TAINT on every callee this walk folds. It does not say, and cannot
     * say, that it has the VALUE. So the two walks stay, and they are not
     * duplication: two analyses of different kinds that happen to traverse
     * the same call. What the gate proves is a CONSISTENCY property, not an
     * inheritance opportunity — a callee this walk proves constant carries
     * no taint to its return, so a summary claiming otherwise means one of
     * the two is wrong. Worth gating permanently; worth nothing as a
     * refactor. That is the decision asked for, with the number that
     * prompted the question explained rather than acted on.
     */
    private fun workspaceReturnValue(ins: KirCall, depth: Int): FoldedValue? {
        val candidates = workspaceCandidates(ins.callee) ?: return null
        var value: FoldedValue? = null
        for (candidate in candidates) {
            // Recursion: a cycle has no single provenance. The guard entry
            // belongs to an outer frame — leave it there.
            if (!workspaceInFlight.add(candidate.canonicalName)) {
                statsSink?.recordProducer("workspace-recursion")
                return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
            }
            try {
                for ((block, site) in returnSitesOf(candidate)) {
                    val (retIndex, returned) = site
                    // A Unit return (`return` with no value) is not a
                    // value. Folded this into the general arm: as its
                    // own name it was a distinction the measurement never
                    // made — no Kotlin a fixture can write reaches a Unit
                    // return site through a VALUE ask, and an arm nothing
                    // drives is a vocabulary entry is about.
                    val reg = returned ?: return unresolved("workspace-return-unprovable")
                    val siteValue = fold(candidate, block, retIndex, reg, depth + 1)
                    if (siteValue == null || (!siteValue.resolved && siteValue.status != ValueStatus.NULL)) {
                        // The budget binds INSIDE the callee's body: keep its
                        // name — a silent stop is the one answer the depth
                        // report cannot use.
                        if (siteValue?.failure == FoldFailure.DEPTH_CAP) return siteValue
                        // The callee returns its PARAMETER: the arm the next
                        // widening question names.
                        return if (siteValue?.failure == FoldFailure.PARAMETER) {
                            unresolved("workspace-parameter-return")
                        } else {
                            unresolved("workspace-return-unprovable")
                        }
                    }
                    // The site names a CALL, not the value itself: whatever
                    // the body returned publishes as FOLDED_CONST — the
                    // resolution a consumer reads is the shape AT THE USE
                    // SITE, and only the depth report needs the finer
                    // provenance. NULL keeps its status: a function whose
                    // every return is provably null gives the consumers the
                    // absence they branch on, never a guess.
                    val normalized = when {
                        siteValue.status == ValueStatus.NULL -> siteValue
                        else -> siteValue.copy(status = ValueStatus.FOLDED_CONST)
                    }
                    if (value == null) {
                        value = normalized
                    } else if (value.value != normalized.value || value.status != normalized.status) {
                        // Return sites disagree: unresolved — not a guess,
                        // not the first arm.
                        statsSink?.recordProducer("workspace-returns-disagree")
                        return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
                    }
                }
            } finally {
                workspaceInFlight.remove(candidate.canonicalName)
            }
        }
        if (value == null) {
            // No candidate offered a readable return site. Folded
            // this into the general arm too: every Kotlin body the lowering
            // produces carries a return site — a `throw` gets one whose
            // value is the exception, and so does a `while (true)` — both of
            // which were tried against this arm and landed on
            // return-unprovable instead. Keeping a name for a case no
            // fixture can reach is the state §3 exists to end.
            statsSink?.recordProducer("workspace-return-unprovable")
            return FoldedValue(null, ValueStatus.UNRESOLVED, failure = FoldFailure.PRODUCER)
        }
        return value
    }

    /**
     * The workspace bodies a call site can dispatch to, or null when the
     * FQN names no workspace function (the caller's PRODUCER case). A
     * site-known descriptor narrows overloads; without one, EVERY overload
     * must agree — the same widening-toward-more-candidates rule the flow
     * engine applies, and a constructor is never a constant-value candidate.
     */
    private fun workspaceCandidates(callee: KirCallee): List<KirFunction>? {
        if (callee.kind == CallKind.CONSTRUCTOR) return null
        val declared = workspaceByFqn[callee.fqn].orEmpty().filter { it.body != null }
        if (declared.isEmpty()) return null
        val narrowed = callee.descriptor?.let { d -> declared.filter { it.jvmDescriptor == d } }.orEmpty()
        val candidates = narrowed.ifEmpty { declared }
        if (callee.kind == CallKind.VIRTUAL) {
            if (candidates.any { !isExactWorkspaceTarget(it) }) {
                // An override can hide in a jar: recorded as its own
                // producer arm, refused.
                statsSink?.recordProducer("workspace-virtual-open")
                return null
            }
        }
        return candidates
    }

    /**
     * The flow engine's exactness rule: a virtual call may be overridden
     * only when no override can hide outside the workspace. Missing facts
     * widen toward MORE candidates, never fewer — here that means refusing
     * the fold, never proving a constant the dispatch could contradict.
     */
    private fun isExactWorkspaceTarget(f: KirFunction): Boolean {
        if (f.enclosingClass == null) return true
        if ("final" in f.modifiers) return true
        if (f.visibility == "private") return true
        val flags = f.ownerFlags
        return flags.any { it == "final" || it == "object" || it == "companion" || it == "enum" }
    }

    /** Return sites of a workspace function, in stable (block, index) order. */
    private fun returnSitesOf(fn: KirFunction): List<Pair<KirBlock, Pair<Int, String?>>> =
        workspaceReturnSites.getOrPut(fn) {
            val sites = mutableListOf<Pair<KirBlock, Pair<Int, String?>>>()
            for (block in fn.body?.blocks.orEmpty()) {
                for ((index, ins) in block.instructions.withIndex()) {
                    if (ins is KirReturn) sites.add(block to (index to ins.value))
                }
            }
            sites
        }

    private fun defOf(ins: KirIns): String? = when (ins) {
        is KirLoad -> ins.result
        is KirStringConcat -> ins.result
        is KirFieldGet -> ins.result
        is KirAssign -> ins.result
        // A local `val`/`var` lowers to a STORE, not an assign, and the
        // store defines its target — `KirIns.defs` has always said so. This
        // arm did not, so every register named by a local was invisible to
        // the fold: the backward scan walked past its own definition, and
        // §2's dominator walk scanned the dominating block for a def whose
        // instruction it could not recognise and fell through to
        // CROSS_BLOCK. The two views of "what defines this register" — the
        // CFG's `ins.defs` and this function — must be the same view
        // (a later review).
        is KirStore -> ins.target
        is KirCall -> ins.result
        is KirNew -> ins.result
        is KirCast -> ins.result
        is KirTypeCheck -> ins.result
        is KirElvis -> ins.result
        is KirPhi -> ins.result
        else -> null
    }

    companion object {
        private const val MAX_DEPTH = 8

        /** Callee FQNs whose result is a process-environment read. */
        val DEFAULT_ENV_READERS = setOf("java.lang.System.getenv", "kotlin.system.getenv")
    }
}
