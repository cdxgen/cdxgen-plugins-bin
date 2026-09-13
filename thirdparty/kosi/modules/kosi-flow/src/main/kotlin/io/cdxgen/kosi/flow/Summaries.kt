package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.models.ModelPack

/**
 * P5's interprocedural half: bottom-up function summaries over the call
 * graph's SCC condensation, applied at call sites under the P3 dispatch
 * modes, with an `origin` label on every boundary move so a reviewer can
 * tell a computed summary from blanket propagation.
 *
 * The origin vocabulary is closed and documented in
 * JSON_ATTRIBUTE_REFERENCE.md:
 *   computed         — a real fixpoint over the callee's body;
 *   pack             — a model-pack entry supplied the effect;
 *   recursive-approx — the SCC hit its iteration budget and this is the
 *                      last iterate;
 *   default          — the `--unknown-call` fallback, no body was seen.
 */
internal object SummaryOrigin {
    const val COMPUTED = "computed"
    const val PACK = "pack"
    const val RECURSIVE_APPROX = "recursive-approx"
    const val DEFAULT = "default"
}

/** One interprocedurally-visible escape: a parameter's taint reaches a sink. */
internal data class SummarySinkEffect(
    /** Index into the summary's function's [KirFunction.params]. */
    val paramIndex: Int,
    /**
     * The access path from the parameter to the value that reached the
     * sink ("" = the parameter value itself, "command" = its `.command`
     * field). The caller matches its own taint on the same path.
     */
    val paramPath: String,
    /** Global site id of the sink call inside the (possibly deeper) callee. */
    val sinkSite: Int,
    val sinkCalleeFqn: String,
    val sinkCategory: String,
    val sinkSeverity: String,
    val sinkArgumentIndex: Int,
    val sinkAccessPath: String,
    /**
     * Forward site path from this function's entry to the sink: this
     * function's moves, then (for escapes through a deeper call) the call
     * site and the deeper function's path. Endpoints are site ids in the
     * GLOBAL id space, so one path can span functions.
     */
    val path: List<Int>,
    /** True when the path could not be fully walked (cap, cycle, missing provenance). */
    val elided: Boolean,
)

/**
 * A summary fact: `param` facts (a parameter's taint, no category — the
 * caller's categories travel over the channel at application time) and
 * `source` facts (born at a source call inside the body, category-carrying).
 * [path] is the access path from the parameter root to the value carrying
 * this fact: seeds start at "", and a field READ of the parameter's base
 * extends it — so a sink reached through `job.command` records paramPath
 * "command", and the caller looks for its taint on the SAME path of its own
 * argument (field sensitivity at the boundary, the clean-sibling negative
 * preserved).
 */
internal data class SummaryFact(
    val param: Int?,
    val site: Int?,
    val category: String,
    val path: String = "",
) : Comparable<SummaryFact> {
    override fun compareTo(other: SummaryFact): Int =
        compareValuesBy(this, other, { it.param ?: -1 }, { it.site ?: -1 }, { it.category }, { it.path })

    fun withPath(newPath: String): SummaryFact = SummaryFact(param, site, category, newPath)
}

/**
 * The summary of one function: what taint entering through its parameters
 * does inside it. Parameter facts are tracked WITHOUT categories — a summary
 * says "p0 reaches the sink", and the caller's real categories travel over
 * that channel at application time. Source facts (taint born at a source
 * call inside the body) do carry categories, because `sourceReturns` is
 * category-valued in the schema.
 */
internal class FunctionSummary(
    val function: KirFunction,
    /** Parameters whose taint reaches the return value. */
    val paramToReturn: Set<Int>,
    /** Write effects: param i's taint lands on param j's register. */
    val paramToParam: Map<Int, Set<Int>>,
    /**
     * Field write effects: param i's taint stored into param j's object at
     * these access-path suffixes (`box.command = raw` is from=1 to=0
     * suffix=command). The receiver is just param j = the receiver index;
     * the schema's paramToReceiver/accessPaths project that case.
     */
    val paramFieldWrites: Map<Int, Map<Int, Set<String>>>,
    /** Kept for the schema projection: the receiver-part of [paramFieldWrites]. */
    val receiverWrites: Map<Int, Set<String>>,
    val sinkEffects: List<SummarySinkEffect>,
    /** Taint born at a source call inside the body, returned: category -> forward path. */
    val sourceReturns: Map<String, List<Int>>,
    /** Categories a pack sanitizer inside the body clears (report data). */
    val sanitizes: Set<String>,
    /** Function-valued parameters whose value the body invokes. */
    val invokedParams: Set<Int>,
    val origin: String,
) {
    fun sameAs(other: FunctionSummary): Boolean =
        paramToReturn == other.paramToReturn &&
            paramToParam == other.paramToParam &&
            paramFieldWrites == other.paramFieldWrites &&
            receiverWrites == other.receiverWrites &&
            sinkEffects == other.sinkEffects &&
            sourceReturns == other.sourceReturns &&
            sanitizes == other.sanitizes &&
            invokedParams == other.invokedParams

    /** Projects onto the schema type (param ids `p<i>` over the params list). */
    fun toSchema(): io.cdxgen.kosi.schema.FlowSummary {
        val names = function.params.map { it.name }
        val receiverIndex = function.params.indexOfFirst { it.receiver }
        fun pid(index: Int): String = "p$index"
        return io.cdxgen.kosi.schema.FlowSummary(
            functionId = function.canonicalName,
            function = function.canonicalName,
            parameterNames = names.map { it ?: "p${names.indexOf(it)}" },
            parameterTypes = function.params.map { it.type ?: "" },
            returnType = function.returnType ?: "",
            paramToReturn = paramToReturn.map { pid(it) },
            paramToParam = (paramToParam.flatMap { (from, tos) -> tos.map { "${pid(from)}->${pid(it)}" } } +
                paramFieldWrites.flatMap { (from, tos) ->
                    tos.filterKeys { to -> to != receiverIndex }.flatMap { (_, suffixes) ->
                        if (suffixes.isEmpty()) emptyList() else listOf("${pid(from)}->${pid(tos.keys.first())}")
                    }
                }),
            paramToReceiver = paramFieldWrites
                .filterKeys { from -> receiverIndex in (paramFieldWrites[from] ?: emptyMap()) }
                .keys.map { pid(it) },
            paramToSink = sinkEffects
                .groupBy { pid(it.paramIndex) }
                .mapValues { (_, effects) -> effects.map { it.sinkArgumentIndex }.distinct().sorted() },
            sourceReturns = sourceReturns.keys.sorted(),
            sanitizes = sanitizes.sorted(),
            accessPaths = receiverWrites.entries
                .filter { it.value.isNotEmpty() }
                .associate { (param, suffixes) -> pid(param) to suffixes.sorted().joinToString("|") },
            origin = origin,
        )
    }
}

/**
 * Resolves call sites to workspace callee sets, per the run's dispatch mode.
 * Built ONLY from the KIR's facts — canonical names, jvmDescriptors,
 * `overrides`, enclosing classes and owner flags — with missing facts
 * widening toward MORE candidates, never fewer (the P3 rule).
 */
internal class CallIndex(
    compiled: List<CompiledFunction>,
    private val dispatchMode: String,
) {
    private val workspaceClasses: Set<String> = compiled
        .mapNotNull { it.function.enclosingClass }
        .toSortedSet()

    /**
     * VTA's exact-type facts per function: registers whose type is known by
     * CONSTRUCTION (a `KirNew`, a constructor call), propagated through
     * copies, stores, phis and elvis joins to a per-function fixpoint — the
     * same site-local pre-pass the P3 graph runs. Registers with no known
     * type yield an empty set and their sites fall back to the RTA
     * candidate set; unknown never narrows.
     */
    private val registerTypesByFunction: Map<String, Map<String, Set<String>>> = compiled.associate { cf ->
        val body = cf.blocks
        val types = HashMap<String, MutableSet<String>>()
        fun learn(reg: String, type: String): Boolean = types.getOrPut(reg) { sortedSetOf() }.add(type)
        fun propagate(target: String, source: String?): Boolean {
            if (source == null) return false
            val sourceTypes = types[source] ?: return false
            if (sourceTypes.isEmpty()) return false
            return types.getOrPut(target) { sortedSetOf() }.addAll(sourceTypes)
        }

        var changed = true
        var passes = 0
        while (changed && passes < 8) {
            changed = false
            passes++
            for (block in body) {
                for (ins in block.instructions) {
                    when (ins) {
                        is KirNew -> changed = learn(ins.result, ins.type) || changed
                        is KirCall ->
                            changed = when (ins.callee.kind) {
                                CallKind.CONSTRUCTOR -> learn(ins.result ?: continue, ins.callee.fqn) || changed
                                else -> propagate(ins.result ?: continue, ins.receiver) || changed
                            }

                        is io.cdxgen.kosi.kir.KirAssign -> changed = propagate(ins.result, ins.source) || changed
                        is KirStore -> changed = propagate(ins.target, ins.value) || changed
                        is io.cdxgen.kosi.kir.KirPhi -> for ((_, source) in ins.inputs) changed = propagate(ins.result, source) || changed
                        is io.cdxgen.kosi.kir.KirElvis -> {
                            changed = propagate(ins.result, ins.value) || changed
                            changed = propagate(ins.result, ins.fallback) || changed
                        }

                        else -> {}
                    }
                }
            }
        }
        cf.function.canonicalName to types
    }

    /** A package-qualified receiver type narrows to chain-form classes by suffix. */
    private fun knownTypes(functionCanonical: String, receiver: String?): Set<String> {
        if (receiver == null) return emptySet()
        val raw = registerTypesByFunction[functionCanonical]?.get(receiver).orEmpty()
        if (raw.isEmpty()) return emptySet()
        return raw.flatMap { type -> canonicalClasses(type) }.toSet()
    }

    /**
     * Narrows [candidates] by the receiver's known construction types. Only
     * POSITIVE evidence narrows: an empty intersection means the type facts
     * disagree with the override index, and the override index — the sound
     * superset — wins.
     */
    fun narrowByReceiverType(functionCanonical: String, receiver: String?, candidates: List<KirFunction>): List<KirFunction> {
        val known = knownTypes(functionCanonical, receiver)
        if (known.isEmpty()) return candidates
        val narrowed = candidates.filter { f ->
            val owner = f.enclosingClass ?: return@filter false
            known.any { it == owner || owner.startsWith("$it.") || it.endsWith(".$owner") || owner == it }
        }
        return narrowed.ifEmpty { candidates }
    }

    private val byCanonical: Map<String, List<KirFunction>> = compiled
        .groupBy { it.function.canonicalName }
        .mapValues { (_, fs) -> fs.map { it.function }.sortedBy { it.jvmDescriptor ?: "" } }

    /** Overridden symbol fqn -> workspace functions with bodies overriding it. */
    private val overriders: Map<String, List<KirFunction>> = compiled
        .flatMap { cf -> cf.function.overrides.map { it to cf.function } }
        .groupBy({ it.first }, { it.second })
        .mapValues { (_, fs) -> fs.sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" })) }

    /** Workspace classes the engine saw constructed: KirNew sites + constructor calls + singletons. */
    private val instantiatedClasses: Set<String> = buildSet {
        for (cf in compiled) {
            for (block in cf.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is KirNew -> addAll(canonicalClasses(ins.type))
                        is KirCall ->
                            if (ins.callee.kind == CallKind.CONSTRUCTOR) {
                                addAll(canonicalClasses(ins.callee.fqn))
                            } else {
                                {}
                            }
                        else -> {}
                    }
                }
            }
            val flags = cf.function.ownerFlags
            val owner = cf.function.enclosingClass
            if (owner != null && flags.any { it == "object" || it == "companion" || it == "enum" }) add(owner)
        }
    }

    /** A package-qualified type FQN matches the KIR's chain-form classes by suffix. */
    private fun canonicalClasses(typeFqn: String): List<String> =
        workspaceClasses.filter { typeFqn == it || typeFqn.endsWith(".$it") }

    /** Exact dispatch needs positive evidence — the P3 [isExact] rule. */
    private fun isExact(f: KirFunction): Boolean {
        if (f.enclosingClass == null) return true
        if ("final" in f.modifiers) return true
        if (f.visibility == "private") return true
        val flags = f.ownerFlags
        return flags.any { it == "final" || it == "object" || it == "companion" || it == "enum" }
    }

    private val usesRta: Boolean get() = dispatchMode == "rta" || dispatchMode == "vta" || dispatchMode == "auto"

    /**
     * Workspace functions whose bodies can execute at a call site. Static
     * kinds resolve exactly through the canonical index; virtual kinds join
     * the overriding bodies under the mode's narrowing. A constructor has no
     * summary to apply — an empty list is the honest answer, and the pack
     * (constructor sinks) has already matched before this is consulted.
     */
    fun targets(calleeFqn: String, descriptor: String?, kind: CallKind): List<KirFunction> {
        if (kind == CallKind.CONSTRUCTOR) return emptyList()
        val declared = byCanonical[calleeFqn].orEmpty().filter { it.body != null }
        val exact = declared.firstOrNull { descriptor != null && it.jvmDescriptor == descriptor }
            ?: declared.firstOrNull()
        if (kind != CallKind.VIRTUAL) {
            return listOfNotNull(exact)
        }
        if (exact != null && isExact(exact)) return listOf(exact)
        if (dispatchMode == "static" || dispatchMode == "none") return emptyList()
        val candidates = (overriders[calleeFqn].orEmpty() + listOfNotNull(exact))
            .filter { it.body != null }
            .distinctBy { it.canonicalName + "\u0000" + (it.jvmDescriptor ?: "") }
            .sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }))
        if (usesRta) {
            // Keep only targets whose owner the run saw instantiated; a class
            // with no constructor site and no singleton flag never executes.
            val ready = candidates.filter { it.enclosingClass == null || it.enclosingClass in instantiatedClasses }
            if (ready.isNotEmpty()) return ready
        }
        return candidates
    }
}

/**
 * Computes [FunctionSummary]s: Tarjan's SCC condensation of the call graph,
 * processed in reverse topological order (callees before callers), each SCC
 * iterated to a fixpoint — recursion converges, it does not bail out. A
 * budget caps the per-SCC iterations; a hit stamps the members' summaries
 * `recursive-approx` and is COUNTED over the SCC count (a cap without its
 * population is R25's shape).
 */
internal class Summarizer(
    private val compiledInOrder: List<CompiledFunction>,
    private val callIndex: CallIndex,
    private val pack: ModelPack,
    private val options: TaintEngine.Options,
) {
    class Result(
        val table: Map<String, FunctionSummary>,
        val sccsProcessed: Int,
        val sccIterationCapHits: Int,
        /** Functions whose summary was skipped: oversized body or state. */
        val skipped: Map<String, Int>,
    )

    private val byCanonical: Map<String, CompiledFunction> =
        compiledInOrder.associateBy { it.function.canonicalName }

    fun compute(): Result {
        val edges = HashMap<String, MutableSet<String>>()
        for (cf in compiledInOrder) {
            val out = edges.getOrPut(cf.function.canonicalName) { sortedSetOf() }
            for (block in cf.blocks) {
                for (ins in block.instructions) {
                    if (ins !is KirCall) continue
                    for (target in callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)) {
                        out.add(target.canonicalName)
                    }
                }
            }
        }
        val order = compiledInOrder.map { it.function.canonicalName }.sorted()
        val sccs = Tarjan.sccs(order, edges)

        val table = HashMap<String, FunctionSummary>()
        val skipped = sortedMapOf<String, Int>()
        var capHits = 0
        for (scc in sccs) {
            val members = scc.sorted()
            var changed = true
            var rounds = 0
            val hit = { capHits++ }
            while (changed) {
                if (rounds++ > options.summaryIterationBudget) {
                    hit()
                    break
                }
                changed = false
                for (member in members) {
                    val cf = byCanonical[member] ?: continue
                    // The same body budget the main analysis enforces — a
                    // function too big to analyse is too big to summarise.
                    val instructionCount = cf.sitesByBlock.values.sumOf { it.size }
                    if (instructionCount > options.maxFunctionInstructions) {
                        skipped.merge("summary-oversized-function", 1, Int::plus)
                        table.remove(member)
                        continue
                    }
                    val analysis = computeSummary(cf, table)
                    if (analysis.second) {
                        // The state exploded past the budget: publish NO
                        // summary rather than a partial one — callers then
                        // fall to the labelled unknown default instead of a
                        // silently truncated summary.
                        skipped.merge("summary-state-budget", 1, Int::plus)
                        table.remove(member)
                        continue
                    }
                    val next = analysis.first
                    val previous = table[member]
                    if (previous == null || !next.sameAs(previous)) {
                        table[member] = next
                        changed = true
                    }
                }
            }
            if (rounds > options.summaryIterationBudget) {
                // The last iterate is what callers saw: honest, but labelled.
                for (member in members) {
                    table[member]?.let { current ->
                        if (current.origin == SummaryOrigin.COMPUTED) {
                            table[member] = current.withOrigin(SummaryOrigin.RECURSIVE_APPROX)
                        }
                    }
                }
            }
        }
        return Result(table, sccs.size, capHits, skipped)
    }

    private fun FunctionSummary.withOrigin(origin: String): FunctionSummary = FunctionSummary(
        function, paramToReturn, paramToParam, paramFieldWrites, receiverWrites, sinkEffects,
        sourceReturns, sanitizes, invokedParams, origin,
    )

    /**
     * One summary iterate: the same forward, field-sensitive fixpoint the
     * main engine runs, seeded with a fact per parameter and driven by the
     * summary handler (pack entries first, then callee summaries, then the
     * unknown default). Escapes are recorded in the final sweep, at fixpoint.
     */
    private fun computeSummary(cf: CompiledFunction, table: Map<String, FunctionSummary>): Pair<FunctionSummary, Boolean> {
        val analysis = SummaryAnalysis(cf, table, callIndex, pack, options)
        analysis.run()
        return analysis.toSummary() to analysis.stateOverBudget
    }
}

/** Tarjan's SCC, iterative, over sorted adjacency for determinism. */
internal object Tarjan {

    fun sccs(nodes: List<String>, edges: Map<String, Set<String>>): List<List<String>> {
        val index = HashMap<String, Int>()
        val low = HashMap<String, Int>()
        val onStack = HashSet<String>()
        val stack = ArrayDeque<String>()
        val out = mutableListOf<List<String>>()
        var counter = 0
        for (root in nodes) {
            if (index.containsKey(root)) continue
            // (node, successor cursor) frame stack — no recursion.
            val frames = ArrayDeque<Pair<String, MutableIterator<String>>>()
            fun push(node: String) {
                index[node] = counter
                low[node] = counter
                counter++
                stack.addLast(node)
                onStack.add(node)
                frames.addLast(node to edges[node].orEmpty().toSortedSet().iterator())
            }
            push(root)
            while (frames.isNotEmpty()) {
                val (node, cursor) = frames.last()
                if (cursor.hasNext()) {
                    val next = cursor.next()
                    if (!index.containsKey(next)) {
                        push(next)
                    } else if (next in onStack) {
                        low[node] = minOf(low[node] ?: 0, index[next] ?: 0)
                    }
                } else {
                    frames.removeLast()
                    if (frames.isNotEmpty()) {
                        val parent = frames.last().first
                        low[parent] = minOf(low[parent] ?: 0, low[node] ?: 0)
                    }
                    if (low[node] == index[node]) {
                        val component = mutableListOf<String>()
                        while (true) {
                            val member = stack.removeLast()
                            onStack.remove(member)
                            component.add(member)
                            if (member == node) break
                        }
                        out.add(component)
                    }
                }
            }
        }
        return out
    }
}

/** Summary facts derive along field reads of their parameter roots only. */
internal object SummaryFactOps : FactOps<SummaryFact> {
    override fun categoryOf(fact: SummaryFact): String = fact.category

    override fun deriveOnFieldRead(fact: SummaryFact, suffix: String): SummaryFact? =
        fact.param?.let { fact.withPath(joinPath(fact.path, suffix)) }
}

internal fun joinPath(prefix: String, suffix: String): String =
    when {
        prefix.isEmpty() -> suffix
        suffix.isEmpty() -> prefix
        else -> "$prefix.$suffix"
    }

/**
 * The summary-mode analysis of one function. It is the ONE shared transfer
 * ([FlowTransfer]) over [SummaryFact]s — the reporting engine's transfer and
 * this one are the same function (R65); the summary's own work is in the
 * host callbacks: parameter seeds at entry, escape recording at sinks,
 * returns, field writes and invokes, and callee summary application.
 */
internal class SummaryAnalysis(
    private val cf: CompiledFunction,
    private val table: Map<String, FunctionSummary>,
    private val callIndex: CallIndex,
    pack: ModelPack,
    private val options: TaintEngine.Options,
) : TransferHost<SummaryFact, Boolean> {
    override val ops = SummaryFactOps
    override val pack = pack
    override val unknownCallPropagate = options.unknownCallPropagate
    override val fieldSensitive = options.accessPathDepth > 0

    private val chain = HashMap<ChainKey<SummaryFact>, Move>()
    private val state = FlowState<SummaryFact>()

    /** Upstream paths for facts born at summary applications inside this body. */
    private val upstream = HashMap<SummaryFact, List<Int>>()

    // ---- recorded escapes (the summary's content) --------------------------

    private val paramToReturn = sortedSetOf<Int>()
    private val paramToParam = HashMap<Int, MutableSet<Int>>()
    private val paramFieldWrites = HashMap<Int, MutableMap<Int, MutableSet<String>>>()
    private val receiverWrites = HashMap<Int, MutableSet<String>>()

    /** Records param i's taint stored into param [toParam]'s object at [suffix]. */
    private fun recordFieldWrite(fromParam: Int, toParam: Int, suffix: String) {
        paramFieldWrites.getOrPut(fromParam) { LinkedHashMap() }.getOrPut(toParam) { sortedSetOf() }.add(suffix)
        val receiverIndex = cf.function.params.indexOfFirst { it.receiver }
        if (toParam == receiverIndex) {
            receiverWrites.getOrPut(fromParam) { sortedSetOf() }.add(suffix)
        }
    }
    private val sinkEffects = LinkedHashMap<SummarySinkEffect, SummarySinkEffect>()

    /**
     * One witness per (param, sink site, category, argument, access path):
     * a recursive body produces a witness per unrolling, and publishing all
     * of them is N slices for ONE flow. The shortest path wins — the most
     * direct trace, and the value that STABILIZES under path truncation.
     */
    private fun recordEffect(effect: SummarySinkEffect) {
        val canonical = effect.copy(path = emptyList(), paramPath = effect.paramPath)
        val existing = sinkEffects[canonical]
        if (existing == null || effect.path.size < existing.path.size) {
            sinkEffects[canonical] = effect
        }
    }

    /** Caps a composed path at the trace budget, keeping the SINK end: the source side is re-anchored at slice build. */
    private fun stabilize(path: List<Int>): Pair<List<Int>, Boolean> =
        if (path.size > options.maxTraceNodes) path.takeLast(options.maxTraceNodes) to true else path to false
    private val sourceReturns = HashMap<String, MutableList<List<Int>>>()
    private val sanitizes = sortedSetOf<String>()
    private val invokedParams = sortedSetOf<Int>()

    private var capHit = false

    /**
     * True when the analysis state (registers x facts) blew past
     * [TaintEngine.Options.maxSummaryStateEntries]: real-repo functions can
     * push the summary state into gigabytes, and an OOM crash is the one
     * degradation worse than a missing summary. The summary is then dropped
     * entirely (callers fall to the labelled default), never partially
     * published.
     */
    var stateOverBudget: Boolean = false
        private set

    /** v-register -> parameter index, from the entry parameter stores. */
    private val paramAliases: Map<String, Int> = buildMap {
        val entryBlock = cf.blocks.firstOrNull() ?: return@buildMap
        for (ins in entryBlock.instructions) {
            if (ins !is KirStore) continue
            val paramIndex = cf.function.params.indexOfFirst { it.register == ins.value }
            if (paramIndex >= 0) put(ins.target, paramIndex)
        }
    }

    /** Register -> the parameter index it aliases through entry stores and assigns. */
    private fun paramIndexOf(register: String, depth: Int = 0): Int? {
        paramAliases[register]?.let { return it }
        cf.function.params.indexOfFirst { it.register == register }.takeIf { it >= 0 }?.let { return it }
        if (depth >= 3) return null
        // Follow one hop of assigns in program order.
        for (block in cf.blocks) {
            for (ins in block.instructions) {
                if (ins is io.cdxgen.kosi.kir.KirAssign && ins.result == register) {
                    return paramIndexOf(ins.source, depth + 1)
                }
            }
        }
        return null
    }

    fun run() {
        val transfer = FlowTransfer(this, chain)
        val fixpoint = transfer.runFixpoint(cf.blocks, cf.sitesByBlock, cf.successors, cf.predecessors)
        if (fixpoint == null) {
            stateOverBudget = true
            return
        }
        capHit = fixpoint.capHit
        // Final sweep at fixpoint: record every escape.
        for (block in cf.blocks) {
            val input = transfer.inputForBlock(block.id, fixpoint.outStates, cf.predecessors)
            transfer.transfer(cf.sitesByBlock.getValue(block.id), input, collect = true)
        }
    }

    companion object {
        /** The synthetic site of a parameter's birth move (filtered from paths). */
        const val ENTRY_SITE = -1
    }

    // ---- the TransferHost implementation ------------------------------------

    override fun birthFact(site: Int, category: String): SummaryFact = SummaryFact(null, site, category)

    override fun packMoveOrigin(): String? = null

    override fun onSourceApplied(fqn: String, site: Int, fact: SummaryFact, resultKey: TaintKey, collect: Boolean?) {}

    override fun onSanitizerCleared(cleared: List<String>, collect: Boolean?) {
        if (collect != true) return
        for (category in cleared) sanitizes.add(category)
    }

    override fun onPackPassthroughApplied(fqn: String, collect: Boolean?) {}

    override fun onSinkMatched(collect: Boolean?) {}

    override fun onResolvedCall(ins: KirCall, site: Int, collect: Boolean?) {
        // An invoke of a function-valued PARAMETER (`block(x)` lowers to
        // Function1.invoke with the value on the receiver) is a fact about
        // this summary regardless of what the pack says about Function1.
        if (collect != true) return
        val receiver = ins.receiver
        if (ins.callee.fqn.endsWith(".invoke") && receiver != null) {
            paramIndexOf(receiver)?.let { invokedParams.add(it) }
        }
    }

    override fun onSinkRead(
        sink: io.cdxgen.kosi.models.SinkPattern,
        fqn: String,
        site: Int,
        argIndex: Int,
        argKey: TaintKey,
        facts: Set<SummaryFact>,
        collect: Boolean?,
    ) {
        // Recorded in the collect sweep only: mid-fixpoint chains are
        // partial, and a summary must describe the converged body, not an
        // iterate.
        if (collect != true) return
        for (fact in facts) {
            if (fact.param == null) continue // a source-born fact at a sink is intraprocedural
            val raw = upstream[fact].orEmpty() + walkBack(fact, argKey)
            val (path, cut) = stabilize(raw)
            recordEffect(
                SummarySinkEffect(
                    paramIndex = fact.param,
                    paramPath = fact.path,
                    sinkSite = site,
                    sinkCalleeFqn = fqn,
                    sinkCategory = sink.category,
                    sinkSeverity = sink.severity,
                    sinkArgumentIndex = argIndex,
                    sinkAccessPath = argKey.render(),
                    path = path,
                    elided = cut,
                ),
            )
        }
    }

    override fun onEffectWritten(
        fqn: String,
        valueReg: String,
        receiverKey: TaintKey,
        facts: Set<SummaryFact>,
        site: Int,
        collect: Boolean?,
    ) {
        if (collect != true) return
        val toParam = paramIndexOf(receiverKey.base)
        for (fact in facts) {
            val from = fact.param ?: continue
            if (toParam != null) {
                recordFieldWrite(from, toParam, "[]")
            }
        }
    }

    override fun onFieldWriteEscape(
        receiver: String,
        valueReg: String,
        suffix: String,
        facts: Set<SummaryFact>,
        collect: Boolean?,
    ) {
        // A write into a PARAMETER's object is a summary ESCAPE: after the
        // call, the caller's argument object carries the written field's
        // taint. The receiver case (a member storing into `this`) is the
        // to-param = receiver index.
        if (collect != true) return
        val toParam = paramIndexOf(receiver) ?: return
        val fromParam = paramIndexOf(valueReg)
        for (fact in facts) {
            val from = fact.param ?: continue
            if (fromParam != null) {
                recordFieldWrite(from, toParam, suffix)
            }
        }
    }

    override fun onReturn(ins: KirReturn, site: Int, state: FlowState<SummaryFact>, collect: Boolean?) {
        if (collect != true) return
        if (ins.value != null) {
            val valueKey = TaintKey(ins.value!!, "")
            for (fact in state.factsOf(valueKey)) {
                val up = upstream[fact].orEmpty()
                val path = up + walkBack(fact, valueKey)
                when {
                    fact.param != null -> paramToReturn.add(fact.param!!)
                    fact.site != null -> sourceReturns.getOrPut(fact.category) { mutableListOf() }.add(path)
                }
            }
        }
        recordParamWrites(state)
    }

    override fun onDynamicCall(ins: KirDynamicCall, site: Int, collect: Boolean?) {
        // An invocation of a function-valued parameter is a fact about this
        // summary regardless of resolution.
        if (collect != true) return
        ins.receiver?.let { recv -> paramIndexOf(recv)?.let { invokedParams.add(it) } }
    }

    override fun onUnknownPropagation(collect: Boolean?) {}

    override fun entryBindings(): List<Pair<String, SummaryFact>> =
        cf.function.params.mapIndexed { index, param -> param.register to SummaryFact(index, null, "") }

    override fun entryBlockId(): String? = cf.blocks.firstOrNull()?.id

    override fun stateOverBudget(state: FlowState<SummaryFact>): Boolean =
        state.entryCount() > options.maxSummaryStateEntries

    /** Walks the provenance chain from [key] back to a birth move; forward site list. */
    private fun walkBack(fact: SummaryFact, key: TaintKey): List<Int> {
        val visited = HashSet<ChainKey<SummaryFact>>()
        val moves = mutableListOf<Move>()
        var current = key
        while (true) {
            if (!visited.add(ChainKey(fact, current))) {
                break
            }
            val move = chain[ChainKey(fact, current)] ?: break
            moves.add(move)
            if (move.prevKey == null) break
            current = move.prevKey
        }
        // The walk's site list; an effect with a cut path is still published,
        // and the SLICE built from it carries the elided marker and a
        // guaranteed source endpoint.
        return moves.map { it.site }.filter { it >= 0 }.reversed()
    }

    private fun moveChain(
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
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

    override fun applyCalleeSummaries(
        ins: KirCall,
        site: Int,
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
        collect: Boolean?,
    ): Boolean {
        val fqn = ins.callee.fqn
        val targets = callIndex.targets(fqn, ins.callee.descriptor, ins.callee.kind)
        if (targets.isEmpty()) {
            // No dispatch target: the shared unknown default runs.
            return false
        }
        val originByTarget = targets.associate { it.canonicalName to (table[it.canonicalName]?.origin ?: SummaryOrigin.COMPUTED) }
        for (target in targets) {
            val summary = table[target.canonicalName] ?: continue
            applySummary(summary, ins.receiver, ins.args, ins.result, site, originByTarget.getValue(target.canonicalName), state, chain)
        }
        return true
    }

    /**
     * Applies one callee summary in this body's context: parameter taint
     * moving to the result, to other parameters, into the receiver, reaching
     * sinks deeper down, and source-born taint returned. `thisReceiver` maps
     * a receiver-less call's implicit this to the analysed function's own
     * receiver so member-to-member effects compose.
     */
    private fun applySummary(
        summary: FunctionSummary,
        receiver: String?,
        args: List<String>,
        result: String?,
        site: Int,
        origin: String,
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
    ) {
        val params = summary.function.params
        val receiverIndex = params.indexOfFirst { it.receiver }
        fun mapping(index: Int): String? = when {
            receiverIndex >= 0 && index == 0 -> receiver ?: thisReceiver()
            receiverIndex >= 0 -> args.getOrNull(index - 1)
            else -> args.getOrNull(index)
        }

        fun reg(register: String): TaintKey = TaintKey(register, "")

        if (result != null) {
            val resultKey = reg(result)
            for (param in summary.paramToReturn.sorted()) {
                val from = mapping(param) ?: continue
                val fromKey = TaintKey(from, "")
                val facts = state.factsOf(fromKey)
                if (facts.isEmpty()) continue
                state.addFacts(resultKey, facts)
                for (fact in facts) {
                    chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "summary", origin)
                }
            }
            for ((category, path) in summary.sourceReturns) {
                val fact = SummaryFact(null, site, category)
                upstream[fact] = listOf(site) + path
                state.addFacts(resultKey, listOf(fact))
                chain[ChainKey(fact, resultKey)] = Move(site, null, "source-return", origin)
            }
        }
        if (summary.sinkEffects.isNotEmpty()) recordComposedSinkEffects(summary, receiver, args, site, state)
        for ((from, tos) in summary.paramToParam) {
            val fromReg = mapping(from) ?: continue
            for (to in tos.sorted()) {
                val toReg = mapping(to) ?: continue
                moveChain(state, chain, reg(fromReg), reg(toReg), site, "summary", null)
            }
        }
        for ((param, suffixes) in summary.receiverWrites) {
            if (receiverIndex < 0) continue
            val targetBase = receiver ?: thisReceiver() ?: continue
            val fromReg = mapping(param) ?: continue
            for (suffix in suffixes.sorted()) {
                moveChain(state, chain, reg(fromReg), TaintKey(targetBase, suffix), site, "summary", null)
            }
        }
    }

    private fun recordComposedSinkEffects(
        summary: FunctionSummary,
        receiver: String?,
        args: List<String>,
        site: Int,
        state: FlowState<SummaryFact>,
    ) {
        val params = summary.function.params
        val receiverIndex = params.indexOfFirst { it.receiver }
        fun mapping(index: Int): String? = when {
            receiverIndex >= 0 && index == 0 -> receiver ?: thisReceiver()
            receiverIndex >= 0 -> args.getOrNull(index - 1)
            else -> args.getOrNull(index)
        }
        for (effect in summary.sinkEffects.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }))) {
            val fromReg = mapping(effect.paramIndex) ?: continue
            val fromKey = TaintKey(fromReg, "")
            for (fact in state.factsOf(fromKey)) {
                if (fact.param == null) continue
                val raw = upstream[fact].orEmpty() + walkBack(fact, fromKey) + listOf(site) + effect.path
                val (path, cut) = stabilize(raw)
                recordEffect(
                    SummarySinkEffect(
                        paramIndex = fact.param,
                        paramPath = joinPath(fact.path, effect.paramPath),
                        sinkSite = effect.sinkSite,
                        sinkCalleeFqn = effect.sinkCalleeFqn,
                        sinkCategory = effect.sinkCategory,
                        sinkSeverity = effect.sinkSeverity,
                        sinkArgumentIndex = effect.sinkArgumentIndex,
                        sinkAccessPath = effect.sinkAccessPath,
                        path = path,
                        elided = effect.elided || cut,
                    ),
                )
            }
        }
    }

    /** The `this` register of the analysed function, when it has one. */
    private fun thisReceiver(): String? {
        val receiverParam = cf.function.params.firstOrNull { it.receiver } ?: return null
        return paramAliases.entries
            .firstOrNull { cf.function.params.getOrNull(it.value)?.receiver == true }?.key
            ?: receiverParam.register
    }

    /**
     * A parameter's fact sitting on a DIFFERENT parameter's register at an
     * exit is a WRITE EFFECT the caller must see: after the call, argument
     * j carries argument i's taint (`paramToParam`).
     */
    private fun recordParamWrites(state: FlowState<SummaryFact>) {
        for ((alias, paramIndex) in paramAliases) {
            for ((key, facts) in state.map) {
                if (key.base != alias) continue
                for (fact in facts) {
                    val from = fact.param ?: continue
                    if (from != paramIndex) {
                        paramToParam.getOrPut(from) { sortedSetOf() }.add(paramIndex)
                    }
                }
            }
        }
    }

    fun toSummary(): FunctionSummary = FunctionSummary(
        function = cf.function,
        paramToReturn = paramToReturn.toSet(),
        paramToParam = paramToParam.mapValues { it.value.toSet() },
        paramFieldWrites = paramFieldWrites.mapValues { (_, tos) -> tos.mapValues { it.value.toSet() } },
        receiverWrites = receiverWrites.mapValues { it.value.toSet() },
        sinkEffects = sinkEffects.keys.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }, { it.sinkCategory })),
        // Several witnesses per category can exist; the summary keeps the
        // shortest (deterministic tie-break: lexicographic) — the most
        // direct source-to-return trace.
        sourceReturns = sourceReturns.mapValues { (_, paths) ->
            paths.minWithOrNull(compareBy({ it.size }, { it.joinToString(",") })) ?: emptyList()
        }.filterValues { it.isNotEmpty() },
        sanitizes = sanitizes.toSet(),
        invokedParams = invokedParams.toSet(),
        origin = if (capHit) SummaryOrigin.RECURSIVE_APPROX else SummaryOrigin.COMPUTED,
    )
}

/**
 * Per-function register -> KirLambda definitions, used to resolve a
 * lambda-valued argument at a call site to the extracted body the summary
 * engine applies. Assignment copies are followed so `val f = { .. }; g(f)`
 * resolves too.
 */
internal fun lambdaDefsOf(cf: CompiledFunction): Map<String, String> {
    val defs = HashMap<String, String>()
    val assigns = HashMap<String, String>()
    for (block in cf.blocks) {
        for (ins in block.instructions) {
            when (ins) {
                is KirLambda -> defs[ins.result] = ins.function
                is io.cdxgen.kosi.kir.KirAssign -> assigns[ins.result] = ins.source
                else -> {}
            }
        }
    }
    val resolved = HashMap<String, String>()
    for ((reg, lambda) in defs) {
        resolved[reg] = lambda
        // Transitively name everything assignable to this lambda within a
        // small chain budget.
        var frontier = listOf(reg)
        var depth = 0
        while (frontier.isNotEmpty() && depth < 3) {
            depth++
            val next = mutableListOf<String>()
            for ((target, source) in assigns) {
                if (source in frontier && target !in resolved) {
                    resolved[target] = lambda
                    next.add(target)
                }
            }
            frontier = next
        }
    }
    return resolved
}

/** The lambda-capture binding of one extracted lambda at its creation site. */
internal fun lambdaCaptures(cf: CompiledFunction, functionCanonical: String): List<String> {
    for (block in cf.blocks) {
        for (ins in block.instructions) {
            if (ins is KirLambda && ins.function == functionCanonical) return ins.captures
        }
    }
    return emptyList()
}
