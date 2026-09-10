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
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirPhi
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirSafeCall
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirSuspendPoint
import io.cdxgen.kosi.kir.KirThrow
import io.cdxgen.kosi.kir.KirTypeCheck
import io.cdxgen.kosi.kir.uses
import io.cdxgen.kosi.models.ModelPack
import io.cdxgen.kosi.models.PatternMatcher

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

                        is KirAssign -> changed = propagate(ins.result, ins.source) || changed
                        is KirStore -> changed = propagate(ins.target, ins.value) || changed
                        is KirPhi -> for ((_, source) in ins.inputs) changed = propagate(ins.result, source) || changed
                        is KirElvis -> {
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

/**
 * The summary-mode analysis of one function. Facts are
 * [SummaryFact]s: `param` facts (a parameter's taint, no category — the
 * caller's categories travel over the channel at application time) and
 * `source` facts (born at a source call inside the body, category-carrying).
 */
internal class SummaryAnalysis(
    private val cf: CompiledFunction,
    private val table: Map<String, FunctionSummary>,
    private val callIndex: CallIndex,
    private val pack: ModelPack,
    private val options: TaintEngine.Options,
) {
    /**
     * A summary fact. [path] is the access path from the parameter root to
     * the value carrying this fact: seeds start at "", and a field READ of
     * the parameter's base extends it — so a sink reached through
     * `job.command` records paramPath "command", and the caller looks for
     * its taint on the SAME path of its own argument (field sensitivity at
     * the boundary, the clean-sibling negative preserved).
     */
    private data class SummaryFact(
        val param: Int?,
        val site: Int?,
        val category: String,
        val path: String = "",
    ) : Comparable<SummaryFact> {
        override fun compareTo(other: SummaryFact): Int =
            compareValuesBy(this, other, { it.param ?: -1 }, { it.site ?: -1 }, { it.category }, { it.path })

        fun withPath(newPath: String): SummaryFact = SummaryFact(param, site, category, newPath)
    }

    private data class ChainKey(val fact: SummaryFact, val key: TaintKey)

    /** Birth move kinds: a parameter's entry, a source call inside the body. */
    private val chain = HashMap<ChainKey, Move>()

    private val state = State()

    private class State {
        val map = java.util.TreeMap<TaintKey, java.util.TreeSet<SummaryFact>>()

        fun factsOf(key: TaintKey): java.util.TreeSet<SummaryFact> = map[key] ?: EMPTY

        fun setFacts(key: TaintKey, facts: java.util.TreeSet<SummaryFact>) {
            if (facts.isEmpty()) map.remove(key) else map[key] = facts
        }

        fun addFacts(key: TaintKey, facts: Collection<SummaryFact>) {
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

        fun mergeFrom(other: State) {
            for ((key, facts) in other.map) addFacts(key, facts)
        }

        companion object {
            private val EMPTY = java.util.TreeSet<SummaryFact>()
        }
    }

    /** Upstream paths for facts born at summary applications inside this body. */
    private val upstream = HashMap<SummaryFact, List<Int>>()

    // ---- recorded escapes (the summary's content) --------------------------

    private val paramToReturn = sortedSetOf<Int>()
    private val paramToParam = HashMap<Int, MutableSet<Int>>()
    private val paramFieldWrites = HashMap<Int, MutableMap<Int, MutableSet<String>>>()
    private val receiverWrites = HashMap<Int, MutableSet<String>>()

    /**
     * A parameter-root fact sitting on a receiver's BASE register models the
     * object itself; reading a FIELD of that object yields the value at
     * fact.path + suffix. Without this, `fun sink(job: Job) =
     * ProcessBuilder(job.command)` never sees the parameter's taint (it
     * lives on the base) — and with a BLIND base read, the clean-sibling
     * negative would die, because `job.label` would read the same taint.
     * The synthesized fact carries the EXTENDED path, so the effect records
     * exactly which field was sunk.
     */
    private fun synthesizeFieldRead(receiver: String, suffix: String, result: String, site: Int) {
        if (suffix.isEmpty()) return
        val baseKey = reg(receiver)
        val resultKey = reg(result)
        val rooted = state.factsOf(baseKey).filter { it.param != null }
        if (rooted.isEmpty()) return
        for (fact in rooted) {
            val derived = fact.withPath(joinPath(fact.path, suffix))
            state.addFacts(resultKey, listOf(derived))
            chain[ChainKey(derived, resultKey)] = Move(site, baseKey, "field")
        }
    }

    private fun joinPath(prefix: String, suffix: String): String =
        when {
            prefix.isEmpty() -> suffix
            suffix.isEmpty() -> prefix
            else -> "$prefix.$suffix"
        }

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
                if (ins is KirAssign && ins.result == register) {
                    return paramIndexOf(ins.source, depth + 1)
                }
            }
        }
        return null
    }

    fun run() {
        // Entry state: one fact per parameter, born at the (synthetic) entry
        // move so every later move's provenance walk terminates here. It is
        // JOINTED INTO the entry block's input on every pass — the entry
        // block may also carry loop predecessors, and the seeds must
        // survive both; seeding `state` directly would be erased by the
        // next transfer's copy of its input.
        val entryState = State()
        for ((index, param) in cf.function.params.withIndex()) {
            val fact = SummaryFact(index, null, "")
            val key = TaintKey(param.register, "")
            entryState.addFacts(key, listOf(fact))
            chain[ChainKey(fact, key)] = Move(ENTRY_SITE, null, "param")
        }
        val entryBlockId = cf.blocks.first().id
        val blocks = cf.blocks
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
            val input = joinPredecessors(blockId, outStates)
            if (blockId == entryBlockId) input.mergeFrom(entryState)
            val output = transfer(cf.sitesByBlock.getValue(blockId), input)
            var entries = 0
            for ((key, facts) in output.map) {
                entries += 1 + facts.size
                if (entries > options.maxSummaryStateEntries) break
            }
            if (entries > options.maxSummaryStateEntries) {
                stateOverBudget = true
                break
            }
            val previous = outStates[blockId]
            if (previous == null || output.map != previous.map) {
                outStates[blockId] = output
                for (succ in cf.successors[blockId].orEmpty()) {
                    if (queued.add(succ)) work.addLast(succ)
                }
            }
        }
        if (stateOverBudget) return
        // Final sweep at fixpoint: record every escape.
        for (block in blocks) {
            val input = joinPredecessors(block.id, outStates)
            if (block.id == entryBlockId) input.mergeFrom(entryState)
            transfer(cf.sitesByBlock.getValue(block.id), input, collect = true)
        }
    }

    companion object {
        /** The synthetic site of a parameter's birth move (filtered from paths). */
        const val ENTRY_SITE = -1
    }

    private fun joinPredecessors(blockId: String, outStates: Map<String, State>): State {
        val joined = State()
        for (pred in cf.predecessors[blockId].orEmpty()) {
            outStates[pred]?.let { joined.mergeFrom(it) }
        }
        return joined
    }

    private fun fieldSuffix(path: AccessPath?): String =
        if (options.accessPathDepth <= 0 || path == null) {
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

    private fun reg(register: String): TaintKey = TaintKey(register, "")

    private fun moveAll(from: TaintKey, to: TaintKey, site: Int, kind: String, replace: Boolean) {
        val facts = state.factsOf(from)
        if (facts.isEmpty()) {
            if (replace) state.removeKey(to)
            return
        }
        if (replace) state.setFacts(to, java.util.TreeSet(facts)) else state.addFacts(to, facts)
        for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind)
    }

    private fun joinInto(result: String, operands: List<String>, site: Int, kind: String) {
        val merged = java.util.TreeSet<SummaryFact>()
        val origin = HashMap<SummaryFact, TaintKey>()
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

    private fun transfer(sites: List<Site>, input: State, collect: Boolean = false): State {
        val state = this.state
        state.map.clear()
        for ((key, facts) in input.map) state.map[key] = java.util.TreeSet(facts)

        for (site in sites) {
            when (val ins = site.ins) {
                is KirAssign -> moveAll(reg(ins.source), reg(ins.result), site.id, "assign", replace = true)
                is KirStore -> moveAll(reg(ins.value), reg(ins.target), site.id, "assign", replace = true)
                is KirLoad -> state.removeKey(reg(ins.result))
                is KirNew -> state.removeKey(reg(ins.result))
                is KirLambda -> state.removeKey(reg(ins.result))
                is KirTypeCheck -> state.removeKey(reg(ins.result))
                is KirStringConcat -> joinInto(ins.result, ins.parts, site.id, "concat")
                is KirPhi -> joinInto(ins.result, ins.inputs.values.toList(), site.id, "phi")
                is KirElvis -> joinInto(ins.result, listOf(ins.value, ins.fallback), site.id, "elvis")
                is KirCast -> moveAll(reg(ins.value), reg(ins.result), site.id, "assign", replace = true)
                is KirFieldGet -> {
                    moveAll(TaintKey(ins.receiver, fieldSuffix(ins.path)), reg(ins.result), site.id, "field", replace = true)
                    synthesizeFieldRead(ins.receiver, fieldSuffix(ins.path), ins.result, site.id)
                }
                is KirSafeCall -> {
                    moveAll(TaintKey(ins.receiver, fieldSuffix(ins.path)), reg(ins.result), site.id, "field", replace = true)
                    synthesizeFieldRead(ins.receiver, fieldSuffix(ins.path), ins.result, site.id)
                }
                is KirFieldSet -> {
                    val targetKey = TaintKey(ins.receiver, fieldSuffix(ins.path))
                    moveAll(reg(ins.value), targetKey, site.id, "field", replace = false)
                    // A write into a PARAMETER's object is a summary ESCAPE:
                    // after the call, the caller's argument object carries
                    // the written field's taint. The receiver case (a member
                    // storing into `this`) is the to-param = receiver index.
                    if (collect) {
                        val toParam = paramIndexOf(ins.receiver) ?: continue
                        val fromParam = paramIndexOf(ins.value)
                        for (fact in state.factsOf(reg(ins.value))) {
                            val from = fact.param ?: continue
                            if (fromParam != null) {
                                recordFieldWrite(from, toParam, fieldSuffix(ins.path))
                            }
                        }
                    }
                }
                is KirIndexGet -> {
                    val elementKey = TaintKey(ins.receiver, if (options.accessPathDepth > 0) "[]" else "")
                    val wholeKey = reg(ins.receiver)
                    // Per-fact blame, as in the reporting engine (R62).
                    val merged = java.util.TreeSet<SummaryFact>()
                    val blame = HashMap<SummaryFact, TaintKey>()
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
                    moveAll(reg(ins.value), TaintKey(ins.receiver, if (options.accessPathDepth > 0) "[]" else ""), site.id, "index", replace = false)

                is KirSuspendPoint -> {
                    // A suspend boundary is transparent to a MAY analysis:
                    // the value crossing it is the value the call produced,
                    // and coroutine suspension does not launder taint. Not an
                    // omission — the P6 report counts how many slices cross
                    // these boundaries, which requires them to persist.
                    state.removeKey(reg(ins.result))
                }

                is KirBranch, is KirThrow -> {}
                is KirReturn -> {
                    if (collect) {
                        if (ins.value != null) {
                            val valueKey = reg(ins.value!!)
                            for (fact in state.factsOf(valueKey)) {
                                val up = upstream[fact].orEmpty()
                                val path = up + walkBack(fact, valueKey)
                                when {
                                    fact.param != null -> paramToReturn.add(fact.param)
                                    fact.site != null -> sourceReturns.getOrPut(fact.category) { mutableListOf() }.add(path)
                                }
                            }
                        }
                        recordParamWrites()
                    }
                }

                is KirCall -> handleCall(ins, site, collect)
                is KirDynamicCall -> {
                    // An invocation of a function-valued parameter is a fact
                    // about this summary regardless of resolution.
                    if (collect) {
                        ins.receiver?.let { recv -> paramIndexOf(recv)?.let { invokedParams.add(it) } }
                    }
                    handleUnknown(ins.result, ins.receiver, ins.args, site.id)
                }
            }
        }
        // A COPY: outStates keeps per-block states, and this.state is reused
        // by the next transfer call — returning the live object would alias
        // every stored state to one mutating map.
        return state.copy()
    }

    /** The `this` register of the analysed function, when it has one. */
    private fun thisReceiver(): String? {
        val receiverParam = cf.function.params.firstOrNull { it.receiver } ?: return null
        return paramAliases.entries
            .firstOrNull { cf.function.params.getOrNull(it.value)?.receiver == true }?.key
            ?: receiverParam.register
    }

    /** Walks the provenance chain from [key] back to a birth move; forward site list. */
    private fun walkBack(fact: SummaryFact, key: TaintKey): List<Int> {
        val visited = HashSet<ChainKey>()
        val moves = mutableListOf<Move>()
        var elided = false
        var current = key
        while (true) {
            if (!visited.add(ChainKey(fact, current))) {
                elided = true
                break
            }
            val move = chain[ChainKey(fact, current)] ?: break
            moves.add(move)
            if (move.prevKey == null) break
            current = move.prevKey
        }
        // The walk's site list; `elided` is remembered by the caller's
        // effect only when the walk never reached a birth move — an effect
        // with a cut path is still published, and the SLICE built from it
        // carries the elided marker and a guaranteed source endpoint.
        return moves.map { it.site }.filter { it >= 0 }.reversed()
    }

    private fun handleCall(ins: KirCall, site: Site, collect: Boolean) {
        val fqn = ins.callee.fqn
        val result = ins.result
        val receiver = ins.receiver

        // An invoke of a function-valued PARAMETER (`block(x)` lowers to
        // Function1.invoke with the value on the receiver) is a fact about
        // this summary regardless of what the pack says about Function1.
        if (collect && fqn.endsWith(".invoke") && receiver != null) {
            paramIndexOf(receiver)?.let { invokedParams.add(it) }
        }

        fun registerAt(index: Int): String? {
            if (index < 0) return null
            return if (receiver != null) {
                if (index == 0) receiver else ins.args.getOrNull(index - 1)
            } else {
                ins.args.getOrNull(index)
            }
        }

        var matched = false

        // SINK first, on the pre-call state. Recorded in the collect sweep
        // only: mid-fixpoint chains are partial, and a summary must describe
        // the converged body, not an iterate.
        val sink = pack.sinks.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sink != null && collect) {
            matched = true
            for (argIndex in sink.relevantArguments.sorted()) {
                val register = registerAt(argIndex) ?: continue
                val argKey = TaintKey(register, "")
                for (fact in state.factsOf(argKey)) {
                    if (fact.param == null) continue // a source-born fact at a sink is intraprocedural
                    val raw = upstream[fact].orEmpty() + walkBack(fact, argKey)
                    val (path, cut) = stabilize(raw)
                    recordEffect(
                        SummarySinkEffect(
                            paramIndex = fact.param,
                            paramPath = fact.path,
                            sinkSite = site.id,
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
        } else if (sink != null) {
            matched = true
        }

        // SOURCE: a category-carrying fact born here.
        val source = pack.sources.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (source != null && result != null) {
            matched = true
            val fact = SummaryFact(null, site.id, source.category)
            val resultKey = TaintKey(result, "")
            state.addFacts(resultKey, listOf(fact))
            chain[ChainKey(fact, resultKey)] = Move(site.id, null, "source")
        }

        // SANITIZER: clears the named categories on the result only.
        val sanitizer = pack.sanitizers.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (sanitizer != null && result != null) {
            matched = true
            val resultKey = TaintKey(result, "")
            val remaining = state.factsOf(resultKey).filter { it.category !in sanitizer.clears }
            if (remaining.size != state.factsOf(resultKey).size) {
                for (category in sanitizer.clears) sanitizes.add(category)
            }
            state.setFacts(resultKey, java.util.TreeSet(remaining))
        }

        // PASSTHROUGH.
        val passthrough = pack.passthroughs.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (passthrough != null) {
            matched = true
            for (flow in passthrough.flows) {
                if (flow.size < 2) continue
                val from = registerAt(flow[0])
                val to = if (flow[1] == -1) result else registerAt(flow[1])
                if (from == null || to == null) continue
                moveChain(TaintKey(from, ""), TaintKey(to, ""), site.id, "call")
            }
            for (flow in passthrough.elementFlows) {
                if (flow.size < 2) continue
                val to = if (flow[1] == -1) result else registerAt(flow[1])
                val fromReceiver = receiver ?: continue
                if (to == null) continue
                moveChain(
                    TaintKey(fromReceiver, if (options.accessPathDepth > 0) "[]" else ""),
                    TaintKey(to, ""),
                    site.id,
                    "call",
                )
            }
        }

        // EFFECT: argument taint into the receiver's element state.
        val effect = pack.effects.firstOrNull { PatternMatcher.matches(it.pattern, fqn) }
        if (effect != null && receiver != null) {
            matched = true
            for (writeIndex in effect.writesToArguments) {
                if (writeIndex <= 0) continue
                val register = registerAt(writeIndex) ?: continue
                moveChain(
                    TaintKey(register, ""),
                    TaintKey(receiver, if (options.accessPathDepth > 0) "[]" else ""),
                    site.id,
                    "effect",
                )
                if (collect) {
                    val toParam = paramIndexOf(receiver)
                    for (fact in state.factsOf(TaintKey(register, ""))) {
                        val from = fact.param ?: continue
                        if (toParam != null) {
                            recordFieldWrite(from, toParam, "[]")
                        }
                    }
                }
            }
        }

        if (matched) {
            // Pack entries stay authoritative: a matched call applies no
            // summary. Escape records that DO apply here: the pack sink above
            // already recorded param escapes; nothing else carries a summary.
            return
        }

        // Summary application: the JOIN of the dispatch targets' summaries.
        val targets = callIndex.targets(fqn, ins.callee.descriptor, ins.callee.kind)
        if (targets.isEmpty()) {
            handleUnknown(result, receiver, ins.args, site.id)
            return
        }
        val originByTarget = targets.associate { it.canonicalName to (table[it.canonicalName]?.origin ?: SummaryOrigin.COMPUTED) }
        for (target in targets) {
            val summary = table[target.canonicalName] ?: continue
            applySummary(summary, receiver, ins.args, result, site, originByTarget.getValue(target.canonicalName))
        }
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
        site: Site,
        origin: String,
    ) {
        val params = summary.function.params
        val receiverIndex = params.indexOfFirst { it.receiver }
        fun mapping(index: Int): String? = when {
            receiverIndex >= 0 && index == 0 -> receiver ?: thisReceiver()
            receiverIndex >= 0 -> args.getOrNull(index - 1)
            else -> args.getOrNull(index)
        }

        if (result != null) {
            val resultKey = reg(result)
            for (param in summary.paramToReturn.sorted()) {
                val from = mapping(param) ?: continue
                val fromKey = TaintKey(from, "")
                val facts = state.factsOf(fromKey)
                if (facts.isEmpty()) continue
                state.addFacts(resultKey, facts)
                for (fact in facts) {
                    chain[ChainKey(fact, resultKey)] = Move(site.id, fromKey, "summary", origin)
                }
            }
            for ((category, path) in summary.sourceReturns) {
                val fact = SummaryFact(null, site.id, category)
                upstream[fact] = listOf(site.id) + path
                state.addFacts(resultKey, listOf(fact))
                chain[ChainKey(fact, resultKey)] = Move(site.id, null, "source-return", origin)
            }
        }
        if (summary.sinkEffects.isNotEmpty()) recordComposedSinkEffects(summary, receiver, args, site)
        for ((from, tos) in summary.paramToParam) {
            val fromReg = mapping(from) ?: continue
            for (to in tos.sorted()) {
                val toReg = mapping(to) ?: continue
                moveChain(TaintKey(fromReg, ""), TaintKey(toReg, ""), site.id, "summary")
            }
        }
        for ((param, suffixes) in summary.receiverWrites) {
            if (receiverIndex < 0) continue
            val targetBase = receiver ?: thisReceiver() ?: continue
            val fromReg = mapping(param) ?: continue
            for (suffix in suffixes.sorted()) {
                moveChain(TaintKey(fromReg, ""), TaintKey(targetBase, suffix), site.id, "summary")
            }
        }
    }

    private fun recordComposedSinkEffects(summary: FunctionSummary, receiver: String?, args: List<String>, site: Site) {
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
                val raw = upstream[fact].orEmpty() + walkBack(fact, fromKey) + listOf(site.id) + effect.path
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

    private fun moveChain(from: TaintKey, to: TaintKey, site: Int, kind: String) {
        val facts = state.factsOf(from)
        if (facts.isEmpty()) return
        state.addFacts(to, facts)
        for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind)
    }

    private fun handleUnknown(result: String?, receiver: String?, args: List<String>, site: Int) {
        if (result == null) return
        if (!options.unknownCallPropagate) {
            state.removeKey(reg(result))
            return
        }
        val resultKey = reg(result)
        val incoming = java.util.TreeSet<SummaryFact>()
        // Per-fact blame, as in the reporting engine (R62).
        val blame = HashMap<SummaryFact, TaintKey>()
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
        state.addFacts(resultKey, incoming)
        for (fact in incoming) {
            chain[ChainKey(fact, resultKey)] = Move(site, blame.getValue(fact), "propagate", SummaryOrigin.DEFAULT)
        }
    }

    /**
     * A parameter's fact sitting on a DIFFERENT parameter's register at an
     * exit is a WRITE EFFECT the caller must see: after the call, argument
     * j carries argument i's taint (`paramToParam`).
     */
    private fun recordParamWrites() {
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
                is KirAssign -> assigns[ins.result] = ins.source
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
