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
 *   bytecode         — the fixpoint ran over a dependency jar's lowered
 *                      class file (P9, `--deps`);
 *   recursive-approx — the SCC hit its iteration budget and this is the
 *                      last iterate;
 *   default          — the `--unknown-call` fallback, no body was seen.
 */
object SummaryOrigin {
    const val COMPUTED = "computed"
    const val PACK = "pack"
    const val BYTECODE = "bytecode"
    const val RECURSIVE_APPROX = "recursive-approx"
    const val DEFAULT = "default"
}

/**
 * P22 §1: the identity of one function in every map the flow engine keeps.
 * A canonical name is the package-and-member path with no descriptor, so
 * Kotlin overloads share one — R133's fold lost a verdict to a namesake
 * through exactly such a key, and this module's summary table answered one
 * overload's question with another's by the same spelling (`associateBy`
 * kept the LAST overload and never summarised the rest). The descriptor
 * makes the pair unique for every declared function (the JVM forbids two
 * methods of one class sharing name and descriptor); extracted lambdas have
 * none, and the lowering names them uniquely per module (KirLowering's
 * module-wide ordinal).
 */
internal fun functionKey(f: KirFunction): String = f.canonicalName + "\u0000" + (f.jvmDescriptor ?: "")

/** The key of a function known by name only (a lambda's canonical). */
internal fun functionKeyByName(canonicalName: String): String = canonicalName + "\u0000"

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
 * P24 §2c: taint born at a source INSIDE the callee and stored into one of
 * its parameters' objects — `fun taint(job: Job) { job.command = readLine()
 * }`. The caller must see the write on its own argument's field after the
 * call. [path] is the walk from the source site to the field write, for
 * trace stitching.
 */
internal data class SourceFieldWrite(
    val paramIndex: Int,
    val suffix: String,
    val path: List<Int>,
)

/**
 * P24 §2d: what a function passes when it invokes a function-valued
 * parameter — the channel that lets a passed lambda's body consume taint
 * that never leaves the callee. `block(raw)` records, for the invoked
 * parameter and each argument position, WHERE the argument's taint came
 * from: [fromParam] (my parameter i, at [fromParamPath]) or a source born
 * in me at [sourceSite] carrying [category]. [path] is the walk from the
 * birth to the invoke site, for trace stitching.
 */
internal data class InvokeBind(
    val invokedParam: Int,
    val argIndex: Int,
    val fromParam: Int?,
    val fromParamPath: String,
    val category: String?,
    val sourceSite: Int?,
    val path: List<Int>,
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
    /**
     * P24 §3: witness path per returning parameter — the callee-internal
     * sites the boundary move stitches past, so the frame list names the
     * hops the value took (and the RETURN frame exists at all).
     */
    val paramToReturnPaths: Map<Int, List<Int>> = emptyMap(),
    /**
     * P24 §2: parameter i's object FIELD reaches the return's same field —
     * `fun get(raw: String) = Session(token = raw)` returned and read as
     * `session.token`. The base-key channel ([paramToReturn]) could not say
     * this: the fact lives at (param, "token"), which the return probe at
     * the bare key never saw, so an object carrying taint in a field lost it
     * the moment it crossed back to the caller.
     */
    val paramToReturnFields: Map<Int, Set<String>> = emptyMap(),
    /** P24 §3: witness path per field-channel return, keyed `param\u0000suffix`. */
    val paramToReturnFieldPaths: Map<String, List<Int>> = emptyMap(),
    /** P24 §2c: source-born field writes into parameters' objects. */
    val sourceFieldWrites: Map<String, List<SourceFieldWrite>> = emptyMap(),
    /** P24 §2d: what the body passes when it invokes function-valued parameters. */
    val invokedBinds: List<InvokeBind> = emptyList(),
) {
    fun sameAs(other: FunctionSummary): Boolean =
        paramToReturn == other.paramToReturn &&
            paramToParam == other.paramToParam &&
            paramFieldWrites == other.paramFieldWrites &&
            receiverWrites == other.receiverWrites &&
            sinkEffects == other.sinkEffects &&
            sourceReturns == other.sourceReturns &&
            sanitizes == other.sanitizes &&
            invokedParams == other.invokedParams &&
            // P24: the new channels are compared by their STRUCTURE — which
            // effects exist — never by their witness PATHS. Two bodies
            // declared under one function key (the corpus's duplicated
            // framework stubs) compute the same effects with different site
            // ids; comparing paths made `sameAs` flip every SCC round, and
            // ten stubs came out `recursive-approx` on the merged tree for
            // no semantic difference at all. A witness is a presentation of
            // an effect, chosen deterministically by the last writer.
            paramToReturnPaths.keys == other.paramToReturnPaths.keys &&
            paramToReturnFields == other.paramToReturnFields &&
            paramToReturnFieldPaths.keys == other.paramToReturnFieldPaths.keys &&
            sourceFieldWrites.mapValues { (_, w) -> w.mapTo(sortedSetOf()) { "${it.paramIndex}\u0000${it.suffix}" } } ==
                other.sourceFieldWrites.mapValues { (_, w) -> w.mapTo(sortedSetOf()) { "${it.paramIndex}\u0000${it.suffix}" } } &&
            invokedBinds.map { Triple(it.invokedParam, it.argIndex, it.fromParam ?: it.category) }.toSet() ==
                other.invokedBinds.map { Triple(it.invokedParam, it.argIndex, it.fromParam ?: it.category) }.toSet()

    /**
     * The may-analysis union with [other]: every effect either summary has,
     * the joined summary has. Used where a consumer can only name the
     * FUNCTION (the deps tier's FQN lookups), never one overload — the
     * honest answer to "what can this name do" is the union, not whichever
     * overload a map happened to keep last (P22 §1). Sorted/merged fields
     * keep the join commutative and deterministic.
     */
    fun join(other: FunctionSummary): FunctionSummary = FunctionSummary(
        function = function,
        paramToReturn = paramToReturn + other.paramToReturn,
        paramToParam = mergeSets(paramToParam, other.paramToParam),
        paramFieldWrites = mergeWith(paramFieldWrites, other.paramFieldWrites) { a, b -> mergeSets(a, b) },
        receiverWrites = mergeSets(receiverWrites, other.receiverWrites),
        sinkEffects = (sinkEffects + other.sinkEffects).sortedWith(
            compareBy({ it.paramIndex }, { it.paramPath }, { it.sinkSite }, { it.sinkCalleeFqn }, { it.sinkArgumentIndex }, { it.sinkAccessPath }),
        ),
        // NOT a union: this value is a WITNESS PATH, not a set of effects.
        // `recordSourceReturn` prepends it verbatim to the published slice's
        // trace, so unioning two overloads' paths (the P22 review's R138 —
        // `(a + b).distinct().sorted()`) fabricated a trace out of sites
        // interleaved from two different bodies, ordered by site id: a walk
        // no execution can take, published as evidence. Every other field
        // here is a set and unions soundly; a witness can only be CHOSEN.
        // The choice is the rule `toSummary` already uses when one body
        // offers several witnesses for a category — the shortest, ties
        // broken lexicographically — so the joined path is always a real
        // path of a real overload.
        sourceReturns = mergeWith(sourceReturns, other.sourceReturns) { a, b ->
            listOf(a, b).minWithOrNull(compareBy({ it.size }, { it.joinToString(",") }))!!
        },
        sanitizes = sanitizes + other.sanitizes,
        invokedParams = invokedParams + other.invokedParams,
        // P24: the new channels are effect sets with witness paths — the
        // paths are CHOSEN per canonical key (shortest, lexicographic
        // tie-break), the same rule `toSummary` applies. Unioning two
        // witnesses would fabricate a walk no execution takes (R138).
        paramToReturnPaths = mergeWitnesses(paramToReturnPaths, other.paramToReturnPaths),
        paramToReturnFields = mergeSets(paramToReturnFields, other.paramToReturnFields),
        paramToReturnFieldPaths = mergeWitnesses(paramToReturnFieldPaths, other.paramToReturnFieldPaths),
        sourceFieldWrites = mergeWith(sourceFieldWrites, other.sourceFieldWrites) { a, b ->
            (a + b)
                .groupBy { it.paramIndex to it.suffix }
                .map { (_, writes) -> writes.minWithOrNull(compareBy({ it.path.size }, { it.path.joinToString(",") }))!! }
                .sortedWith(compareBy({ it.paramIndex }, { it.suffix }))
        },
        invokedBinds = run {
            (invokedBinds + other.invokedBinds)
                .groupBy { Triple(it.invokedParam, it.argIndex, it.fromParam ?: -(it.sourceSite ?: -1)) }
                .map { (_, binds) -> binds.minWithOrNull(compareBy({ it.path.size }, { it.path.joinToString(",") }))!! }
                .sortedWith(compareBy({ it.invokedParam }, { it.argIndex }, { it.fromParam ?: -1 }, { it.sourceSite ?: -1 }))
        },
        // The join answers name-keyed lookups, and the only name-keyed
        // consumer is the deps tier, whose summaries uniformly carry
        // `bytecode` — so the joined origin is this one's.
        origin = origin,
    )

    /** One shortest witness per key, chosen (never unioned — R138). */
    private fun <K> mergeWitnesses(a: Map<K, List<Int>>, b: Map<K, List<Int>>): Map<K, List<Int>> {
        val out = HashMap(a)
        for ((key, path) in b) {
            val existing = out[key]
            out[key] = if (existing == null || path.size < existing.size ||
                (path.size == existing.size && path.joinToString(",") < existing.joinToString(","))
            ) {
                path
            } else {
                existing
            }
        }
        return out
    }

    private fun <K, V> mergeSets(into: Map<K, Set<V>>, other: Map<K, Set<V>>): Map<K, Set<V>> {
        val out = HashMap(into)
        for ((k, v) in other) out[k] = out[k]?.let { it + v } ?: v
        return out
    }

    private fun <K, V> mergeWith(into: Map<K, V>, other: Map<K, V>, merge: (V, V) -> V): Map<K, V> {
        val out = HashMap(into)
        for ((k, v) in other) out[k] = out[k]?.let { merge(it, v) } ?: v
        return out
    }

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
            paramToReturnFields = paramToReturnFields.entries
                .sortedWith(compareBy({ it.key }, { it.value.firstOrNull() ?: "" }))
                .flatMap { (param, suffixes) -> suffixes.sorted().map { "${pid(param)}.${it}" } },
            sourceFieldWrites = sourceFieldWrites.entries
                .sortedWith(compareBy({ it.key }, { it.value.firstOrNull()?.paramIndex ?: 0 }, { it.value.firstOrNull()?.suffix ?: "" }))
                .flatMap { (category, writes) -> writes.sortedWith(compareBy({ it.paramIndex }, { it.suffix })).map { "${pid(it.paramIndex)}.${it.suffix}:${category}" } },
            invokes = invokedBinds.sortedWith(compareBy({ it.invokedParam }, { it.argIndex }, { it.fromParam ?: -1 }, { it.sourceSite ?: -1 })).map { bind ->
                val from = bind.fromParam?.let { pid(it) } ?: "source:${bind.category}"
                "${pid(bind.invokedParam)}(arg${bind.argIndex})<-$from"
            },
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
     * candidate set; unknown never narrows. Keyed by [functionKey], not the
     * canonical name: overloads share a name, and an `associate` here kept
     * the LAST overload's type facts and answered the other's VTA question
     * with them (the P22 §1 sweep's second instance of R133's shape).
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
        functionKey(cf.function) to types
    }

    /** A package-qualified receiver type narrows to chain-form classes by suffix. */
    private fun knownTypes(fn: KirFunction, receiver: String?): Set<String> {
        if (receiver == null) return emptySet()
        val raw = registerTypesByFunction[functionKey(fn)]?.get(receiver).orEmpty()
        if (raw.isEmpty()) return emptySet()
        return raw.flatMap { type -> canonicalClasses(type) }.toSet()
    }

    /**
     * Narrows [candidates] by the receiver's known construction types. Only
     * POSITIVE evidence narrows: an empty intersection means the type facts
     * disagree with the override index, and the override index — the sound
     * superset — wins.
     */
    fun narrowByReceiverType(fn: KirFunction, receiver: String?, candidates: List<KirFunction>): List<KirFunction> {
        val known = knownTypes(fn, receiver)
        if (known.isEmpty()) return candidates
        val narrowed = candidates.filter { f ->
            val owner = f.enclosingClass ?: return@filter false
            known.any { it == owner || owner.startsWith("$it.") || it.endsWith(".$owner") || owner == it }
        }
        return narrowed.ifEmpty { candidates }
    }

    /**
     * Overload candidates by canonical name — the value is the LIST of every
     * overload with that name, so the non-unique key is the point: a call
     * site names an FQN, and narrowing to one body is [targets]' job on
     * descriptor/exactness evidence, never the index's (P22 §1 sweep: the
     * key is correct exactly because nothing reads it as one function).
     */
    private val byCanonical: Map<String, List<KirFunction>> = compiled
        .groupBy { it.function.canonicalName }
        .mapValues { (_, fs) -> fs.map { it.function }.sortedBy { it.jvmDescriptor ?: "" } }

    /**
     * Overridden symbol fqn -> workspace functions with bodies overriding it.
     * The key names a SYMBOL, not one function, and the value is the list of
     * every overrider — a dispatch candidate set, never one body (P22 §1
     * sweep).
     */
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
    /**
     * The origin stamped on every summary this run computes: `computed` for
     * the workspace tier, `bytecode` for the `--deps` tier (P9) — the label
     * the promotion gate reads, so a jar-derived summary is never mistaken
     * for a workspace one.
     */
    private val originLabel: String = SummaryOrigin.COMPUTED,
    /**
     * The P9 `--deps` tier, when present: workspace call sites whose callees
     * resolve to no workspace function look up dependency summaries here, so
     * a workspace summary composes the effects of a call that enters a jar.
     */
    private val deps: TaintEngine.DepsTier? = null,
) {
    class Result(
        /** Keyed by [functionKey]: one summary per FUNCTION, never per name. */
        val table: Map<String, FunctionSummary>,
        val sccsProcessed: Int,
        val sccIterationCapHits: Int,
        /** Functions whose summary was skipped: oversized body or state. */
        val skipped: Map<String, Int>,
        /** The diagnostic code whose budget stopped the run early, when one did. */
        val stoppedBy: String? = null,
        /** Composed param paths the depth cap dropped (exact drops; P16 §2). */
        val composedPathDrops: Int = 0,
    )

    /**
     * All overloads by [functionKey]. Before P22 this was `associateBy`
     * canonical name — it kept the LAST overload and the other overloads
     * were never summarised at all, while the table's one name-keyed entry
     * answered every overload's call sites with that namesake's effects:
     * a missed flow in one direction (the constant overload's empty summary
     * swallowed the tainted one's) and a confident wrong one in the other.
     */
    private val byKey: Map<String, List<CompiledFunction>> =
        compiledInOrder.groupBy { functionKey(it.function) }

    fun compute(): Result {
        // P24 §2b: constructor call edges. `CallIndex.targets` answers empty
        // for CONSTRUCTOR calls (a constructor has no dispatch), so the SCC
        // graph had NO edge from a constructor call site to the synthesised
        // `<init>` body — the caller's SCC could converge before the
        // constructor was ever summarised, and the field-write channel was
        // order-dependent (Box.<init> happened to sort first; Session.<init>
        // did not). The edge resolves the same way the application does: by
        // the class's `<init>` name.
        val constructorKeysByName = compiledInOrder
            .filter { it.function.canonicalName.endsWith(".<init>") }
            .groupBy { it.function.canonicalName }
            .mapValues { (_, cfs) -> cfs.map { functionKey(it.function) }.sorted() }
        val edges = HashMap<String, MutableSet<String>>()
        for (cf in compiledInOrder) {
            val out = edges.getOrPut(functionKey(cf.function)) { sortedSetOf() }
            for (block in cf.blocks) {
                for (ins in block.instructions) {
                    if (ins !is KirCall) continue
                    if (ins.callee.kind == io.cdxgen.kosi.kir.CallKind.CONSTRUCTOR) {
                        constructorKeysByName[ins.callee.fqn + ".<init>"]?.let { out.addAll(it) }
                        continue
                    }
                    for (target in callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)) {
                        out.add(functionKey(target))
                    }
                }
            }
        }
        val order = compiledInOrder.map { functionKey(it.function) }.sorted()
        val sccs = Tarjan.sccs(order, edges)

        val table = HashMap<String, FunctionSummary>()
        val skipped = sortedMapOf<String, Int>()
        var capHits = 0
        var composedPathDrops = 0
        var stoppedBy: String? = null
        for (scc in sccs) {
            // The P10 budget is checked between SCCs: a trip keeps every
            // summary already converged and ships them, and the run says so.
            options.shouldStop?.invoke()?.let {
                stoppedBy = it
                break
            }
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
                // P24: several bodies can share one function key (the
                // corpus's duplicated framework stubs - and, since the
                // primary-constructor synthesis, their `<init>`s with
                // genuinely DIFFERENT parameter lists). The round's answer
                // for a key is the may-UNION of its bodies (an effect any
                // body has is an effect the key carries), REPLACED by the
                // next round's union - never accumulated with it, which
                // composes a recursive member's effects into itself and
                // grows without bound.
                val roundBodies = HashMap<String, FunctionSummary>()
                for (member in members) {
                    for (cf in byKey[member].orEmpty()) {
                        // The same body budget the main analysis enforces — a
                        // function too big to analyse is too big to summarise.
                        val instructionCount = cf.sitesByBlock.values.sumOf { it.size }
                        if (instructionCount > options.maxFunctionInstructions) {
                            skipped.merge("summary-oversized-function", 1, Int::plus)
                            table.remove(member)
                            continue
                        }
                        val analysis = computeSummary(cf, table)
                        composedPathDrops += analysis.composedPathDrops
                        if (analysis.overBudget) {
                            // The state or the escape set exploded past its
                            // budget: publish NO summary rather than a partial
                            // one — callers then fall to the labelled unknown
                            // default instead of a silently truncated summary.
                            skipped.merge(analysis.overBudgetLabel, 1, Int::plus)
                            table.remove(member)
                            // P16 §2 measurement aid: name the functions the
                            // degradation touches, on stderr, only under
                            // KOSI_TRACE — a number without names invited nobody
                            // to ask what the budget cost.
                            if (!System.getenv("KOSI_TRACE").isNullOrBlank() && analysis.overBudgetLabel == "summary-effect-budget") {
                                System.err.println("TRACE: summary-effect-budget dropped $member")
                            }
                            continue
                        }
                        val next = analysis.summary
                        roundBodies[member] = roundBodies[member]?.join(next) ?: next
                    }
                    roundBodies.remove(member)?.let { union ->
                        val previous = table[member]
                        if (previous == null || !union.sameAs(previous)) {
                            table[member] = union
                            changed = true
                        }
                    }
                }
            }
            if (rounds > options.summaryIterationBudget) {
                // The last iterate is what callers saw: honest, but labelled
                // — on the WORKSPACE tier. The `--deps` tier keeps
                // `origin=bytecode` (the PRODUCER the gate reads; flipping it
                // would hide which summaries come from jars at all): its
                // approximation stays visible in sccIterationCapHits over
                // sccsProcessed, which the tier publishes.
                if (originLabel == SummaryOrigin.COMPUTED) {
                    for (member in members) {
                        table[member]?.let { current ->
                            if (current.origin == SummaryOrigin.COMPUTED) {
                                table[member] = current.withOrigin(SummaryOrigin.RECURSIVE_APPROX)
                            }
                        }
                    }
                }
            }
        }
        return Result(table, sccs.size, capHits, skipped, stoppedBy, composedPathDrops)
    }

    private fun FunctionSummary.withOrigin(origin: String): FunctionSummary = FunctionSummary(
        function, paramToReturn, paramToParam, paramFieldWrites, receiverWrites, sinkEffects,
        sourceReturns, sanitizes, invokedParams, origin,
        paramToReturnPaths, paramToReturnFields, paramToReturnFieldPaths, sourceFieldWrites, invokedBinds,
    )

    /**
     * One summary iterate: the same forward, field-sensitive fixpoint the
     * main engine runs, seeded with a fact per parameter and driven by the
     * summary handler (pack entries first, then callee summaries, then the
     * unknown default). Escapes are recorded in the final sweep, at fixpoint.
     * Returns the summary, the over-budget LABEL (which budget tripped),
     * whether any budget tripped — a tripped budget drops the summary whole —
     * and how many composed paths the depth cap dropped (P16 §2).
     */
    private class SummaryOutcome(
        val summary: FunctionSummary,
        val overBudgetLabel: String,
        val overBudget: Boolean,
        val composedPathDrops: Int,
    )

    private fun computeSummary(cf: CompiledFunction, table: Map<String, FunctionSummary>): SummaryOutcome {
        val analysis = SummaryAnalysis(cf, table, callIndex, pack, options, originLabel, deps)
        analysis.run()
        return SummaryOutcome(analysis.toSummary(), analysis.overBudgetLabel, analysis.stateOverBudget, analysis.composedPathDrops)
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
    /** The origin this tier's summaries carry (`computed`, or `bytecode` for the `--deps` tier). */
    private val originLabel: String = SummaryOrigin.COMPUTED,
    /** The P9 `--deps` tier, for call sites whose callee lives in a jar. */
    private val deps: TaintEngine.DepsTier? = null,
) : TransferHost<SummaryFact, Boolean> {
    override val ops = SummaryFactOps
    override val pack = pack
    override val unknownCallPropagate = options.unknownCallPropagate
    override val fieldSensitive = options.accessPathDepth > 0
    override fun aliasClass(register: String): Set<String> = aliases.aliasClass(register)
    override fun lambdaTargets(register: String): List<String> = aliases.lambdaTargets(register)

    /**
     * One summary lookup for a call site: the dispatch targets' summaries
     * joined per effect is the CALLER's job; here a single named summary is
     * enough for the alias feed (constructor field writes, param returns).
     * Constructors resolve by `<init>` name — the call site's descriptor is
     * the constructor-CALL shape, which no declared `<init>` matches.
     */
    private fun summaryForCall(ins: KirCall): FunctionSummary? {
        if (ins.callee.kind == io.cdxgen.kosi.kir.CallKind.CONSTRUCTOR) {
            val key = functionKeyByName(ins.callee.fqn + ".<init>")
            val overloads = table.keys.filter { it == key || it.substringBefore('\u0000') == ins.callee.fqn + ".<init>" }
            // May-union across the class's constructor overloads: the site
            // cannot narrow by descriptor, so every overload's writes hold.
            var joined: FunctionSummary? = null
            for (k in overloads.sorted()) {
                val s = table[k] ?: continue
                joined = if (joined == null) s else joined.join(s)
            }
            return joined
        }
        val targets = callIndex.targets(ins.callee.fqn, ins.callee.descriptor, ins.callee.kind)
        var joined: FunctionSummary? = null
        for (target in targets) {
            val s = table[functionKey(target)] ?: continue
            joined = if (joined == null) s else joined.join(s)
        }
        return joined
    }

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

    /** P24 §3: witness paths for returning parameters (the callee's hops). */
    private val paramToReturnPaths = HashMap<Int, MutableList<List<Int>>>()

    /** P24 §2: parameter-object FIELDS reaching the return's same field. */
    private val paramToReturnFields = HashMap<Int, MutableSet<String>>()

    /** P24 §3: witness paths for the field channel, keyed `param\u0000suffix`. */
    private val paramToReturnFieldPaths = HashMap<String, MutableList<List<Int>>>()

    /** P24 §2c: source-born field writes into parameters' objects. */
    private val sourceFieldWrites = HashMap<String, MutableList<SourceFieldWrite>>()

    /** P24 §2d: what the body passes when it invokes function-valued parameters. */
    private val invokedBinds = LinkedHashMap<String, InvokeBind>()

    /**
     * P24 §2: the function's alias classes — computed once per analysis from
     * the CFG and the CURRENT summary table (the table's paramToReturn feeds
     * it; each iterate's aliases are therefore deterministic in the
     * iterate).
     */
    private val aliases: AliasAnalysis by lazy {
        AliasAnalysis(cf) { ins -> summaryForCall(ins) }.also { it.run() }
    }

    /**
     * One witness per (param, sink site, category, argument, access path):
     * a recursive body produces a witness per unrolling, and publishing all
     * of them is N slices for ONE flow. The shortest path wins — the most
     * direct trace, and the value that STABILIZES under path truncation.
     *
     * P15 bounds, both applied before the map grows:
     * 1. A composed `paramPath` deeper than [paramPathCap] — the deepest
     *    path the LOWERING can put on a fact key — is DROPPED, exactly. At
     *    application time the caller looks up
     *    `TaintKey(register, effect.paramPath)`, so an effect whose path no
     *    key can spell never matches a fact, in either engine. This was the
     *    fuel of the P15 explosion: composing
     *    FragmentManagerImpl's recursive cluster appended another
     *    `.mActive.mChildFragmentManager...` segment per iteration
     *    (depth 8 -> 15 while the cap is 6), every deeper join a NEW map
     *    key, 8k entries -> 68M in one function.
     * 2. The map itself is budgeted like the state (R58): past
     *    [TaintEngine.Options.maxSummarySinkEffects] entries the summary is
     *    marked over-budget and dropped WHOLE by the Summarizer — callers
     *    fall to the labelled unknown default; a partial escape set is
     *    never published.
     */
    private fun recordEffect(effect: SummarySinkEffect) {
        if (paramPathDepth(effect.paramPath) > paramPathCap) {
            // P16 §2: the drop is EXACT (an effect deeper than the deepest
            // fact-key path can never match one), but until now it was also
            // invisible — a degradation nobody could count. The run publishes
            // the per-run total as `composed-path-depth` in
            // stats.truncations, so the cap's cost is a number every report
            // carries, not an assumption.
            composedPathDrops++
            return
        }
        if (sinkEffects.size >= options.maxSummarySinkEffects) {
            stateOverBudget = true
            overBudgetLabel = "summary-effect-budget"
            return
        }
        val canonical = effect.copy(path = emptyList(), paramPath = effect.paramPath)
        val existing = sinkEffects[canonical]
        if (existing == null || effect.path.size < existing.path.size) {
            sinkEffects[canonical] = effect
        }
    }

    /**
     * The deepest path a FACT KEY can carry, which is what an effect's
     * `paramPath` is looked up against. It is set by the LOWERING, not by
     * `Options.accessPathDepth` (which only switches field sensitivity on
     * and off — nothing truncates a key to it): every key path renders one
     * [AccessPath], and `AccessPath.of` keeps at most
     * [AccessPath.DEFAULT_DEPTH] elements and appends `*` when it cuts. So
     * `job.a.b.c.d.e.f` is the key `a.b.c.d.e.*` — SIX segments, formable
     * on both sides of a call — and capping at the option's 5 dropped that
     * escape and lost the flow with it (pinned by
     * `aCollapsedAccessPathEscapeStillFiresAcrossTheBoundary`). Deeper than
     * this is unformable, so dropping it is exact; composition only ever
     * makes a path longer, so dropping early is monotone-safe.
     */
    private val paramPathCap: Int = AccessPath.DEFAULT_DEPTH + 1

    private fun paramPathDepth(path: String): Int = if (path.isEmpty()) 0 else path.count { it == '.' } + 1

    /** Caps a composed path at the trace budget, keeping the SINK end: the source side is re-anchored at slice build. */
    private fun stabilize(path: List<Int>): Pair<List<Int>, Boolean> =
        if (path.size > options.maxTraceNodes) path.takeLast(options.maxTraceNodes) to true else path to false
    private val sourceReturns = HashMap<String, MutableList<List<Int>>>()
    private val sanitizes = sortedSetOf<String>()
    private val invokedParams = sortedSetOf<Int>()

    private var capHit = false

    /**
     * True when the analysis state (registers x facts) blew past
     * [TaintEngine.Options.maxSummaryStateEntries], or the escape set past
     * [TaintEngine.Options.maxSummarySinkEffects]: real-repo functions can
     * push either into gigabytes, and an OOM crash is the one degradation
     * worse than a missing summary. The summary is then dropped entirely
     * (callers fall to the labelled default), never partially published.
     */
    var stateOverBudget: Boolean = false
        private set

    /** Which budget tripped — the skipped-count label the run publishes. */
    var overBudgetLabel: String = "summary-state-budget"
        private set

    /** Composed param paths dropped by [paramPathCap] in this analysis (P16 §2). */
    var composedPathDrops: Int = 0
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

    override fun onSanitizerCleared(fqn: String, cleared: List<String>, collect: Boolean?) {
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
            when {
                fact.param != null -> {
                    if (fromParam != null) {
                        recordFieldWrite(fromParam, toParam, suffix)
                    }
                }

                // P24 §2c: taint born at a SOURCE inside me, stored into a
                // parameter's object — the caller's argument carries the
                // write after the call. Before this arm the fact was
                // skipped (`fact.param ?: continue`), which is exactly the
                // shape the probe's case 9 missed.
                fact.site != null -> {
                    val path = upstream[fact].orEmpty() + walkBack(fact, TaintKey(valueReg, ""))
                    sourceFieldWrites.getOrPut(fact.category) { mutableListOf() }
                        .add(SourceFieldWrite(toParam, suffix, path))
                }
            }
        }
    }

    override fun onReturn(ins: KirReturn, site: Int, state: FlowState<SummaryFact>, collect: Boolean?) {
        if (collect != true) return
        if (ins.value != null) {
            // P24 §2: a fact sitting on a FIELD of the returned object is a
            // field-channel return: the caller's argument's field reaches
            // the result's field. The bare-key probe below cannot see it,
            // and the scan is ALIAS-AWARE — the object may be named by any
            // register of its class (`val second = first; return second`).
            val returnBases = aliases.aliasClass(ins.value!!)
            for ((key, facts) in state.map) {
                if (key.base !in returnBases || key.path.isEmpty()) continue
                for (fact in facts) {
                    if (fact.param != null) {
                        paramToReturnFields.getOrPut(fact.param!!) { sortedSetOf() }.add(key.path)
                        val walk = upstream[fact].orEmpty() + walkBack(fact, key) + listOf(site)
                        paramToReturnFieldPaths.getOrPut("${fact.param}\u0000${key.path}") { mutableListOf() }.add(walk)
                    }
                }
            }
            val valueKey = TaintKey(ins.value!!, "")
            for (fact in state.factsOf(valueKey)) {
                val up = upstream[fact].orEmpty()
                val path = up + walkBack(fact, valueKey)
                when {
                    fact.param != null -> {
                        paramToReturn.add(fact.param!!)
                        // P24 §3: the witness path, ending at the RETURN
                        // instruction — the hop a boundary move splices in,
                        // and the only producer of a `return` frame.
                        paramToReturnPaths.getOrPut(fact.param!!) { mutableListOf() }
                            .add(path + listOf(site))
                    }

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
        // guaranteed source endpoint. P24 §3: boundary moves splice their
        // callee-internal witness sites in, so composed paths (a chain of
        // paramToReturn applications) name every level's hops.
        return moves.reversed()
            .flatMap { it.viaSites + listOf(it.site) }
            .filter { it >= 0 }
    }

    private fun moveChain(
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
        from: TaintKey,
        to: TaintKey,
        site: Int,
        kind: String,
        origin: String?,
    ): Boolean = moveChainVia(state, chain, from, to, site, kind, origin, emptyList())

    private fun moveChainVia(
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
        from: TaintKey,
        to: TaintKey,
        site: Int,
        kind: String,
        origin: String?,
        via: List<Int>,
    ): Boolean {
        val facts = state.factsOf(from)
        if (facts.isEmpty()) return false
        state.addFacts(to, facts)
        for (fact in facts) chain[ChainKey(fact, to)] = Move(site, from, kind, origin, via)
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

        // P24 §2d: a call THROUGH a function value whose target this body
        // knows — a lambda defined here (`val f = { .. }; f(x)`) or captured
        // from an enclosing one. The function value is an abstract object
        // whose target is known at its allocation site; the invoke applies
        // that body's summary with the invoke's arguments bound to its
        // value parameters and its captures to the allocation-site
        // registers.
        if (ins.callee.fqn.endsWith(".invoke") && ins.receiver != null) {
            val applied = applyLambdaInvoke(ins, site, state, chain, collect)
            if (applied) return true
        }

        // P24 §2b: a constructor call applies the class's `<init>` summary
        // with the NEW OBJECT as the receiver — the constructor is a
        // function that writes the object's fields, and its parameter field
        // writes are what make `Job(tainted)` taint `job.command`.
        if (ins.callee.kind == io.cdxgen.kosi.kir.CallKind.CONSTRUCTOR) {
            val ctor = summaryForCall(ins)
            if (ctor != null) {
                applySummary(ctor, ins.result, ins.args, ins.result, site, ctor.origin, state, chain)
                return true
            }
            return false
        }

        val targets = callIndex.targets(fqn, ins.callee.descriptor, ins.callee.kind)
        // Keyed by FUNCTION, not name: a descriptor-narrowed call site must
        // meet its own overload's summary, never a namesake's (P22 §1).
        val applicable = targets.mapNotNull { target -> table[functionKey(target)] }
        if (applicable.isEmpty()) {
            // P24 §2d: an invoke of a function-valued PARAMETER records what
            // this body PASSES — the channel the caller completes by binding
            // the lambda it passed. Without it, `block(raw)` inside me is a
            // fact about `block` only, and the lambda body's sinks can never
            // fire on taint that never leaves me.
            if (collect == true && ins.callee.fqn.endsWith(".invoke") && ins.receiver != null) {
                recordInvokeBinds(ins, site, state)
            }
            // No WORKSPACE summary applies here — the same condition the
            // taint host uses before it consults the tier, so a call site
            // that reaches a jar in one engine reaches it in the other. A
            // constructor callee simply misses: the lowerer never emits
            // `<init>` into the tier, so no carve-out is needed for it.
            // P9: a workspace function whose body passes taint THROUGH a
            // dependency method must record the composed effect in its own
            // summary, exactly as it does for a workspace callee.
            val dep = deps?.summaries(ins.callee.fqn)
            if (dep != null) {
                applySummary(dep, ins.receiver, ins.args, ins.result, site, dep.origin, state, chain)
                return true
            }
            // With no dispatch target either, the shared unknown default runs.
            return targets.isNotEmpty()
        }
        if (collect == true && ins.callee.fqn.endsWith(".invoke") && ins.receiver != null) {
            recordInvokeBinds(ins, site, state)
        }
        for (summary in applicable) {
            applySummary(summary, ins.receiver, ins.args, ins.result, site, summary.origin, state, chain)
        }
        return true
    }

    /**
     * Records [InvokeBind]s for an invoke of a function-valued parameter:
     * for each argument carrying facts, WHERE the taint came from (one of my
     * parameters, or a source born in me) and the walk to the invoke site.
     */
    private fun recordInvokeBinds(ins: KirCall, site: Int, state: FlowState<SummaryFact>) {
        val receiver = ins.receiver ?: return
        val invokedParam = paramIndexOf(receiver) ?: return
        invokedParams.add(invokedParam)
        for ((argIndex, arg) in ins.args.withIndex()) {
            for (fact in state.factsOf(TaintKey(arg, ""))) {
                val path = upstream[fact].orEmpty() + walkBack(fact, TaintKey(arg, ""))
                val bind = when {
                    fact.param != null -> InvokeBind(
                        invokedParam = invokedParam,
                        argIndex = argIndex,
                        fromParam = fact.param,
                        fromParamPath = fact.path,
                        category = null,
                        sourceSite = null,
                        path = path + listOf(site),
                    )

                    fact.site != null -> InvokeBind(
                        invokedParam = invokedParam,
                        argIndex = argIndex,
                        fromParam = null,
                        fromParamPath = "",
                        category = fact.category,
                        sourceSite = fact.site,
                        path = path + listOf(site),
                    )

                    else -> null
                } ?: continue
                val canonical = "${bind.invokedParam}\u0000${bind.argIndex}\u0000" +
                    "${bind.fromParam ?: -(bind.sourceSite ?: -1)}"
                val existing = invokedBinds[canonical]
                if (existing == null || bind.path.size < existing.path.size) {
                    invokedBinds[canonical] = bind
                }
            }
        }
    }

    /**
     * A call through a function value with a KNOWN target: applies the
     * lambda body's summary here. Returns false when the receiver holds no
     * known lambda (an invoke on a parameter keeps its summary channel).
     */
    private fun applyLambdaInvoke(
        ins: KirCall,
        site: Int,
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
        collect: Boolean?,
    ): Boolean {
        val targets = aliases.lambdaTargets(ins.receiver!!)
        if (targets.isEmpty()) return false
        var applied = false
        for (canonical in targets) {
            val lambdaSummary = table[functionKeyByName(canonical)] ?: continue
            val captured = lambdaCaptures(cf, canonical)
            // The extracted body's parameters are its captures followed by
            // its value parameters; the invoke's arguments bind the latter.
            fun binding(index: Int): String? =
                if (index < captured.size) captured[index] else ins.args.getOrNull(index - captured.size)
            applySummaryWith(lambdaSummary, ::binding, ins.result, site, lambdaSummary.origin, state, chain)
            applied = true
        }
        return applied
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
        applySummaryWith(summary, ::mapping, result, site, origin, state, chain)
    }

    /**
     * The shared application over an explicit PARAMETER BINDING — the
     * call-site mapping, or the captures-plus-arguments mapping of an invoke
     * through a known lambda (P24 §2d).
     */
    private fun applySummaryWith(
        summary: FunctionSummary,
        binding: (Int) -> String?,
        result: String?,
        site: Int,
        origin: String,
        state: FlowState<SummaryFact>,
        chain: HashMap<ChainKey<SummaryFact>, Move>,
    ) {
        fun reg(register: String): TaintKey = TaintKey(register, "")

        if (result != null) {
            val resultKey = reg(result)
            for (param in summary.paramToReturn.sorted()) {
                val from = binding(param) ?: continue
                val fromKey = TaintKey(from, "")
                val facts = state.factsOf(fromKey)
                if (facts.isEmpty()) continue
                state.addFacts(resultKey, facts)
                // P24 §3: the callee-internal witness splices into the
                // boundary move, so the frame list names the hops the value
                // took inside the callee — and the return.
                val via = summary.paramToReturnPaths[param].orEmpty()
                for (fact in facts) {
                    chain[ChainKey(fact, resultKey)] = Move(site, fromKey, "summary", origin, via)
                }
            }
            for ((category, path) in summary.sourceReturns) {
                val fact = SummaryFact(null, site, category)
                upstream[fact] = listOf(site) + path
                state.addFacts(resultKey, listOf(fact))
                chain[ChainKey(fact, resultKey)] = Move(site, null, "source-return", origin)
            }
            // P24 §2: the field channel — the callee stored param i's
            // VALUE into the returned object's field (`Session(token =
            // raw)`), so the argument's BASE taint reaches the result's
            // FIELD.
            for ((param, suffixes) in summary.paramToReturnFields) {
                val from = binding(param) ?: continue
                for (suffix in suffixes.sorted()) {
                    val via = summary.paramToReturnFieldPaths["$param\u0000$suffix"].orEmpty()
                    moveChainVia(state, chain, TaintKey(from, ""), TaintKey(result, suffix), site, "summary", origin, via)
                }
            }
        }

        // P24 §2c: source-born FIELD WRITES — taint born inside the callee
        // and stored into parameter i's object lands on my argument's field.
        for ((category, writes) in summary.sourceFieldWrites) {
            for (write in writes.sortedWith(compareBy({ it.paramIndex }, { it.suffix }))) {
                val toReg = binding(write.paramIndex) ?: continue
                for (base in aliases.aliasClass(toReg).sorted()) {
                    val fact = SummaryFact(null, site, category)
                    upstream[fact] = listOf(site) + write.path
                    state.addFacts(TaintKey(base, write.suffix), listOf(fact))
                    chain[ChainKey(fact, TaintKey(base, write.suffix))] = Move(site, null, "source-field-write", origin)
                }
            }
        }

        if (summary.sinkEffects.isNotEmpty()) recordComposedSinkEffects(summary, binding, site, state)
        for ((from, tos) in summary.paramToParam) {
            val fromReg = binding(from) ?: continue
            for (to in tos.sorted()) {
                val toReg = binding(to) ?: continue
                moveChain(state, chain, reg(fromReg), reg(toReg), site, "summary", null)
            }
        }
        for ((param, suffixes) in summary.receiverWrites) {
            val fromReg = binding(param) ?: continue
            // The write lands on the RECEIVER's object — under every name
            // the caller gave it (P24 §2's alias fan-out). The receiver is
            // the summary's parameter 0 when it declares one; a receiver-less
            // summary has no receiverWrites to apply.
            val receiverReg = if (summary.function.params.any { it.receiver }) binding(0) else null
            val targetBases = receiverReg?.let { aliases.aliasClass(it) } ?: emptySet()
            for (suffix in suffixes.sorted()) {
                for (base in targetBases.sorted()) {
                    moveChain(state, chain, reg(fromReg), TaintKey(base, suffix), site, "summary", null)
                }
            }
        }

        // P24 §2d: the callee invokes a function-valued parameter and my
        // body supplied the function value: compose — if the invoked
        // parameter binds to one of MY parameters, the bind becomes mine
        // (what I pass when I invoke MY parameter); a source-born bind
        // composes its path through the call site.
        for (bind in summary.invokedBinds) {
            val invokedReg = binding(bind.invokedParam) ?: continue
            val myInvokedParam = paramIndexOf(invokedReg) ?: continue
            invokedParams.add(myInvokedParam)
            when {
                bind.fromParam != null -> {
                    val sourceReg = binding(bind.fromParam) ?: continue
                    val mySourceParam = paramIndexOf(sourceReg) ?: continue
                    recordBind(
                        InvokeBind(
                            invokedParam = myInvokedParam,
                            argIndex = bind.argIndex,
                            fromParam = mySourceParam,
                            fromParamPath = bind.fromParamPath,
                            category = null,
                            sourceSite = null,
                            path = listOf(site) + bind.path,
                        ),
                    )
                }

                bind.category != null -> recordBind(
                    InvokeBind(
                        invokedParam = myInvokedParam,
                        argIndex = bind.argIndex,
                        fromParam = null,
                        fromParamPath = "",
                        category = bind.category,
                        sourceSite = bind.sourceSite,
                        path = listOf(site) + bind.path,
                    ),
                )
            }
        }
    }

    private fun recordBind(bind: InvokeBind) {
        val canonical = "${bind.invokedParam}\u0000${bind.argIndex}\u0000" +
            "${bind.fromParam ?: -(bind.sourceSite ?: -1)}"
        val existing = invokedBinds[canonical]
        if (existing == null || bind.path.size < existing.path.size) {
            invokedBinds[canonical] = bind
        }
    }



    private fun recordComposedSinkEffects(
        summary: FunctionSummary,
        binding: (Int) -> String?,
        site: Int,
        state: FlowState<SummaryFact>,
    ) {
        for (effect in summary.sinkEffects.sortedWith(compareBy({ it.paramIndex }, { it.sinkSite }))) {
            val fromReg = binding(effect.paramIndex) ?: continue
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
        // P22 §0's elided-trace fixture caught this: the dedup map's KEYS
        // are the path-STRIPPED canonicals, so publishing `.keys` discarded
        // every composed site path at the publish boundary — an
        // interprocedural slice's callee-internal trace was structurally
        // empty, `stabilize` could never cut (paths restarted empty at
        // every level), and a composed trace longer than the trace cap was
        // unrepresentable: the measured `partial` population of zero was
        // this defect, not shallowness. Publish the VALUES — one
        // shortest-path witness per canonical — under a comparator that
        // covers every field, so the order stays total and deterministic.
        sinkEffects = sinkEffects.values.sortedWith(
            compareBy(
                { it.paramIndex },
                { it.sinkSite },
                { it.sinkCategory },
                { it.paramPath },
                { it.sinkArgumentIndex },
                { it.sinkAccessPath },
                { it.path.joinToString(",") },
                { it.elided },
            ),
        ),
        // Several witnesses per category can exist; the summary keeps the
        // shortest (deterministic tie-break: lexicographic) — the most
        // direct source-to-return trace.
        sourceReturns = sourceReturns.mapValues { (_, paths) ->
            paths.minWithOrNull(compareBy({ it.size }, { it.joinToString(",") })) ?: emptyList()
        }.filterValues { it.isNotEmpty() },
        sanitizes = sanitizes.toSet(),
        invokedParams = invokedParams.toSet(),
        paramToReturnPaths = paramToReturnPaths.mapValues { (_, paths) ->
            paths.minWithOrNull(compareBy({ it.size }, { it.joinToString(",") })) ?: emptyList()
        }.filterValues { it.isNotEmpty() },
        paramToReturnFields = paramToReturnFields.mapValues { (_, v) -> v.toSet() },
        paramToReturnFieldPaths = paramToReturnFieldPaths.mapValues { (_, paths) ->
            paths.minWithOrNull(compareBy({ it.size }, { it.joinToString(",") })) ?: emptyList()
        }.filterValues { it.isNotEmpty() },
        sourceFieldWrites = sourceFieldWrites.mapValues { (_, writes) ->
            writes.distinctBy { it.paramIndex to it.suffix }
                .sortedWith(compareBy({ it.paramIndex }, { it.suffix }))
        }.filterValues { it.isNotEmpty() },
        invokedBinds = invokedBinds.values.sortedWith(
            compareBy({ it.invokedParam }, { it.argIndex }, { it.fromParam ?: -1 }, { it.sourceSite ?: -1 }),
        ),
        origin = if (capHit && originLabel == SummaryOrigin.COMPUTED) SummaryOrigin.RECURSIVE_APPROX else originLabel,
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
