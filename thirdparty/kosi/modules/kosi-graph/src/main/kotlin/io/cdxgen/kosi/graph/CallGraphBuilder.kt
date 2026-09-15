package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.schema.CallGraph
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.Severity

/**
 * The call graph builder (02-ARCHITECTURE.md §5). Input: the lowered
 * [KirModule] and the run's [GraphOptions]. Reachability is computed on the
 * COMPLETE graph afterwards, so the stdlib/dependency view re-shapes what is
 * EMITTED without redefining what is REACHABLE, and a path a view filter
 * cuts survives as a `collapsed` edge.
 *
 * Determinism contract: every emitted collection is sorted at construction,
 * ids are assigned after a canonical sort, and iteration never consults hash
 * order. Two runs on one input produce byte-identical graphs.
 */
object CallGraphBuilder {

    /** File path -> (relativePath, modulePath), plus the module purl lookup. */
    data class Attribution(
        val byAbsoluteFilePath: Map<String, Pair<String, String>>,
        val purlByModulePath: Map<String, String>,
    ) {
        companion object {
            val NONE = Attribution(emptyMap(), emptyMap())
        }
    }

    class Result(
        val callGraph: CallGraph,
        val algorithmUsed: String,
        val unresolvedCalls: Int,
        val collapsedEdgeCount: Int,
    )

    fun build(module: KirModule, options: GraphOptions, attribution: Attribution): Result {
        val functions = module.functions.sortedWith(
            compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }, { it.column }),
        )
        val index = DispatchIndex(functions)
        val nodes = GraphNodes(attribution)

        // Every lowered function is a node, edges or not: the exported-reach
        // denominator and the breakdown both read the whole node set.
        for (f in functions) nodes.localNode(f)

        // ---- walk bodies: call sites + constructor evidence ------------------
        val sites = mutableListOf<Site>()
        var unresolvedCalls = 0
        for (f in functions) {
            val sourceKey = nodes.keyOf(f) ?: continue
            val body = f.body ?: continue
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is io.cdxgen.kosi.kir.KirNew ->
                            sites.add(Site.constructor(sourceKey, ins.type, ins.line))

                        is io.cdxgen.kosi.kir.KirDynamicCall -> unresolvedCalls++

                        is io.cdxgen.kosi.kir.KirCall ->
                            if (ins.callee.kind == CallKind.CONSTRUCTOR) {
                                sites.add(Site.constructor(sourceKey, ins.callee.fqn, ins.line))
                            } else {
                                sites.add(
                                    Site.call(
                                        sourceKey = sourceKey,
                                        calleeFqn = ins.callee.fqn,
                                        descriptor = ins.callee.descriptor,
                                        kind = ins.callee.kind,
                                        line = ins.line,
                                        receiver = ins.receiver,
                                        scopeFunction = ins.callee.fqn in SCOPE_FUNCTION_EDGES,
                                        method = ins.callee.fqn.substringAfterLast('.'),
                                    ),
                                )
                            }

                        else -> {}
                    }
                }
            }
        }

        // ---- roots (they also seed RTA: a root runs on a live receiver) ------
        val (rootsByScope, rootDiagnostics) = Roots.select(options.roots, nodes.list())
        val flatRoots = rootsByScope.values.flatten().toSortedSet()
        val rootClasses = sortedSetOf<String>()
        for (key in flatRoots) nodes.node(key)?.enclosingClass?.let { rootClasses.add(it) }

        // ---- dispatch ---------------------------------------------------------
        val dispatch = Dispatch(index, nodes, sites, rootClasses, flatRoots, options)
        val edges = dispatch.edges

        // ---- reachability on the COMPLETE graph -------------------------------
        val allKeys = nodes.keysSorted()
        val adjacency = edges.groupBy({ it.sourceKey }, { it.targetKey })
            .mapValues { (_, targets) -> targets.distinct().sorted() }
        val distance = Reachability.bfsDistances(flatRoots, adjacency, allKeys)
        val scopeMembership: Map<String, Set<String>> = rootsByScope.entries
            .sortedBy { it.key.id }
            .associate { (scope, roots) -> scope.id to Reachability.reachableFrom(roots, adjacency) }

        // ---- the view ----------------------------------------------------------
        val view = ViewFilter.apply(nodes, edges, options, distance)
        val diagnostics = buildList {
            addAll(rootDiagnostics)
            if (unresolvedCalls > 0) {
                add(
                    Diagnostic(
                        code = DiagnosticCodes.CALLGRAPH_UNRESOLVED_CALLS,
                        severity = Severity.WARNING,
                        message = "$unresolvedCalls call site(s) resolved to no callee and emit no edge; " +
                            "they are counted, never silently absent",
                        position = Position(".", 1, 1),
                        count = unresolvedCalls,
                    ),
                )
            }
            for (message in dispatch.fallbackMessages) {
                add(
                    Diagnostic(
                        code = DiagnosticCodes.CALLGRAPH_TIMEOUT,
                        severity = Severity.WARNING,
                        message = message,
                        position = Position(".", 1, 1),
                        count = 1,
                    ),
                )
            }
        }.sortedWith(Diagnostic.COMPARATOR)

        val scopeNames: (String) -> List<String> = { key ->
            scopeMembership.entries.filter { key in it.value }.map { it.key }.sorted()
        }
        val callGraph = CallGraph(
            mode = options.mode.id,
            algorithmUsed = dispatch.algorithmUsed,
            nodes = view.nodes,
            edges = view.edges,
            reachability = view.reachability(scopeNames),
            stats = view.breakdown(),
            diagnostics = diagnostics,
        )
        return Result(callGraph, dispatch.algorithmUsed, unresolvedCalls, view.collapsedEdgeCount)
    }

    /** The retained scope-function evidence edges (§4's inlined lambda bodies). */
    val SCOPE_FUNCTION_EDGES = setOf(
        "kotlin.let", "kotlin.run", "kotlin.apply", "kotlin.also", "kotlin.with", "kotlin.use",
    )
}

/**
 * One walked call site, before dispatch. Constructor-shaped sites (`KirNew`
 * and CONSTRUCTOR-kind calls) both instantiate their class when reached.
 */
internal data class Site(
    val sourceKey: String,
    val calleeFqn: String,
    val descriptor: String?,
    val kind: CallKind,
    val line: Int,
    val receiver: String?,
    val isConstructor: Boolean,
    val isScopeFunction: Boolean,
    val method: String?,
) {
    companion object {
        fun constructor(sourceKey: String, type: String, line: Int) =
            Site(sourceKey, type, null, CallKind.CONSTRUCTOR, line, null, true, false, null)

        fun call(
            sourceKey: String,
            calleeFqn: String,
            descriptor: String?,
            kind: CallKind,
            line: Int,
            receiver: String?,
            scopeFunction: Boolean,
            method: String?,
        ) = Site(sourceKey, calleeFqn, descriptor, kind, line, receiver, false, scopeFunction, method)
    }
}

/**
 * The complete-graph edge, pre-id. A real call edge and a collapsed bridge
 * may share endpoints; the real edge wins the dedup, a bridge is emitted
 * only when no direct edge exists.
 */
internal data class InternalEdge(
    val sourceKey: String,
    val targetKey: String,
    val callType: String,
    val line: Int,
    val method: String?,
    val candidateCount: Int?,
    val collapsedHops: Int? = null,
    val collapsedPackages: List<String>? = null,
) : Comparable<InternalEdge> {
    override fun compareTo(other: InternalEdge): Int = compareValuesBy(
        this, other,
        { it.sourceKey }, { it.targetKey }, { it.callType }, { it.line },
        { it.collapsedHops ?: -1 },
    )

    val isCollapsed: Boolean get() = collapsedHops != null

    companion object {
        private fun rank(edge: InternalEdge): Int = if (edge.isCollapsed) 1 else 0

        fun dedup(edges: List<InternalEdge>): List<InternalEdge> {
            val out = LinkedHashMap<Pair<String, String>, InternalEdge>()
            for (edge in edges.sorted()) {
                val key = edge.sourceKey to edge.targetKey
                val existing = out[key]
                if (existing == null || rank(edge) < rank(existing)) out[key] = edge
            }
            return out.values.sorted()
        }
    }
}

/**
 * Dispatch resolution per mode (02-ARCHITECTURE.md §5's mode table).
 *
 * `static` connects dispatch-free sites only (top-level/private/final/
 * object/companion/enum targets, constructors, operators, extensions).
 * `cha` adds the open-hierarchy candidate set. `sealed` is CHA plus the
 * closed-set narrowing and the `sealed-exact`/`sealed-bounded` call types.
 * `rta` and `vta` are reachability-driven: work starts from the roots, a
 * constructor site instantiates its class only once its body is reached, and
 * a virtual site's candidates connect only after their owner class is
 * instantiated — classes and methods grow to a monotone fixpoint, so the
 * emitted edges are exactly the ones reachability can justify. The fixpoint
 * result does not depend on processing order (the edge set is monotone), so
 * determinism costs nothing.
 *
 * The work budget counts deterministic units (evaluations + edge emissions);
 * only `auto` falls back on exceeding it (vta -> rta -> sealed, recorded as
 * `callgraph-timeout`), so an explicitly requested mode always produces its
 * full graph and byte-identical output never hinges on machine speed.
 */
private class Dispatch(
    private val index: DispatchIndex,
    private val nodes: GraphNodes,
    sites: List<Site>,
    private val rootSeeds: Set<String>,
    private val roots: Set<String>,
    private val options: GraphOptions,
) {
    var algorithmUsed: String = "none"
        private set
    var edges: List<InternalEdge> = emptyList()
        private set
    var fallbackMessages: List<String> = emptyList()
        private set

    /** Sites grouped by the function that contains them, in walk order. */
    private val sitesBySource: Map<String, List<Site>> = sites.groupBy { it.sourceKey }

    private val rtaInstantiated = sortedSetOf<String>()
    private val out = LinkedHashMap<String, LinkedHashMap<String, InternalEdge>>()
    private var work = 0L
    private var currentBudget = Long.MAX_VALUE

    private val usesRta: Boolean
        get() = algorithmUsed == "rta" || algorithmUsed == "vta"

    // VTA's exact-type pre-pass: once per function, call-site-local,
    // independent of reachability.
    private val registerTypes: Map<String, Map<String, Set<String>>> by lazy {
        if (algorithmUsed != "vta") {
            emptyMap()
        } else {
            sitesBySource.keys.associateWith { key -> RegisterTypes.of(nodes.functionOf(key), index) }
        }
    }

    init {
        val requested = options.mode
        val budget = options.timeoutSeconds.toLong() * GraphOptions.WORK_UNITS_PER_SECOND
        if (requested == CallGraphMode.AUTO) {
            seedRta()
            val chain = listOf("vta", "rta", "sealed")
            val messages = mutableListOf<String>()
            for ((i, algorithm) in chain.withIndex()) {
                algorithmUsed = algorithm
                reset()
                if (!run(budget)) break
                messages.add(
                    "callgraph algorithm $algorithm exceeded the deterministic work budget " +
                        "($budget units from --callgraph-timeout=${options.timeoutSeconds}s); " +
                        "fell back to ${chain.getOrElse(i + 1) { "sealed" }}",
                )
            }
            fallbackMessages = messages.takeLast(1)
        } else {
            algorithmUsed = when (requested) {
                CallGraphMode.STATIC -> "static"
                CallGraphMode.CHA -> "cha"
                CallGraphMode.SEALED -> "sealed"
                CallGraphMode.RTA -> "rta"
                CallGraphMode.VTA -> "vta"
                CallGraphMode.NONE -> "none"
            }
            if (usesRta) seedRta()
            run(Long.MAX_VALUE)
        }
        edges = InternalEdge.dedup(out.values.flatMap { it.values })
    }

    /** Classes alive without user code constructing them, plus root receivers. */
    private fun seedRta() {
        for ((klass, flags) in index.classFlags) {
            if (flags.any { it == "object" || it == "companion" || it == "enum" }) rtaInstantiated.add(klass)
        }
        rtaInstantiated.addAll(rootSeeds)
    }

    private fun reset() {
        out.clear()
        work = 0
    }

    private fun spend(units: Int = 1): Boolean {
        work += units
        return work <= currentBudget
    }

    /** Returns true when the budget was EXCEEDED (the run is incomplete). */
    private fun run(budget: Long): Boolean {
        currentBudget = budget
        if (!usesRta) {
            for (sourceKey in sitesBySource.keys.sorted()) {
                for (site in sitesBySource.getValue(sourceKey)) {
                    if (!connectSimple(site)) return true
                }
            }
            return false
        }
        // Reachability-driven fixpoint: bodies to process, and classes whose
        // instantiation re-opens deferred virtual sites.
        val deferredByClass = HashMap<String, MutableSet<String>>() // class -> source keys waiting
        val bodiesProcessed = mutableSetOf<String>()
        val bodyQueue = ArrayDeque<String>()
        val classQueue = ArrayDeque<String>()

        fun enqueueBody(key: String) {
            if (key in bodiesProcessed) return
            val function = nodes.functionOf(key) ?: return
            if (function.body == null) return
            bodiesProcessed.add(key)
            bodyQueue.addLast(key)
        }

        fun instantiate(klass: String) {
            if (klass in rtaInstantiated) return
            rtaInstantiated.add(klass)
            classQueue.addLast(klass)
        }

        fun emitCallEdge(site: Site, target: String, callType: String, candidateCount: Int?) {
            addEdge(InternalEdge(site.sourceKey, target, callType, site.line, site.method, candidateCount))
            enqueueBody(target)
            // The edge proves the receiver class is live at run time: a call
            // that executes has a real instance under it.
            nodes.node(target)?.enclosingClass?.let { instantiate(it) }
        }

        /**
         * Connects one site. `null` result = budget exhausted; empty wait set
         * = connected (or connected-partially under RTA, whose remaining
         * candidates arrive with the fixpoint); non-empty = deferred on
         * classes that are not instantiated yet, registered by the caller.
         */
        fun connect(site: Site): Pair<Boolean, Set<String>>? {
            if (!spend()) return null
            return when {
                site.isConstructor -> {
                    val target = nodes.externalNode(site.calleeFqn, null, kind = "constructor")
                    addEdge(InternalEdge(site.sourceKey, target, "static", site.line, null, null))
                    instantiate(site.calleeFqn)
                    index.canonicalize(site.calleeFqn)?.let { instantiate(it) }
                    Pair(true, emptySet())
                }

                site.kind == CallKind.VIRTUAL -> {
                    val (targets, callType, waitingOn, libraryLeaf) = virtualTargets(site)
                    if (!spend(1 + targets.size)) return null
                    if (libraryLeaf) {
                        // Dispatch into code with no workspace declaration and
                        // no workspace implementation: one receiver-typed edge
                        // to the resolved callee, an external leaf.
                        val target = nodes.externalNode(site.calleeFqn, site.descriptor)
                        emitCallEdge(site, target, "receiver-typed", null)
                        return Pair(true, emptySet())
                    }
                    val candidateCount = targets.size.takeIf { it > 1 }
                    for (target in targets) emitCallEdge(site, target, callType, candidateCount)
                    Pair(true, waitingOn)
                }

                else -> {
                    val callType = if (site.isScopeFunction) "lambda-inlined" else "static"
                    val workspace = index.workspaceCallee(site.calleeFqn, site.descriptor)
                    val target = if (workspace != null) {
                        nodes.keyOf(workspace) ?: nodes.externalNode(site.calleeFqn, site.descriptor)
                    } else {
                        nodes.externalNode(site.calleeFqn, site.descriptor)
                    }
                    emitCallEdge(site, target, callType, null)
                    Pair(true, emptySet())
                }
            }
        }

        fun processBody(sourceKey: String): Boolean {
            for (site in sitesBySource[sourceKey].orEmpty()) {
                val outcome = connect(site) ?: return false
                for (klass in outcome.second) {
                    deferredByClass.getOrPut(klass) { sortedSetOf() }.add(sourceKey)
                }
            }
            return true
        }

        for (key in roots.sorted()) enqueueBody(key)
        for (klass in rtaInstantiated.sorted()) classQueue.addLast(klass)

        while (true) {
            if (bodyQueue.isNotEmpty()) {
                val key = bodyQueue.removeFirst()
                if (!processBody(key)) return true
                continue
            }
            if (classQueue.isEmpty()) break
            val klass = classQueue.removeFirst()
            val waiting = deferredByClass[klass] ?: continue
            val sources = waiting.sorted().toList()
            waiting.clear()
            for (sourceKey in sources) {
                // The body already went through processBody once; re-running
                // it re-evaluates the deferred virtual sites against the now
                // larger instantiated set. Idempotent: the edge map
                // deduplicates, and re-connection cannot double-emit.
                bodiesProcessed.remove(sourceKey)
                enqueueBody(sourceKey)
            }
        }
        return false
    }

    /** Non-dispatched sites, used by the complete-graph algorithms. */
    private fun connectSimple(site: Site): Boolean {
        if (!spend()) return false
        when {
            site.isConstructor -> {
                val target = nodes.externalNode(site.calleeFqn, null, kind = "constructor")
                addEdge(InternalEdge(site.sourceKey, target, "static", site.line, null, null))
            }

            site.kind == CallKind.VIRTUAL -> {
                val (targets, callType, _, libraryLeaf) = virtualTargets(site)
                if (libraryLeaf) {
                    // A call into code with no workspace declaration is still
                    // direct evidence: one receiver-typed edge to the callee.
                    val target = nodes.externalNode(site.calleeFqn, site.descriptor)
                    addEdge(InternalEdge(site.sourceKey, target, "receiver-typed", site.line, site.method, null))
                } else {
                    val candidateCount = targets.size.takeIf { it > 1 }
                    for (target in targets) {
                        addEdge(InternalEdge(site.sourceKey, target, callType, site.line, site.method, candidateCount))
                    }
                }
            }

            else -> {
                val callType = if (site.isScopeFunction) "lambda-inlined" else "static"
                val workspace = index.workspaceCallee(site.calleeFqn, site.descriptor)
                val target = if (workspace != null) {
                    nodes.keyOf(workspace) ?: nodes.externalNode(site.calleeFqn, site.descriptor)
                } else {
                    nodes.externalNode(site.calleeFqn, site.descriptor)
                }
                addEdge(InternalEdge(site.sourceKey, target, callType, site.line, site.method, null))
            }
        }
        return true
    }

    private fun addEdge(edge: InternalEdge) {
        if (!spend()) return
        out.getOrPut(edge.sourceKey) { LinkedHashMap() }.put(edge.targetKey, edge)
    }

    /**
     * Candidate targets for a virtual site under the current algorithm:
     * exact sites collapse to their declaration; sealed sites carry the
     * closed set with `sealed-exact`/`sealed-bounded` call types; RTA keeps
     * only targets whose owner is instantiated, reporting the classes it
     * still waits for; VTA narrows by known receiver types when the evidence
     * is positive.
     */
    private fun virtualTargets(site: Site): Quad {
        val declared = index.workspaceCallee(site.calleeFqn, site.descriptor)
        if (declared == null) {
            // No workspace declaration for the callee. If local classes
            // implement it (a library interface method), dispatch lands
            // there; otherwise it is a receiver-typed external leaf.
            val impls = index.overridingCanonical(site.calleeFqn).filter { index.isConcrete(it) }
            if (impls.isEmpty()) {
                return Quad(emptyList(), "receiver-typed", emptySet(), libraryLeaf = true)
            }
            // Open dispatch through a library interface is still open
            // dispatch: static mode declines it exactly as it declines a
            // workspace open hierarchy.
            if (algorithmUsed == "static") return Quad(emptyList(), "", emptySet())
            // The owner's modality is unknown for a library type: open by
            // definition, so the label is the interface one however far RTA
            // narrows the live targets — a smaller set is an instantiation
            // fact, not a closed hierarchy.
            return gateRtaVta(site, impls.sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" })))
                .copy(callType = "interface-cha")
        }
        if (index.isExact(declared)) {
            return if (index.isConcrete(declared)) {
                Quad(listOfNotNull(nodes.keyOf(declared)), "static", emptySet())
            } else {
                Quad(emptyList(), "static", emptySet())
            }
        }
        // `static` stops here: an open dispatch site is exactly what the mode
        // declines to model (the candidate machinery below is cha and above).
        if (algorithmUsed == "static") return Quad(emptyList(), "", emptySet())
        val candidates = (index.overriding(declared).filter { index.isConcrete(it) } +
            listOfNotNull(declared.takeIf { index.isConcrete(it) }))
            .distinctBy { it.canonicalName + "\u0000" + (it.jvmDescriptor ?: "") }
            .sortedWith(compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }))
        if (candidates.isEmpty()) return Quad(emptyList(), "", emptySet())
        val gated = gateRtaVta(site, candidates)
        // The label names what the RUNTIME target set is after narrowing: a
        // sealed site with one live target is exact, with more it is bounded.
        val callType = when {
            index.isSealedSite(declared) && gated.targets.size == 1 -> "sealed-exact"
            index.isSealedSite(declared) -> "sealed-bounded"
            index.isInterfaceSite(declared) -> "interface-cha"
            else -> "receiver-typed"
        }
        return gated.copy(callType = callType)
    }

    /**
     * RTA keeps only candidates whose owner is instantiated, reporting the
     * classes it still waits for; VTA narrows by known receiver types when
     * the evidence is positive.
     */
    private fun gateRtaVta(site: Site, candidates: List<KirFunction>): Quad {
        var effective = candidates
        var waitingOn: Set<String> = emptySet()
        if (usesRta) {
            val ready = candidates.filter { it.enclosingClass == null || it.enclosingClass in rtaInstantiated }
            waitingOn = candidates.mapNotNull { it.enclosingClass }.filter { it !in rtaInstantiated }.toSortedSet()
            if (ready.isEmpty()) return Quad(emptyList(), callType = "", waitingOn = waitingOn)
            effective = ready
        }
        if (algorithmUsed == "vta") {
            val knownTypes = site.receiver
                ?.let { registerTypes[site.sourceKey]?.get(it) }
                .orEmpty()
                .mapNotNull { index.canonicalize(it) }
            if (knownTypes.isNotEmpty()) {
                val narrowed = effective.filter { f ->
                    f.enclosingClass != null && knownTypes.any { t -> index.isSubtypeOf(f.enclosingClass!!, t) }
                }
                // Narrow only on positive evidence: an empty intersection
                // means the type facts disagree with the override index, and
                // the override index (the sound superset) wins.
                if (narrowed.isNotEmpty()) effective = narrowed
            }
        }
        return Quad(effective.mapNotNull { nodes.keyOf(it) }, "", waitingOn)
    }
}

/**
 * VTA's exact-type pre-pass: register types known by construction (a `new`
 * or a constructor call), propagated through copies, stores, phis and elvis
 * joins to a per-function fixpoint. Registers with no known type yield an
 * empty set and their sites fall back to the RTA candidate set — unknown
 * never narrows.
 */
internal object RegisterTypes {

    fun of(function: KirFunction?, index: DispatchIndex): Map<String, Set<String>> {
        val body = function?.body ?: return emptyMap()
        val types = HashMap<String, MutableSet<String>>()

        fun learn(reg: String, type: String): Boolean =
            types.getOrPut(reg) { sortedSetOf() }.add(type)

        fun propagate(target: String, source: String?): Boolean {
            val sourceTypes = types[source] ?: return false
            if (sourceTypes.isEmpty()) return false
            return types.getOrPut(target) { sortedSetOf() }.addAll(sourceTypes)
        }

        var changed = true
        var passes = 0
        while (changed && passes < 8) {
            changed = false
            passes++
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is io.cdxgen.kosi.kir.KirNew -> changed = learn(ins.result, ins.type) || changed
                        is io.cdxgen.kosi.kir.KirCall ->
                            changed = when (ins.callee.kind) {
                                CallKind.CONSTRUCTOR -> learn(ins.result ?: continue, ins.callee.fqn) || changed
                                else -> propagate(ins.result ?: continue, ins.receiver) || changed
                            }

                        is io.cdxgen.kosi.kir.KirAssign -> changed = propagate(ins.result, ins.source) || changed
                        is io.cdxgen.kosi.kir.KirStore -> changed = propagate(ins.target, ins.value) || changed
                        is io.cdxgen.kosi.kir.KirPhi ->
                            for ((_, source) in ins.inputs) {
                                changed = propagate(ins.result, source) || changed
                            }

                        is io.cdxgen.kosi.kir.KirElvis -> {
                            changed = propagate(ins.result, ins.value) || changed
                            changed = propagate(ins.result, ins.fallback) || changed
                        }

                        else -> {}
                    }
                }
            }
        }
        return types
    }
}

/**
 * The dispatch decision for one site: target node keys, the call type to
 * label them with, the classes RTA is still waiting on, and whether the site
 * falls back to a receiver-typed external leaf (no workspace declaration and
 * no workspace implementation).
 */
internal data class Quad(
    val targets: List<String>,
    val callType: String,
    val waitingOn: Set<String>,
    val libraryLeaf: Boolean = false,
)
