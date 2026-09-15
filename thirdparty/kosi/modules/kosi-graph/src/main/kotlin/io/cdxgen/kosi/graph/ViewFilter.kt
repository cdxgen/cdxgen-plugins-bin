package io.cdxgen.kosi.graph

import io.cdxgen.kosi.schema.CallGraphBreakdown
import io.cdxgen.kosi.schema.CallGraphEdge
import io.cdxgen.kosi.schema.CallGraphNode
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.ReachabilityEntry
import io.cdxgen.kosi.schema.DependencyDetail

/**
 * The post-hoc view (02-ARCHITECTURE.md §5): reachability was computed on
 * the complete graph; this filter decides what the report EMITS. Omitting a
 * scope must not sever the graph — a path through omitted nodes survives as
 * one `collapsed` edge carrying the hop count and the packages traversed,
 * and the bridges walk only the call edges kosi resolved (every edge here
 * came from a resolved call; unresolved sites emit none).
 *
 * Rules:
 *  - `--include-stdlib=false` omits stdlib nodes; paths through them bridge.
 *  - `--dependency-detail collapse` (default) omits dependency nodes and
 *    bridges them the same way; `full` keeps them; `drop` omits them WITHOUT
 *    bridging — the consumer explicitly asked for the severance, and the
 *    option name says so.
 *  - A real edge between two kept nodes always wins over a collapsed bridge
 *    between the same pair.
 */
internal object ViewFilter {

    class View internal constructor(
        val nodeKeys: List<String>,
        val nodes: List<CallGraphNode>,
        val edges: List<CallGraphEdge>,
        val collapsedEdgeCount: Int,
        private val idByKey: Map<String, String>,
        private val bucketById: Map<String, Classification.Bucket>,
        private val distance: Map<String, Int>,
    ) {
        /** Reached view-node keys; the connectivity denominator. */
        fun reachedKeys(): List<String> = nodeKeys.filter { (distance[it] ?: -1) >= 0 }

        fun keyToId(): Map<String, String> = idByKey

        fun reachability(scopeNames: (String) -> List<String>): List<ReachabilityEntry> =
            nodeKeys.map { key ->
                ReachabilityEntry(
                    nodeId = idByKey.getValue(key),
                    reached = (distance[key] ?: -1) >= 0,
                    distance = distance[key] ?: -1,
                    roots = scopeNames(key),
                )
            }

        fun breakdown(): CallGraphBreakdown {
            var localNodes = 0
            var stdlibNodes = 0
            var dependencyNodes = 0
            var syntheticNodes = 0
            for (node in nodes) {
                when (bucketOfNode(node)) {
                    Classification.Bucket.SYNTHETIC -> syntheticNodes++
                    Classification.Bucket.LOCAL -> localNodes++
                    Classification.Bucket.STDLIB -> stdlibNodes++
                    Classification.Bucket.DEPENDENCY -> dependencyNodes++
                }
            }
            var localEdges = 0
            var stdlibEdges = 0
            var dependencyEdges = 0
            var syntheticEdges = 0
            for (edge in edges) {
                when (bucketOfEdge(edge)) {
                    Classification.Bucket.SYNTHETIC -> syntheticEdges++
                    Classification.Bucket.LOCAL -> localEdges++
                    Classification.Bucket.STDLIB -> stdlibEdges++
                    Classification.Bucket.DEPENDENCY -> dependencyEdges++
                }
            }
            return CallGraphBreakdown(
                localNodes = localNodes,
                stdlibNodes = stdlibNodes,
                dependencyNodes = dependencyNodes,
                syntheticNodes = syntheticNodes,
                localEdges = localEdges,
                stdlibEdges = stdlibEdges,
                dependencyEdges = dependencyEdges,
                syntheticEdges = syntheticEdges,
            )
        }

        /**
         * The disjoint node partition the breakdown publishes: synthetic
         * first, then local, then stdlib, then dependency — the parts must
         * sum to the whole or the breakdown is not a result.
         */
        private fun bucketOfNode(node: CallGraphNode): Classification.Bucket =
            Classification.bucketOf(node.canonicalName, node.local, node.synthetic)

        private fun bucketOfEdge(edge: CallGraphEdge): Classification.Bucket =
            bucketById[edge.targetId] ?: Classification.Bucket.DEPENDENCY
    }

    fun apply(
        nodes: GraphNodes,
        edges: List<InternalEdge>,
        options: GraphOptions,
        distance: Map<String, Int>,
    ): View {
        val all = nodes.list()
        val byKey = all.associateBy { it.key }
        val bucketByKey = all.associate { it.key to Classification.bucketOf(it.canonicalName, it.local, it.synthetic) }

        fun omitted(key: String): Boolean = when (bucketByKey.getValue(key)) {
            Classification.Bucket.STDLIB -> !options.includeStdlib
            Classification.Bucket.DEPENDENCY -> options.dependencyDetail != DependencyDetail.FULL
            else -> false
        }

        fun bridgeable(key: String): Boolean = when (bucketByKey.getValue(key)) {
            // `drop` severs dependencies on purpose; only the stdlib view and
            // the collapse view re-bridge what they omit.
            Classification.Bucket.STDLIB -> true
            Classification.Bucket.DEPENDENCY -> options.dependencyDetail == DependencyDetail.COLLAPSE
            else -> false
        }

        val keptKeys = all.map { it.key }.filter { !omitted(it) }
        val keptSet = keptKeys.toSet()

        // ---- bridges through the omitted region ------------------------------
        val bridges = mutableListOf<InternalEdge>()
        if (keptKeys.size < all.size) {
            val adjacency = edges.groupBy({ it.sourceKey }, { it.targetKey })
            val entryEdges = edges.filter { it.sourceKey in keptSet && it.targetKey !in keptSet }
                .sortedWith(compareBy({ it.sourceKey }, { it.targetKey }))
            // Per kept node: BFS once over the omitted region from all its
            // omitted successors, carrying hop counts and packages.
            val bySource = entryEdges.groupBy { it.sourceKey }
            for (source in bySource.keys.toSortedSet()) {
                val results = LinkedHashMap<String, Pair<Int, MutableList<String>>>() // target -> (hops, packages)
                val queue = ArrayDeque<Triple<String, Int, List<String>>>()
                for (edge in bySource.getValue(source).sortedBy { it.targetKey }) {
                    queue.addLast(Triple(edge.targetKey, 1, listOf(edge.targetKey)))
                }
                val best = HashMap<String, Int>()
                while (queue.isNotEmpty()) {
                    val (key, hops, path) = queue.removeFirst()
                    if (key in keptSet) {
                        val existing = results[key]
                        if (existing == null || hops < existing.first) {
                            results[key] = Pair(hops, path.toMutableList())
                        }
                        continue
                    }
                    if (key !in byKey || !bridgeable(key)) continue
                    if ((best[key] ?: Int.MAX_VALUE) <= hops) continue
                    best[key] = hops
                    for (next in adjacency[key].orEmpty().sorted()) {
                        queue.addLast(Triple(next, hops + 1, path + next))
                    }
                }
                for ((target, value) in results) {
                    if (target == source) continue
                    val packages = value.second
                        .mapNotNull { byKey[it]?.canonicalName }
                        .map { Classification.packageOf(it) }
                        .filter { it.isNotEmpty() }
                        .distinct()
                        .sorted()
                    bridges.add(
                        InternalEdge(
                            sourceKey = source,
                            targetKey = target,
                            callType = "collapsed",
                            line = 0,
                            method = null,
                            candidateCount = null,
                            collapsedHops = value.first,
                            collapsedPackages = packages,
                        ),
                    )
                }
            }
        }

        // ---- emitted sets ------------------------------------------------------
        val viewEdges = InternalEdge.dedup(edges.filter { it.sourceKey in keptSet && it.targetKey in keptSet } + bridges)
        val orderedKeys = keptKeys.sorted()
        val idByKey = orderedKeys.withIndex().associate { (index, key) -> key to id("node", index) }
        val viewNodes = orderedKeys.map { key ->
            val g = byKey.getValue(key)
            CallGraphNode(
                id = idByKey.getValue(key),
                name = g.name,
                qualifiedName = g.relativePath.ifEmpty { g.canonicalName } + ":" + g.canonicalName,
                canonicalName = g.canonicalName,
                jvmDescriptor = g.jvmDescriptor,
                kind = g.kind,
                modulePath = g.modulePath,
                purl = g.purl,
                filePath = g.relativePath,
                local = g.local,
                stdlib = bucketByKey.getValue(key) == Classification.Bucket.STDLIB,
                external = !g.local,
                synthetic = g.synthetic,
                suspend = g.suspend,
                visibility = g.visibility,
                ownerVisibility = if (g.ownerless) null else g.ownerVisibility,
                receiver = null,
                position = if (g.positionKnown) Position(g.relativePath, g.line, g.column) else null,
            )
        }
        val edgesOut = viewEdges.mapIndexed { index, edge ->
            CallGraphEdge(
                id = id("edge", index),
                sourceId = idByKey.getValue(edge.sourceKey),
                targetId = idByKey.getValue(edge.targetKey),
                callType = edge.callType,
                line = edge.line,
                column = 0,
                calleeText = null,
                receiver = null,
                method = edge.method,
                candidateCount = edge.candidateCount,
                emittedCandidateCount = null,
                collapsedHops = edge.collapsedHops,
                collapsedPackages = edge.collapsedPackages,
            )
        }
        val bucketById = orderedKeys.associate { key -> idByKey.getValue(key) to bucketByKey.getValue(key) }
        return View(
            nodeKeys = orderedKeys,
            nodes = viewNodes,
            edges = edgesOut,
            collapsedEdgeCount = bridges.size,
            idByKey = idByKey,
            bucketById = bucketById,
            distance = distance,
        )
    }

    /** `node-000001`-style ids, assigned only after the canonical sort. */
    fun id(prefix: String, index: Int): String = "$prefix-${(index + 1).toString().padStart(6, '0')}"
}
