package io.cdxgen.kosi.graph

import io.cdxgen.kosi.schema.CallGraph
import io.cdxgen.kosi.schema.JsonWriter

/**
 * The `--reachable-symbols <file>` sidecar: shortest witness paths for every
 * reached node in the emitted view, one per root scope that reaches it,
 * capped at the run's `--max-paths-per-symbol`. A witness is a real walk:
 * consecutive node ids are joined by edges with those ids — the same
 * invariant the connectivity gate checks, published for consumers to read.
 */
object WitnessPaths {

    data class Entry(val canonicalName: String, val paths: List<Path>)

    data class Path(val root: String, val edgeIds: List<String>)

    fun write(callGraph: CallGraph, maxPaths: Int): String {
        val nodesById = callGraph.nodes.associateBy { it.id }
        val adjacency = callGraph.edges.groupBy({ it.sourceId }) { edge -> edge.targetId to edge.id }
        val rootNodes = callGraph.reachability.filter { it.distance == 0 }.map { it.nodeId }.toSet()
        val w = JsonWriter()
        w.beginObject()
        w.num("maxPathsPerSymbol", maxPaths)
        w.beginArray("symbols")
        val reached = callGraph.reachability.filter { it.reached }.map { it.nodeId }.sorted()
        for (nodeId in reached) {
            val node = nodesById[nodeId] ?: continue
            w.beginObject()
            w.str("canonicalName", node.canonicalName)
            w.str("nodeId", nodeId)
            w.beginArray("paths")
            val roots = rootNodes.filter { root -> reaches(root, nodeId, callGraph) }.sorted()
            var count = 0
            for (root in roots) {
                if (count >= maxPaths) break
                val walk = walkPath(root, nodeId, adjacency) ?: continue
                w.beginObject()
                w.beginArray("edges")
                for (edgeId in walk) w.str(edgeId)
                w.endArray()
                w.str("root", root)
                w.endObject()
                count++
            }
            w.endArray()
            w.endObject()
        }
        w.endArray()
        w.endObject()
        return w.render()
    }

    /** Does [root] reach [target] (nodes with distance 0 reach themselves)? */
    private fun reaches(root: String, target: String, callGraph: CallGraph): Boolean {
        if (root == target) return true
        val distanceByNode = callGraph.reachability.associate { it.nodeId to it.distance }
        val rootDistance = distanceByNode[root] ?: return false
        val targetDistance = distanceByNode[target] ?: return false
        return rootDistance == 0 && targetDistance > 0
    }

    /** Edge ids along the BFS shortest path, parents chosen in sorted order. */
    private fun walkPath(
        root: String,
        target: String,
        adjacency: Map<String, List<Pair<String, String>>>,
    ): List<String>? {
        if (root == target) return emptyList()
        val parent = HashMap<String, Pair<String, String>>() // node -> (predecessor, edgeId)
        val queue = ArrayDeque<String>()
        val seen = mutableSetOf(root)
        queue.addLast(root)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            for ((next, edgeId) in adjacency[current].orEmpty().sortedBy { it.first }) {
                if (!seen.add(next)) continue
                parent[next] = current to edgeId
                if (next == target) {
                    val edges = ArrayDeque<String>()
                    var cursor = target
                    while (cursor != root) {
                        val step = parent[cursor] ?: return null
                        edges.addFirst(step.second)
                        cursor = step.first
                    }
                    return edges.toList()
                }
                queue.addLast(next)
            }
        }
        return null
    }
}
