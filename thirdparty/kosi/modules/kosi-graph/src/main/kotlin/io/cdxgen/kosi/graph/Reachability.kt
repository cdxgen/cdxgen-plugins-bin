package io.cdxgen.kosi.graph

/**
 * Reachability over the complete graph: BFS distances from the root set and
 * per-scope membership, plus the witness machinery the
 * `--reachable-symbols` sidecar consumes. Adjacency maps are always given
 * sorted, so traversal order — and therefore every parent choice — is
 * deterministic.
 */
internal object Reachability {

    /** Shortest distance from any root; nodes with no path get -1. */
    fun bfsDistances(roots: Set<String>, adjacency: Map<String, List<String>>, allKeys: List<String>): Map<String, Int> {
        val distance = HashMap<String, Int>()
        val queue = ArrayDeque<String>()
        for (root in roots.sorted()) {
            distance[root] = 0
            queue.addLast(root)
        }
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val next = distance.getValue(current) + 1
            for (target in adjacency[current].orEmpty()) {
                if (target !in distance) {
                    distance[target] = next
                    queue.addLast(target)
                }
            }
        }
        return distance
    }

    /** The set reachable from [roots] (membership per scope, for roots[]). */
    fun reachableFrom(roots: Set<String>, adjacency: Map<String, List<String>>): Set<String> {
        val seen = sortedSetOf<String>()
        val queue = ArrayDeque<String>()
        for (root in roots.sorted()) {
            seen.add(root)
            queue.addLast(root)
        }
        while (queue.isNotEmpty()) {
            for (target in adjacency[queue.removeFirst()].orEmpty()) {
                if (seen.add(target)) queue.addLast(target)
            }
        }
        return seen
    }

    /**
     * One shortest witness path per root scope that reaches the node
     * (deterministic BFS parents: the lexicographically smallest predecessor
     * at each distance), closest roots first, capped at [maxPaths]. An empty
     * list means the node is itself a root.
     */
    fun witnessPaths(
        rootKeys: Set<String>,
        adjacency: Map<String, List<String>>,
        target: String,
        maxPaths: Int,
    ): List<List<String>> {
        if (target in rootKeys) return listOf(listOf(target))
        val paths = mutableListOf<List<String>>()
        for (root in rootKeys.sorted()) {
            if (paths.size >= maxPaths) break
            // Distinct roots give distinct witnesses (they start elsewhere);
            // one shortest path per root, capped at the run's --max-paths-
            // per-symbol.
            shortestPathFrom(root, target, adjacency)?.let { paths.add(it) }
        }
        return paths
    }

    /** BFS with sorted neighbour order: the deterministic shortest path. */
    private fun shortestPathFrom(
        root: String,
        target: String,
        adjacency: Map<String, List<String>>,
    ): List<String>? {
        if (root == target) return listOf(root)
        val parent = HashMap<String, String>()
        val queue = ArrayDeque<String>()
        queue.addLast(root)
        val seen = mutableSetOf(root)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            for (next in adjacency[current].orEmpty()) {
                if (!seen.add(next)) continue
                parent[next] = current
                if (next == target) {
                    val path = ArrayDeque<String>()
                    var cursor: String? = target
                    while (cursor != null) {
                        path.addFirst(cursor)
                        cursor = if (cursor == root) null else parent[cursor]
                    }
                    return path.toList()
                }
                queue.addLast(next)
            }
        }
        return null
    }
}
