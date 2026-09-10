package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.DependencyDetail
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The post-hoc view (02-ARCHITECTURE.md §5), negative cases first: a view
 * that severs a path without re-bridging it is the golem defect — omitting a
 * scope must reshape the report, never silently delete a path. The collapsed
 * bridge, its hop count and its traversed packages are all pinned here,
 * against the filter's real seam: the complete graph as the walk produces it
 * (local nodes plus external ones) with one stdlib middle node carrying an
 * edge to workspace code, the shape dispatch replay (P5) grows into.
 */
class ViewFilterTest {

    private fun nodesWithThroughPath(): GraphNodes {
        val nodes = GraphNodes(CallGraphBuilder.Attribution.NONE)
        nodes.localNode(GraphFixtures.function(canonicalName = "t.callback"))
        nodes.localNode(GraphFixtures.function(canonicalName = "t.direct"))
        nodes.localNode(
            GraphFixtures.function(
                canonicalName = "t.caller",
                body = listOf(
                    GraphFixtures.call("t0", "kotlin.mid", CallKind.STATIC),
                    GraphFixtures.call("t1", "t.direct", CallKind.STATIC),
                ),
            ),
        )
        nodes.externalNode("kotlin.mid", null)
        return nodes
    }

    /** caller -> kotlin.mid (stdlib) -> callback, plus caller -> t.direct. */
    private fun throughPathEdges(nodes: GraphNodes): List<InternalEdge> {
        val caller = nodes.list().first { it.canonicalName == "t.caller" }.key
        val mid = nodes.list().first { it.canonicalName == "kotlin.mid" }.key
        val callback = nodes.list().first { it.canonicalName == "t.callback" }.key
        val direct = nodes.list().first { it.canonicalName == "t.direct" }.key
        return listOf(
            InternalEdge(caller, mid, "static", 1, "mid", null),
            InternalEdge(mid, callback, "static", 0, null, null),
            InternalEdge(caller, direct, "static", 2, "direct", null),
        )
    }

    private fun options(
        includeStdlib: Boolean = false,
        dependencyDetail: DependencyDetail = DependencyDetail.COLLAPSE,
    ): GraphOptions = GraphOptions(
        mode = CallGraphMode.AUTO,
        roots = GraphOptions.rootsOf(listOf("exported")),
        includeStdlib = includeStdlib,
        dependencyDetail = dependencyDetail,
        maxPathsPerSymbol = 3,
        timeoutSeconds = 60,
    )

    private fun apply(
        nodes: GraphNodes,
        edges: List<InternalEdge>,
        options: GraphOptions,
    ): io.cdxgen.kosi.schema.CallGraph {
        val distance = Reachability.bfsDistances(
            nodes.list().filter { it.canonicalName == "t.caller" }.map { it.key }.toSet(),
            edges.groupBy({ it.sourceKey }, { it.targetKey }),
            nodes.keysSorted(),
        )
        val view = ViewFilter.apply(nodes, edges, options, distance)
        val scopeNames: (String) -> List<String> = { listOf("exported") }
        return io.cdxgen.kosi.schema.CallGraph(
            mode = options.mode.id,
            algorithmUsed = "vta",
            nodes = view.nodes,
            edges = view.edges,
            reachability = view.reachability(scopeNames),
            stats = view.breakdown(),
            diagnostics = emptyList(),
        )
    }

    @Test
    fun aPathTheStdlibViewCutsSurvivesAsOneCollapsedEdge() {
        val nodes = nodesWithThroughPath()
        val graph = apply(nodes, throughPathEdges(nodes), options(includeStdlib = false))
        assertTrue(graph.nodes.none { it.canonicalName == "kotlin.mid" }, "the view omits the stdlib node")
        val bridges = graph.edges.filter { it.callType == "collapsed" }
        assertTrue(bridges.isNotEmpty(), "the cut path must survive as a collapsed edge, not vanish")
        val bridge = bridges.single()
        assertEquals(2, bridge.collapsedHops, "caller -> kotlin.mid -> callback collapses to 2 hops")
        assertTrue(
            bridge.collapsedPackages.orEmpty().contains("kotlin"),
            "the traversed stdlib package is carried on the edge",
        )
    }

    @Test
    fun aRealEdgeWinsOverACollapsedBridgeBetweenTheSamePair() {
        val nodes = nodesWithThroughPath()
        val graph = apply(nodes, throughPathEdges(nodes), options(includeStdlib = true))
        // With stdlib included there is no cutting at all.
        assertTrue(graph.edges.none { it.callType == "collapsed" })
        assertEquals(3, graph.edges.size)
    }

    @Test
    fun includeStdlibChangesTheCounts() {
        // The golem filter defect: an always-true include filter nobody
        // noticed. On means stdlib nodes exist; off means they are gone —
        // and the breakdown says so either way.
        val nodes = nodesWithThroughPath()
        val on = apply(nodes, throughPathEdges(nodes), options(includeStdlib = true))
        val off = apply(nodes, throughPathEdges(nodes), options(includeStdlib = false))
        assertTrue(on.nodes.any { it.stdlib }, "include-stdlib on keeps stdlib nodes")
        assertTrue(off.nodes.none { it.stdlib }, "include-stdlib off drops them")
        assertTrue(on.stats.stdlibNodes > 0)
        assertEquals(0, off.stats.stdlibNodes + off.stats.stdlibEdges, "off means off in the breakdown too")
        assertTrue(on.stats.stdlibEdges > 0)
    }

    @Test
    fun dependencyDropSeversOnPurposeWhileCollapseBridges() {
        // Same through-path shape through a DEPENDENCY node: collapse
        // re-bridges, drop severs (the consumer asked for it).
        fun moduleWithDependency(): Pair<GraphNodes, List<InternalEdge>> {
            val nodes = GraphNodes(CallGraphBuilder.Attribution.NONE)
            nodes.localNode(GraphFixtures.function(canonicalName = "t.callback"))
            nodes.localNode(
                GraphFixtures.function(
                    canonicalName = "t.caller",
                    body = listOf(GraphFixtures.call("t0", "com.example.dep.mid", CallKind.STATIC)),
                ),
            )
            nodes.externalNode("com.example.dep.mid", null)
            val caller = nodes.list().first { it.canonicalName == "t.caller" }.key
            val mid = nodes.list().first { it.canonicalName == "com.example.dep.mid" }.key
            val callback = nodes.list().first { it.canonicalName == "t.callback" }.key
            val edges = listOf(
                InternalEdge(caller, mid, "static", 1, "mid", null),
                InternalEdge(mid, callback, "static", 0, null, null),
            )
            return nodes to edges
        }
        val (nodes, edges) = moduleWithDependency()
        val collapse = apply(nodes, edges, options(includeStdlib = true, dependencyDetail = DependencyDetail.COLLAPSE))
        val drop = apply(nodes, edges, options(includeStdlib = true, dependencyDetail = DependencyDetail.DROP))
        assertTrue(
            collapse.edges.any { it.callType == "collapsed" },
            "collapse re-bridges the path through the dependency",
        )
        assertTrue(
            drop.edges.none { it.callType == "collapsed" },
            "drop severs: no bridge is built for dependencies",
        )
    }

    @Test
    fun theBreakdownAlwaysSumsToTheTotals() {
        val nodes = nodesWithThroughPath()
        for (includeStdlib in listOf(true, false)) {
            val graph = apply(nodes, throughPathEdges(nodes), options(includeStdlib = includeStdlib))
            val s = graph.stats
            assertEquals(
                s.localNodes + s.stdlibNodes + s.dependencyNodes + s.syntheticNodes, graph.nodes.size,
                "node breakdown must sum to the node total",
            )
            assertEquals(
                s.localEdges + s.stdlibEdges + s.dependencyEdges + s.syntheticEdges, graph.edges.size,
                "edge breakdown must sum to the edge total",
            )
        }
    }
}
