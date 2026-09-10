package io.cdxgen.kosi.export

import io.cdxgen.kosi.schema.CallGraph
import io.cdxgen.kosi.schema.CallGraphBreakdown
import io.cdxgen.kosi.schema.CallGraphEdge
import io.cdxgen.kosi.schema.CallGraphNode
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.ReachabilityEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The graph exporters: deterministic output, escaping that survives hostile
 * names, and every edge referencing nodes the document carries.
 */
class GraphExportTest {

    private fun graph(): CallGraph {
        val nodes = listOf(
            CallGraphNode(
                id = "node-000001", name = "load", qualifiedName = "src/Main.kt:t.Repo.load",
                canonicalName = "t.Repo.load", jvmDescriptor = null, kind = "method", modulePath = ".",
                purl = "pkg:generic/t", filePath = "src/Main.kt", local = true, stdlib = false,
                external = false, synthetic = false, suspend = false, visibility = "public",
                ownerVisibility = "public", receiver = null, position = Position("src/Main.kt", 3, 1),
            ),
            CallGraphNode(
                id = "node-000002", name = "println", qualifiedName = "kotlin.io:println",
                canonicalName = "kotlin.io.println&<v2>", jvmDescriptor = null, kind = "function",
                modulePath = "", purl = "", filePath = "", local = false, stdlib = true,
                external = true, synthetic = false, suspend = false, visibility = "unknown",
                ownerVisibility = null, receiver = null, position = null,
            ),
        )
        val edges = listOf(
            CallGraphEdge(
                id = "edge-000001", sourceId = "node-000001", targetId = "node-000002",
                callType = "collapsed", line = 3, column = 0, calleeText = null, receiver = null,
                method = null, candidateCount = null, emittedCandidateCount = null,
                collapsedHops = 2, collapsedPackages = listOf("kotlin.io"),
            ),
        )
        return CallGraph(
            mode = "auto",
            algorithmUsed = "vta",
            nodes = nodes,
            edges = edges,
            reachability = listOf(ReachabilityEntry("node-000001", true, 0, listOf("exported"))),
            stats = CallGraphBreakdown(1, 1, 0, 0, 0, 1, 0, 0),
            diagnostics = emptyList(),
        )
    }

    @Test
    fun graphmlEscapesAndReferencesOnlyPresentNodes() {
        val xml = GraphMl.write(graph(), "t")
        assertTrue("<node id=\"node-000001\">" in xml)
        assertTrue("<edge id=\"edge-000001\" source=\"node-000001\" target=\"node-000002\">" in xml)
        // The hostile node name must come out escaped, round-trippable XML.
        assertTrue("println&amp;&lt;v2&gt;" in xml)
        assertTrue("collapsedHops" in xml && ">2<" in xml, "the collapsed hop count travels")
    }

    @Test
    fun gexfIsDeterministicAndEscapes() {
        val a = Gexf.write(graph(), "t")
        val b = Gexf.write(graph(), "t")
        assertEquals(a, b, "two writes of one graph must be byte-identical")
        assertTrue("println&amp;&lt;v2&gt;" in a)
        assertTrue(a.contains("<edge id=\"edge-000001\"") && a.contains("target=\"node-000002\""))
    }

    @Test
    fun theFixedMetaTimestampKeepsTheArtifactDeterministic() {
        assertTrue(Gexf.write(graph(), "t").contains("1970-01-01T00:00:00Z"))
    }
}
