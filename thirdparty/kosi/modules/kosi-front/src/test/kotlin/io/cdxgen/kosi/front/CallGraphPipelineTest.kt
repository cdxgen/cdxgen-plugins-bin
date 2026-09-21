package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.RootScope
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The call graph through the PRODUCTION pipeline: Analyzer.analyze on a
 * real project directory, the same path the CLI and the bench run. Negative
 * cases first: a graph missing its edges silently, a stdlib filter that is
 * always-true (golem's defect), an exported root set that misses the public
 * API.
 */
class CallGraphPipelineTest {

    private fun project(sources: Map<String, String>): Path {
        val root = Files.createTempDirectory("kosi-graph-pipeline")
        for ((path, text) in sources) {
            val file = root.resolve(path)
            Files.createDirectories(file.parent)
            file.writeText(text)
        }
        return root
    }

    private val library = mapOf(
        "src/main/kotlin/Csv.kt" to """
            package t

            public class Writer(private val sep: Char) {
                public fun row(cells: List<String>): String = cells.joinToString(sep.toString())
                public fun render(rows: List<List<String>>): String {
                    var out = ""
                    for (r in rows) out = out + row(r)
                    return out
                }
            }

            public fun parse(line: String): List<String> = line.split(',')

            internal fun normalize(lines: List<String>): List<String> = lines.filter { it.isNotBlank() }

            private fun deadHelper(): Int = 42
        """.trimIndent(),
    )

    @Test
    fun aSeveredWitnessPathWouldBeALieSoEveryReachedNodeIsWitnessed() {
        val root = project(library)
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, roots = listOf(RootScope.EXPORTED.id)),
            commit = "test",
        )
        val graph = assertNotNull(report.callGraph)
        val adjacency = graph.edges.groupBy({ it.sourceId }, { it.targetId })
        val roots = graph.reachability.filter { it.distance == 0 }.map { it.nodeId }.toSet()
        val reached = graph.reachability.filter { it.reached }.map { it.nodeId }
        assertTrue(reached.isNotEmpty(), "exported roots reach the public API on a library")
        // BFS over the EMITTED edges must confirm every reached node.
        val seen = HashSet<String>()
        val queue = ArrayDeque(roots.sorted())
        seen.addAll(roots)
        while (queue.isNotEmpty()) {
            for (next in adjacency[queue.removeFirst()].orEmpty()) {
                if (seen.add(next)) queue.addLast(next)
            }
        }
        assertEquals(reached.size, reached.count { it in seen }, "a reached node without a witness path is a lie")
        // Edges reference nodes the document actually carries.
        val ids = graph.nodes.map { it.id }.toSet()
        assertTrue(graph.edges.all { it.sourceId in ids && it.targetId in ids })
    }

    @Test
    fun includeStdlibChangesTheGraphThroughTheRealPipeline() {
        val root = project(
            mapOf(
                "src/main/kotlin/App.kt" to """
                    package t

                    fun main() {
                        println(listOf("a").size)
                    }
                """.trimIndent(),
            ),
        )
        val off = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test").callGraph!!
        val on = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, includeStdlib = true),
            commit = "test",
        ).callGraph!!
        assertTrue(on.stats.stdlibNodes > 0, "include-stdlib on keeps stdlib nodes")
        assertEquals(0, off.stats.stdlibNodes + off.stats.stdlibEdges, "the default view drops them")
        assertTrue(on.stats.stdlibEdges > 0, "main calls into the stdlib: those edges exist when included")
        val onNodes = on.stats.localNodes + on.stats.stdlibNodes + on.stats.dependencyNodes + on.stats.syntheticNodes
        val offNodes = off.stats.localNodes + off.stats.stdlibNodes + off.stats.dependencyNodes + off.stats.syntheticNodes
        assertTrue(onNodes > offNodes, "the toggle must move the counts, not the caption")
    }

    @Test
    fun callgraphNonePublishesNoGraph() {
        val root = project(library)
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, callgraph = io.cdxgen.kosi.schema.CallGraphMode.NONE),
            commit = "test",
        )
        assertNull(report.callGraph)
    }

    @Test
    fun exportedReachOnALibraryIsAboveTheGateBar() {
        val root = project(library)
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, roots = listOf(RootScope.EXPORTED.id)),
            commit = "test",
        )
        val graph = assertNotNull(report.callGraph)
        val reached = graph.reachability.filter { it.reached }.map { it.nodeId }.toSet()
        val public = graph.nodes.filter {
            it.local && !it.synthetic && (it.visibility == "public" || it.visibility == "protected")
        }
        assertTrue(public.isNotEmpty(), "the library exposes public callables")
        val fraction = public.count { it.id in reached }.toDouble() / public.size
        assertTrue(fraction >= 0.95, "exported reach $fraction below the 0.95 gate (${public.map { it.canonicalName }})")
    }

    @Test
    fun deadPrivateCodeIsNeverReportedAsReached() {
        val root = project(library)
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, roots = listOf(RootScope.EXPORTED.id)),
            commit = "test",
        )
        val graph = assertNotNull(report.callGraph)
        val dead = graph.nodes.filter { it.canonicalName.contains("deadHelper") }
        assertEquals(1, dead.size)
        val entry = graph.reachability.first { it.nodeId == dead.single().id }
        assertEquals(false, entry.reached, "a private uncalled function is not reachable from exported roots")
    }

    @Test
    fun sealedNarrowingSurvivesThePipeline() {
        val root = project(
            mapOf(
                "src/main/kotlin/Tickets.kt" to """
                    package t

                    sealed class Ticket {
                        abstract fun price(): Int
                        object Walkup : Ticket() {
                            override fun price() = 20
                        }
                        data class Advance(val days: Int) : Ticket() {
                            override fun price() = 15 - days
                        }
                    }

                    fun total(t: Ticket): Int = t.price()
                """.trimIndent(),
            ),
        )
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, roots = listOf(RootScope.EXPORTED.id)),
            commit = "test",
        )
        val graph = assertNotNull(report.callGraph)
        val dispatch = graph.edges.filter { it.callType.startsWith("sealed-") }
        assertEquals(2, dispatch.size, "both members of the sealed hierarchy are live targets")
        assertTrue(
            graph.edges.none { it.callType == "interface-cha" },
            "a sealed hierarchy must not carry the open-hierarchy label",
        )
    }

    /**
     * A later review. `--dataflow reachable` names what was ASKED
     * for; the intersection that makes a slice reachable needs a call
     * GRAPH, and `--callgraph none` publishes none — so in that pairing
     * reachability is not computed at all and the only honest count is 0.
     * Replaced a `reachableFromRoots` flag that was false everywhere
     * with a count keyed off the mode, which read "every slice reachable"
     * for a run that had measured nothing: the rule broken inside the
     * change that was applying it, and the unmeasured answer was the
     * OPPOSITE of the measured one on the very first project tried.
     *
     * Restoring the defect (keying either count off the mode instead of the
     * intersection) turns the second half of this test red while the first
     * half — the real, graph-backed count — stays green, which is the pair
     * that makes it a gate rather than a constant.
     */
    @Test
    fun aReachableCountWithoutACallGraphCountsNothing() {
        val root = project(
            mapOf(
                "src/main/kotlin/Relay.kt" to """
                    package t

                    private fun unreached() {
                        val raw = readLine()!!
                        ProcessBuilder(raw).start()
                    }
                """.trimIndent(),
            ),
        )
        val withGraph = Analyzer.analyze(
            root,
            AnalyzeOptions(
                backend = Backend.RESOLVED,
                dataflow = io.cdxgen.kosi.schema.DataflowMode.REACHABLE,
                roots = listOf(RootScope.EXPORTED.id),
            ),
            commit = "test",
        )
        assertNotNull(withGraph.callGraph, "the graph-backed leg must actually have a graph")
        val graphFlow = assertNotNull(withGraph.dataFlow)
        // The intersection is the authority, and the summary reads it rather
        // than deriving a second answer: one question, one piece of code.
        assertEquals(
            graphFlow.slices.size,
            graphFlow.stats.reachableSlices,
            "reachable mode publishes only the slices that survived the intersection",
        )
        assertEquals(
            graphFlow.stats.reachableSlices,
            withGraph.stats.reachableSliceCount,
            "the summary's count is the intersection's count, never re-derived from the mode",
        )

        val noGraph = Analyzer.analyze(
            root,
            AnalyzeOptions(
                backend = Backend.RESOLVED,
                dataflow = io.cdxgen.kosi.schema.DataflowMode.REACHABLE,
                callgraph = io.cdxgen.kosi.schema.CallGraphMode.NONE,
                roots = listOf(RootScope.EXPORTED.id),
            ),
            commit = "test",
        )
        assertNull(noGraph.callGraph, "--callgraph none publishes no graph")
        val blindFlow = assertNotNull(noGraph.dataFlow)
        assertTrue(
            blindFlow.slices.isNotEmpty(),
            "the fixture must publish slices, or the zero below proves nothing",
        )
        assertEquals(
            0,
            blindFlow.stats.reachableSlices,
            "no call graph means reachability was never computed: the honest count is 0, not " +
                "every slice. This read ${blindFlow.slices.size} before the fix, for a project" +
                "whose graph-backed answer is ${graphFlow.stats.reachableSlices}",
        )
        assertEquals(
            0,
            noGraph.stats.reachableSliceCount,
            "and the summary must not re-derive what the engine refused to claim",
        )
    }
}
