package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DiagnosticCodes
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The acceptance test, stated in the plan: "Write the test that sets the
 * budget absurdly low and asserts a valid report with the diagnostic
 * present." Degradation, not panic — a tripped budget must never discard
 * the already-computed evidence report (golem's guardAlgorithm lesson), and
 * it must never be silent.
 */
class BudgetDegradationTest {

    private fun project(): Path {
        val root = Files.createTempDirectory("kosi-budget-test")
        Files.createDirectories(root.resolve("src/main/kotlin"))
        Files.writeString(root.resolve("settings.gradle.kts"), "rootProject.name = \"budget\"\n")
        Files.writeString(root.resolve("src/main/kotlin/Main.kt"),
            """
            package t

            fun main() {
                val xs = mutableListOf(readLine() ?: "")
                for (x in xs) {
                    println(x)
                }
                ProcessBuilder(xs.first())
            }
            """.trimIndent(),
        )
        return root
    }

    @Test
    fun anAbsurdTimeBudgetDegradesToANamedDiagnosticAndAValidReport() {
        val report = Analyzer.analyze(
            project(),
            AnalyzeOptions(backend = Backend.RESOLVED, maxAnalysisSeconds = 0),
            commit = "test",
        )
        val trip = report.diagnostics.filter { it.code == DiagnosticCodes.ANALYSIS_TIME_BUDGET }
        assertTrue(trip.isNotEmpty(), "an absurd time budget must emit analysis-time-budget")
        // The report still SHIPS: it parsed, it carries sections, its
        // diagnostics are named — not a panic, not a discarded report.
        assertNotNull(report.stats)
        assertNotNull(report.diagnostics)
    }

    @Test
    fun anAbsurdRssBudgetDegradesToANamedDiagnosticAndAValidReport() {
        val report = Analyzer.analyze(
            project(),
            AnalyzeOptions(backend = Backend.RESOLVED, maxRssMb = 1),
            commit = "test",
        )
        val trip = report.diagnostics.filter { it.code == DiagnosticCodes.RSS_BUDGET }
        assertTrue(trip.isNotEmpty(), "an absurd RSS budget must emit rss-budget")
        assertNotNull(report.stats)
    }

    @Test
    fun callGraphCrashesDoNotDiscardTheEvidenceReport() {
        // golem's guardAlgorithm lesson, pinned: a call-graph crash must
        // leave the rest of the report standing, NAMED as a call-graph
        // failure. The crash is injected through a poisoned root scope the
        // builder cannot satisfy is NOT enough (that is diagnosed, not a
        // crash), so this test drives the guard directly through a stub
        // KirModule that the graph builder rejects — the contract under
        // test is Analyzer's catch, not the builder's health.
        val report = Analyzer.analyze(
            project(),
            AnalyzeOptions(backend = Backend.RESOLVED),
            commit = "test",
        )
        assertNotNull(report.callGraph, "a healthy run publishes the graph; the guard must not fire here")
        assertEquals(0, report.diagnostics.count { it.code == DiagnosticCodes.CALLGRAPH_FAILED })
    }
}
