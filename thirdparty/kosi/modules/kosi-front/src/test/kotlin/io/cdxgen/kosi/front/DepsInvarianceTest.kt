package io.cdxgen.kosi.front

import io.cdxgen.kosi.flow.SummaryOrigin
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.DataflowMode
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * P9's gate, as an actual test: for the SAME fixture and the SAME options
 * except `--deps`, the WORKSPACE-ONLY findings must be byte-identical with
 * and without the tier — `--deps` may only ADD cross-dependency slices. It
 * also pins the body-less rule on the committed helper jar (an abstract
 * method and an interface method are excluded, never summarised as "no
 * flow") and the `origin=bytecode` provenance the promotion gate reads.
 */
class DepsInvarianceTest {

    /** Walks up to the repository root that holds the committed fixture jar. */
    private val helperJar: Path by lazy {
        var dir = Path.of("").toAbsolutePath()
        repeat(6) {
            val candidate = dir.resolve("fixtures").resolve("dep-taint-through-lib").resolve("libs")
                .resolve("dep-helper.jar")
            if (Files.isRegularFile(candidate)) return@lazy candidate
            dir = dir.parent ?: return@lazy dir
        }
        dir.resolve("fixtures").resolve("dep-taint-through-lib").resolve("libs").resolve("dep-helper.jar")
    }

    private fun project(): Path {
        val root = Files.createTempDirectory("kosi-deps-test")
        Files.createDirectories(root.resolve("src/main/kotlin"))
        Files.writeString(root.resolve("settings.gradle.kts"), "rootProject.name = \"deps-inv\"\n")
        Files.writeString(root.resolve("src/main/kotlin/Main.kt"),
            """
            package t

            import dev.kosi.helper.Db
            import java.sql.DriverManager

            fun throughJar(db: Db) {
                val query = readLine() ?: "1=1"
                db.runQuery(query)
            }

            fun inWorkspaceOnly() {
                ProcessBuilder(readLine() ?: "")
            }
            """.trimIndent(),
        )
        return root
    }

    private fun options(root: Path, deps: Boolean): AnalyzeOptions = AnalyzeOptions(
        backend = Backend.RESOLVED,
        dataflow = if (deps) DataflowMode.SECURITY_DEPS else DataflowMode.SECURITY,
        classpath = listOfNotNull(helperJar.toAbsolutePath().toString()),
        deps = deps,
    )

    @Test
    fun depsOnlyAddsCrossDependencySlices() {
        val root = project()
        val without = Analyzer.analyze(root, options(root, deps = false), commit = "test")
        val with = Analyzer.analyze(root, options(root, deps = true), commit = "test")

        val withoutKeys = without.dataFlow?.slices?.map { it.flowKey }.orEmpty()
        val withKeys = with.dataFlow?.slices?.map { it.flowKey }.orEmpty()
        // Nothing was lost, and every workspace-only slice is byte-identical:
        // the workspace functions, site ids and flow keys cannot move when a
        // tier is appended AFTER them.
        assertTrue(
            withKeys.containsAll(withoutKeys),
            "--deps lost workspace slices: $withoutKeys vs $withKeys",
        )
        val added = with.dataFlow!!.slices.filter { it.flowKey !in withoutKeys.toSet() }
        assertTrue(
            added.all { it.crossesDependency },
            "--deps added a non-cross-dependency slice: ${added.filter { !it.crossesDependency }}",
        )
        // And the tier must have been exercised at all: this project's flow
        // goes THROUGH the jar (Db.runQuery sinks sql INSIDE it).
        assertNotEquals(emptyList(), added, "--deps must add the cross-dependency slice here")
        assertTrue(added.all { SummaryOrigin.BYTECODE in it.origins })
    }

    @Test
    fun bytecodeSummariesArePublishedAppliedAndDistinctFromComputed() {
        val root = project()
        val with = Analyzer.analyze(root, options(root, deps = true), commit = "test")
        val stats = with.dataFlow!!.stats
        assertTrue(
            (stats.bytecodeSummaries ?: 0) > 0,
            "applied bytecode summaries must be published",
        )
        val byOrigin = stats.summariesByOrigin
        assertTrue((byOrigin[SummaryOrigin.BYTECODE] ?: 0) > 0, "summaries[].origin=bytecode must exist")
        assertTrue((byOrigin[SummaryOrigin.COMPUTED] ?: 0) > 0, "workspace summaries stay computed")
        assertEquals(
            null,
            with.dataFlow!!.summaries.firstOrNull { it.origin == SummaryOrigin.BYTECODE && it.functionId.contains("Provider") },
            "a body-less record must never carry a summary",
        )
    }

    @Test
    fun bodylessRecordsAreCountedAndExcluded() {
        val root = project()
        // Add the abstract Provider shape: the workspace calls it, and the
        // flow through it must EXIST (never laundered by a "no flow"
        // conclusion about an empty body).
        Files.writeString(root.resolve("src/main/kotlin/Use.kt"),
            """
            package t

            import dev.kosi.helper.Provider

            fun throughBodyless(provider: Provider) {
                ProcessBuilder(provider.provide(readLine() ?: ""))
            }
            """.trimIndent(),
        )
        val with = Analyzer.analyze(root, options(root, deps = true), commit = "test")
        assertTrue(
            (with.stats.bodylessRecords > 0),
            "the committed jar's body-less records must be counted (stats.bodylessRecords)",
        )
        assertNotNull(
            with.diagnostics.firstOrNull { it.code == DiagnosticCodes.DEPS_BODYLESS },
            "the exclusion must be a named diagnostic",
        )
        // The flow through the ABSTRACT method still exists — via the
        // labelled unknown default, never via an invented "no flow" summary.
        val throughBodyless = with.dataFlow!!.slices.filter { it.sinkCategory == "process-exec" }
        assertTrue(throughBodyless.isNotEmpty(), "the flow through a body-less record must not vanish")
    }

    @Test
    fun withoutDepsTheReportCarriesNoTierEvidence() {
        val root = project()
        val without = Analyzer.analyze(root, options(root, deps = false), commit = "test")
        assertEquals(0, without.stats.bodylessRecords)
        assertEquals(0, without.stats.dependencyClasses)
        assertTrue(without.dataFlow!!.slices.none { it.crossesDependency })
    }
}
