package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P10's parallelism contract: `--dataflow-workers > 1` must produce a
 * byte-identical REPORT at any worker width — parallel speedup is worthless
 * if ids, slices or digests shift with the schedule.
 */
class WorkerDeterminismTest {

    private fun project(): Path {
        val root = Files.createTempDirectory("kosi-workers-test")
        Files.createDirectories(root.resolve("src/main/kotlin"))
        Files.writeString(root.resolve("settings.gradle.kts"), "rootProject.name = \"workers\"\n")
        // Enough interprocedural surface that per-function scheduling actually
        // varies: several callers, callees, a lambda, a loop.
        Files.writeString(root.resolve("src/main/kotlin/Main.kt"),
            """
            package t

            fun sinkOf(value: String) {
                ProcessBuilder(value)
            }

            fun sourceOf(): String = readLine() ?: "x"

            fun pipeline(a: String): String = "pre:" + a

            fun pipeline(b: Int): String = b.toString()

            fun runner() {
                repeat(3) { n ->
                    sinkOf(pipeline(sourceOf() + n))
                }
                val later = { v: String -> sinkOf(v) }
                later(sourceOf())
            }

            fun secondRunner() {
                val raw = sourceOf()
                sinkOf(pipeline(raw))
                sinkOf(raw)
            }
            """.trimIndent(),
        )
        return root
    }

    @Test
    fun workerWidthDoesNotChangeTheEvidence() {
        val root = project()
        fun evidence(workers: Int): io.cdxgen.kosi.schema.DataFlowEvidence =
            Analyzer.analyze(
                root,
                AnalyzeOptions(backend = Backend.RESOLVED, dataflowWorkers = workers),
                commit = "test",
            ).dataFlow!!

        // The comparison is meaningful only if the fixture produced slices.
        assertTrue(evidence(1).slices.isNotEmpty(), "the fixture must produce slices for this comparison to bite")
        assertEquals(evidence(1), evidence(4), "workers=4 must not change the evidence")
        assertEquals(evidence(1), evidence(8), "workers=8 must not change the evidence")
    }
}
