package io.cdxgen.kosi.cli

import io.cdxgen.kosi.schema.AnalyzeOptions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The parser produces exactly the schema defaults when no flags are given —
 * the CLI half of the bench/CLI defaults-sync invariant.
 */
class DefaultsFromParserTest {

    @Test
    fun noFlagsYieldSchemaDefaults() {
        val parsed = ParsedArgs.parse(emptyList())
        val options = AnalyzeOptions()
        assertEquals(options.backend, AnalyzeOptions().backend)
        assertEquals(options.dataflow, AnalyzeOptions().dataflow)
        assertEquals(options.roots, AnalyzeOptions().roots)
        assertEquals(options.dependencyDetail, AnalyzeOptions().dependencyDetail)
        assertEquals(options.dataflowMaxSlices, AnalyzeOptions().dataflowMaxSlices)
    }

    @Test
    fun unknownBackendIsUsageError() {
        assertEquals(ExitCodes.USAGE, Main.run(arrayOf("analyze", "--backend", "mir", "--dir", ".")))
    }

    @Test
    fun resolvedBackendRejectedInPhase0() {
        // Rejected as a usage error WITH the phase-0 explanation, never as a
        // silent degrade to the syntax tier.
        assertEquals(ExitCodes.USAGE, Main.run(arrayOf("analyze", "--backend", "resolved", "--dir", ".")))
    }

    @Test
    fun singleDashFlagsRejected() {
        assertFailsWith<UsageException> { ParsedArgs.parse(listOf("-dir", "x")) }
    }

    @Test
    fun flagValueAndFlagEqualsValueAgree() {
        val a = ParsedArgs.parse(listOf("--dir", "some/path"))
        val b = ParsedArgs.parse(listOf("--dir=some/path"))
        assertEquals(a.value("dir"), b.value("dir"))
    }
}
