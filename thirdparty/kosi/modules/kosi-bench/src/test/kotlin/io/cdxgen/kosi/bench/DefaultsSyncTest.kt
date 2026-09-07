package io.cdxgen.kosi.bench

import io.cdxgen.kosi.schema.AnalyzeOptions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The golem lesson (06-CORPUS.md §5): the harness must use the CLI's option
 * defaults, or harness numbers and CLI numbers stop being comparable. Every
 * matrix slot derives from AnalyzeOptions() and overrides only its label's
 * field; this test pins that invariant from the bench side. The CLI side is
 * pinned by DefaultsFromParserTest in kosi-cli.
 */
class DefaultsSyncTest {

    @Test
    fun benchSlotsUseCliDefaults() {
        val defaults = AnalyzeOptions()
        for (slot in Matrix.defaultMatrix()) {
            val slotOptions = slot.options()
            assertEquals(
                defaults.copy(dataflow = slotOptions.dataflow, backend = slotOptions.backend),
                slotOptions,
                "slot ${slot.label} overrides more than its own dataflow/backend",
            )
        }
    }

    @Test
    fun bothShippingModesAreInTheMatrix() {
        val labels = Matrix.defaultMatrix().map { it.label }.toSet()
        assertTrue("security" in labels, "the shipping default mode must be exercised")
        assertTrue("all" in labels, "the all mode must be exercised for every case")
    }

    @Test
    fun cliDefaultDataflowIsSecurity() {
        // The default matrix's first slot mirrors the CLI default dataflow.
        assertEquals(AnalyzeOptions().dataflow.id, MatrixSlot.SECURITY_LABEL)
    }
}
