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
                defaults.copy(
                    dataflow = slotOptions.dataflow,
                    backend = slotOptions.backend,
                    roots = slotOptions.roots,
                    endpointSources = slotOptions.endpointSources,
                ),
                slotOptions,
                "slot ${slot.label} overrides more than its own dataflow/backend/roots/endpointSources",
            )
        }
    }

    @Test
    fun bothShippingModesAreInTheMatrix() {
        val labels = Matrix.defaultMatrix().map { it.label }.toSet()
        assertTrue("security" in labels, "the shipping default mode must be exercised")
        assertTrue("all" in labels, "the all mode must be exercised for every case")
        assertTrue("resolved" in labels, "the resolved backend must be exercised for every case (P1)")
    }

    @Test
    fun resolvedSlotRunsTheResolvedBackend() {
        val resolved = Matrix.defaultMatrix().single { it.label == "resolved" }
        assertEquals(io.cdxgen.kosi.schema.Backend.RESOLVED, resolved.backend)
    }

    @Test
    fun exportedSlotRootsAtThePublicApi() {
        // P3: a library yields nothing from `main` alone (golem's lesson);
        // the exported slot is where the edge gates get a real denominator.
        val exported = Matrix.defaultMatrix().single { it.label == "exported" }
        assertEquals(io.cdxgen.kosi.schema.Backend.RESOLVED, exported.backend)
        assertEquals(listOf(io.cdxgen.kosi.schema.RootScope.EXPORTED.id), exported.options().roots)
    }

    @Test
    fun theExportedSlotIsInTheMatrixForEveryCase() {
        val labels = Matrix.defaultMatrix().map { it.label }.toSet()
        assertTrue("exported" in labels, "the exported slot must run for every corpus case (P3)")
    }

    @Test
    fun theEndpointSlotRootsTaintAtHandlers() {
        // P7: the endpoint slot is where endpoint-rooted slices come from;
        // without it the endpoint-rooted-slices gate has no population.
        val endpoint = Matrix.defaultMatrix().single { it.label == MatrixSlot.ENDPOINT_LABEL }
        assertEquals(io.cdxgen.kosi.schema.Backend.RESOLVED, endpoint.backend)
        assertTrue(endpoint.endpointSources)
        assertTrue(endpoint.options().endpointSources)
    }

    @Test
    fun cliDefaultDataflowIsSecurity() {
        // The default matrix's first slot mirrors the CLI default dataflow.
        assertEquals(AnalyzeOptions().dataflow.id, MatrixSlot.SECURITY_LABEL)
    }
}
