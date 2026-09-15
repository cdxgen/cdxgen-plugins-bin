package io.cdxgen.kosi.bench

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The P2 lowering gate. P2 reported `loweringFailures` empty on every fixture
 * and 0.000% on the pinned repos, but nothing in `Promotion` looked at the
 * map: the number was measured once, by hand, and could regress to any value
 * without a check firing. These are the tests that fail when the check is
 * removed — negative cases first.
 */
class LoweringGateTest {

    private fun slot(
        slug: String,
        tier: String,
        functions: Int?,
        failures: Map<String, Int> = emptyMap(),
    ): BenchRunner.FixtureResult = BenchRunner.FixtureResult(
        slug = slug,
        tier = tier,
        slot = MatrixSlot.RESOLVED_LABEL,
        annotations = 0,
        positives = 0,
        negatives = 0,
        pass = 0,
        fail = 0,
        xfail = 0,
        xpass = 0,
        positivesPassed = 0,
        positivesRecallDenominator = 0,
        recall = 1.0,
        connectivity = 1.0,
        sliceCount = 0,
        integrityViolations = 0,
        wallMillis = 1,
        parseErrors = 0,
        resolvedCallRatio = 1.0,
        callsTotal = 10,
        callsResolved = 10,
        loweringFailures = failures,
        functionsLowered = functions,
        digest = Digests.FixtureDigest(slug, MatrixSlot.RESOLVED_LABEL, emptyMap()),
    )

    private fun gate(vararg results: BenchRunner.FixtureResult): Promotion.Check {
        val bench = BenchRunner.BenchResult(
            results = results.toList(),
            toolCommit = "test",
            medianWallMillis = 1,
            worstWallMillis = 1,
            peakRssBytes = 1,
        )
        return Promotion.evaluate(bench, bench).checks.single { it.name == "lowering-failures" }
    }

    @Test
    fun aFixtureThatFailsToLowerIsAFailure() {
        val check = gate(slot("sealed-when", "fixtures", functions = 12, failures = mapOf("when-subject" to 1)))
        assertEquals(Promotion.State.FAIL, check.state, check.detail)
        assertTrue("sealed-when" in check.detail, check.detail)
        // The count travels with the denominator it was measured over.
        assertTrue("1 of 12 functions" in check.detail, check.detail)
        assertTrue("when-subject" in check.detail, "the failure must be itemised by construct: ${check.detail}")
    }

    @Test
    fun aRepoAboveTheRateCeilingIsAFailure() {
        // 20 of 1000 = 2%, over the 0.5% ceiling.
        val check = gate(
            slot("nowinandroid", "medium", functions = 1000, failures = mapOf("infix-call" to 20)),
        )
        assertEquals(Promotion.State.FAIL, check.state, check.detail)
        assertTrue("20 of 1000 functions" in check.detail, check.detail)
        assertTrue("infix-call" in check.detail, check.detail)
    }

    @Test
    fun aRepoUnderTheRateCeilingPasses() {
        // 2 of 1000 = 0.2%, under the ceiling; fixtures stay clean.
        val check = gate(
            slot("weak-crypto", "fixtures", functions = 8),
            slot("nowinandroid", "medium", functions = 1000, failures = mapOf("infix-call" to 2)),
        )
        assertEquals(Promotion.State.PASS, check.state, check.detail)
        assertTrue("2 of 1000" in check.detail, check.detail)
    }

    @Test
    fun aRunThatLoweredNothingIsNotEvaluatedRatherThanPassing() {
        // The gate must never pass by having nothing to look at — the
        // recurring defect this whole family of tests exists for.
        val check = gate(slot("syntax-only", "fixtures", functions = 0))
        assertEquals(Promotion.State.NOT_EVALUATED, check.state, check.detail)
    }

    @Test
    fun aCleanFixtureRunNamesTheFunctionCountItProves() {
        val check = gate(slot("weak-crypto", "fixtures", functions = 8))
        assertEquals(Promotion.State.PASS, check.state, check.detail)
        // "clean" over an unstated number of functions is the metric-without-
        // a-denominator defect; the count must be in the detail line.
        assertTrue("8 functions" in check.detail, check.detail)
    }
}
