package io.cdxgen.kosi.bench

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The P4 promotion checks — taint recall, precision per flow, the fixpoint
 * cap and its denominator, connectivity over a NON-ZERO slice count, and the
 * per-repo flow ratchet — each tested THROUGH THE PATH PRODUCTION USES: the
 * bench result is written to a baseline file and read back with
 * [Baseline.load] before the gate sees it (the standing R44 rule).
 */
class FlowGateTest {

    private fun row(
        slug: String,
        tier: String = "fixtures",
        slot: String = MatrixSlot.RESOLVED_LABEL,
        sliceCount: Int = 0,
        flowPositives: Int = 0,
        flowPositivesMatched: Int = 0,
        flowTruePositives: Int = 0,
        fixpointCapHits: Int? = 0,
        functionsAnalysed: Int? = 10,
        connectivity: Double = 1.0,
    ): BenchRunner.FixtureResult = BenchRunner.FixtureResult(
        slug = slug,
        tier = tier,
        slot = slot,
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
        connectivity = connectivity,
        sliceCount = sliceCount,
        integrityViolations = 0,
        wallMillis = 1,
        parseErrors = 0,
        flowPositives = flowPositives,
        flowPositivesMatched = flowPositivesMatched,
        flowTruePositives = flowTruePositives,
        fixpointCapHits = fixpointCapHits,
        functionsAnalysed = functionsAnalysed,
        digest = Digests.FixtureDigest(slug, slot, emptyMap()),
    )

    private fun result(vararg rows: BenchRunner.FixtureResult): BenchRunner.BenchResult = BenchRunner.BenchResult(
        results = rows.toList(),
        toolCommit = "test",
        medianWallMillis = 1,
        worstWallMillis = 1,
        peakRssBytes = 1,
    )

    /** Writes the result to a file and reads it back the way production does. */
    private fun throughBaseline(result: BenchRunner.BenchResult): BenchRunner.BenchResult {
        val file: Path = Files.createTempFile("flow-gate", ".json")
        Baseline.save(result, file)
        return Baseline.load(file) ?: throw AssertionError("baseline round-trip failed")
    }

    private fun check(report: Promotion.Report, name: String): Promotion.Check =
        report.checks.singleOrNull { it.name == name } ?: error("no check named $name in:\n${report.render()}")

    // ---- taint recall ---------------------------------------------------------

    @Test
    fun taintRecallPassesAtTheTargetWithBothCounts() {
        val current = throughBaseline(
            result(
                row("a", flowPositives = 8, flowPositivesMatched = 8, functionsAnalysed = 1),
                row("b", flowPositives = 8, flowPositivesMatched = 7, functionsAnalysed = 1),
            ),
        )
        val check = check(Promotion.evaluate(current, null), "taint-recall")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("(15 of 16 flow expectations)"), check.detail)
    }

    @Test
    fun taintRecallFailsBelowTheTarget() {
        val current = throughBaseline(
            result(row("a", flowPositives = 10, flowPositivesMatched = 5, functionsAnalysed = 1)),
        )
        val check = check(Promotion.evaluate(current, null), "taint-recall")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("0.5000 < 0.85"), check.detail)
    }

    @Test
    fun taintRecallIsNotEvaluatedWithoutLiveFlowExpectations() {
        val current = throughBaseline(result(row("a", functionsAnalysed = 1)))
        val check = check(Promotion.evaluate(current, null), "taint-recall")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
        assertTrue(check.detail.contains("nothing to recall"), check.detail)
    }

    // ---- precision per flow -------------------------------------------------

    @Test
    fun precisionFailsWhenUnaskedSlicesAreReported() {
        val current = throughBaseline(
            result(row("a", sliceCount = 4, flowPositives = 1, flowPositivesMatched = 1, flowTruePositives = 1)),
        )
        val check = check(Promotion.evaluate(current, null), "precision-per-flow")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("1 of 4 slices"), check.detail)
    }

    @Test
    fun precisionPassesWhenEverySliceWasAskedFor() {
        val current = throughBaseline(
            result(row("a", sliceCount = 4, flowPositives = 4, flowPositivesMatched = 4, flowTruePositives = 4)),
        )
        val check = check(Promotion.evaluate(current, null), "precision-per-flow")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("(4 of 4 slices)"), check.detail)
    }

    @Test
    fun precisionIsNotEvaluatedWithoutSlices() {
        val current = throughBaseline(result(row("a", functionsAnalysed = 1)))
        val check = check(Promotion.evaluate(current, null), "precision-per-flow")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
    }

    // ---- fixpoint cap ----------------------------------------------------------

    @Test
    fun fixpointCapPassesAtZeroOverTheAnalysedDenominator() {
        val current = throughBaseline(
            result(row("a", fixpointCapHits = 0, functionsAnalysed = 42), row("b", fixpointCapHits = 0, functionsAnalysed = 58)),
        )
        val check = check(Promotion.evaluate(current, null), "fixpoint-cap")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("0 cap hits over 100 analysed function(s)"), check.detail)
    }

    @Test
    fun fixpointCapFailsOnAnyHit() {
        val current = throughBaseline(
            result(row("a", fixpointCapHits = 2, functionsAnalysed = 42)),
        )
        val check = check(Promotion.evaluate(current, null), "fixpoint-cap")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("2 cap hit(s) over 42"), check.detail)
    }

    // ---- connectivity ------------------------------------------------------------

    @Test
    fun connectivityOverZeroSlicesIsNotEvaluatedNotPassed() {
        val current = throughBaseline(result(row("a", sliceCount = 0, functionsAnalysed = 1)))
        val check = check(Promotion.evaluate(current, null), "connectivity")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state, "1.000 over 0 slices is a vacuous pass (R49's shape)")
    }

    @Test
    fun connectivityOverSlicesPassesWithTheCount() {
        val current = throughBaseline(result(row("a", sliceCount = 7, functionsAnalysed = 1)))
        val check = check(Promotion.evaluate(current, null), "connectivity")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("1.000 over 7 slice(s)"), check.detail)
    }

    // ---- per-repo flow ratchet ------------------------------------------------------

    @Test
    fun perRepoFlowCountsAreNotEvaluatedAgainstAPreFlowBaseline() {
        val baseline = throughBaseline(
            result(row("legacy", tier = "medium", slot = MatrixSlot.RESOLVED_LABEL, functionsAnalysed = null)),
        )
        val current = throughBaseline(
            result(row("legacy", tier = "medium", slot = MatrixSlot.RESOLVED_LABEL, sliceCount = 3)),
        )
        val check = check(Promotion.evaluate(current, baseline), "per-repo-flow-counts")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
        assertTrue(check.detail.contains("no flow data"), check.detail)
    }

    @Test
    fun perRepoFlowCountsFailWhenARepoLosesSlices() {
        val baseline = throughBaseline(
            result(row("repo", tier = "medium", slot = MatrixSlot.RESOLVED_LABEL, sliceCount = 5, functionsAnalysed = 100)),
        )
        val current = throughBaseline(
            result(row("repo", tier = "medium", slot = MatrixSlot.RESOLVED_LABEL, sliceCount = 0, functionsAnalysed = 100)),
        )
        val check = check(Promotion.evaluate(current, baseline), "per-repo-flow-counts")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("slices 5 -> 0"), check.detail)
    }

    // ---- the whole gate -------------------------------------------------------------

    @Test
    fun theGateDropsNotEvaluatedVerdictsIntoHold() {
        // One fixture across all four slots (so coverage holds) with no flow
        // data at all: every unevaluatable criterion must hold the gate, not
        // pass it.
        val current = throughBaseline(
            result(
                row("a", slot = MatrixSlot.SECURITY_LABEL, functionsAnalysed = 1),
                row("a", slot = MatrixSlot.ALL_LABEL, functionsAnalysed = 1),
                row("a", slot = MatrixSlot.RESOLVED_LABEL, functionsAnalysed = 1),
                row("a", slot = MatrixSlot.EXPORTED_LABEL, functionsAnalysed = 1),
            ),
        )
        val report = Promotion.evaluate(current, null)
        assertEquals("HOLD (criteria unevaluated)", report.verdict)
    }
}
