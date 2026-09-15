package io.cdxgen.kosi.bench

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The P5/P6 promotion checks — computed summaries with a multi-key origin
 * distribution, the default-origin share, the LIVE dependency-crossing
 * check, and the async tier's own recall — each tested through the path
 * production uses: written to a baseline file, read back with
 * [Baseline.load], then evaluated (the standing R44 rule).
 */
class SummaryGateTest {

    private fun row(
        slug: String,
        tier: String = "fixtures",
        slot: String = MatrixSlot.RESOLVED_LABEL,
        sliceCount: Int = 0,
        flowPositives: Int = 0,
        flowPositivesMatched: Int = 0,
        summariesComputed: Int? = null,
        summariesByOrigin: Map<String, Int> = emptyMap(),
        defaultOriginSlices: Int? = null,
        summaryCrossingSlices: Int? = null,
        crossDependencySlices: Int? = null,
        crossModuleSlices: Int? = null,
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
        connectivity = 1.0,
        sliceCount = sliceCount,
        integrityViolations = 0,
        wallMillis = 1,
        parseErrors = 0,
        flowPositives = flowPositives,
        flowPositivesMatched = flowPositivesMatched,
        crossDependencySlices = crossDependencySlices,
        summariesComputed = summariesComputed,
        summariesByOrigin = summariesByOrigin,
        defaultOriginSlices = defaultOriginSlices,
        summaryCrossingSlices = summaryCrossingSlices,
        crossModuleSlices = crossModuleSlices,
        digest = Digests.FixtureDigest(slug, slot, emptyMap()),
    )

    private fun result(vararg rows: BenchRunner.FixtureResult) = BenchRunner.BenchResult(
        results = rows.toList(),
        toolCommit = "test",
        medianWallMillis = 1,
        worstWallMillis = 1,
        peakRssBytes = 1,
    )

    private fun throughBaseline(result: BenchRunner.BenchResult): BenchRunner.BenchResult {
        val file: Path = Files.createTempFile("summary-gate", ".json")
        Baseline.save(result, file)
        return Baseline.load(file) ?: throw AssertionError("baseline round-trip failed")
    }

    private fun check(report: Promotion.Report, name: String): Promotion.Check =
        report.checks.singleOrNull { it.name == name } ?: error("no check named $name in:\n${report.render()}")

    // ---- summaries-computed ----------------------------------------------------

    @Test
    fun summariesComputedPassesWithMoreThanOneOriginKey() {
        val current = throughBaseline(
            result(row("a", summariesComputed = 12, summariesByOrigin = mapOf("computed" to 9, "pack" to 3))),
        )
        val check = check(Promotion.evaluate(current, null), "summaries-computed")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("origins: computed=9, pack=3"), check.detail)
    }

    @Test
    fun summariesComputedFailsWhenTheOriginDistributionCarriesOneKey() {
        // A single aggregate number cannot tell computed summaries from
        // blanket propagation — the whole point of the origin field.
        val current = throughBaseline(
            result(row("a", summariesComputed = 12, summariesByOrigin = mapOf("computed" to 12))),
        )
        val check = check(Promotion.evaluate(current, null), "summaries-computed")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("single key"), check.detail)
    }

    @Test
    fun summariesComputedFailsAtZero() {
        val current = throughBaseline(
            result(row("a", summariesComputed = 0, summariesByOrigin = emptyMap())),
        )
        val check = check(Promotion.evaluate(current, null), "summaries-computed")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("0 computed summaries"), check.detail)
    }

    @Test
    fun summariesComputedIsNotEvaluatedWithoutDataflowSlots() {
        val current = throughBaseline(result(row("a", summariesComputed = null)))
        val check = check(Promotion.evaluate(current, null), "summaries-computed")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
    }

    // ---- default-origin-share --------------------------------------------------

    @Test
    fun defaultOriginSharePassesUnderTenPercentWithBothCounts() {
        val current = throughBaseline(
            result(row("a", sliceCount = 90, defaultOriginSlices = 5, summaryCrossingSlices = 80)),
        )
        val check = check(Promotion.evaluate(current, null), "default-origin-share")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("5 of 80"), check.detail)
    }

    @Test
    fun defaultOriginShareFailsAtOrOverTenPercent() {
        val current = throughBaseline(
            result(row("a", sliceCount = 20, defaultOriginSlices = 9, summaryCrossingSlices = 80)),
        )
        val check = check(Promotion.evaluate(current, null), "default-origin-share")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("9 of 80"), check.detail)
    }

    @Test
    fun defaultOriginShareIsNotEvaluatedWhenNothingCrossedASummary() {
        val current = throughBaseline(result(row("a", sliceCount = 5, defaultOriginSlices = 0, summaryCrossingSlices = 0)))
        val check = check(Promotion.evaluate(current, null), "default-origin-share")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
        assertTrue(check.detail.contains("no slice's existence depends on propagation"), check.detail)
    }

    // ---- dependency-crossing-flows (LIVE since P5) ------------------------------

    @Test
    fun dependencyCrossingPassesOnRealCrossingsAndReportsBothKinds() {
        val current = throughBaseline(
            result(
                row("a", sliceCount = 3, crossDependencySlices = 1, crossModuleSlices = 2),
                row("async-x", tier = "async", sliceCount = 2, crossDependencySlices = 0, crossModuleSlices = 1),
            ),
        )
        val check = check(Promotion.evaluate(current, null), "dependency-crossing-flows")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("3 cross-module"), check.detail)
        assertTrue(check.detail.contains("1 cross-dependency"), check.detail)
    }

    @Test
    fun dependencyCrossingIsNotEvaluatedOverZeroCrossings() {
        val current = throughBaseline(result(row("a", sliceCount = 5, crossDependencySlices = 0, crossModuleSlices = 0)))
        val check = check(Promotion.evaluate(current, null), "dependency-crossing-flows")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
        assertTrue(check.detail.contains("0 crossing slices"), check.detail)
    }

    @Test
    fun dependencyCrossingFailsWhenTheBaselineCrossingsVanish() {
        val baseline = result(
            row("a", sliceCount = 3, crossDependencySlices = 2, crossModuleSlices = 1),
        )
        val current = throughBaseline(
            result(row("a", sliceCount = 3, crossDependencySlices = 0, crossModuleSlices = 0)),
        )
        val check = check(Promotion.evaluate(current, baseline), "dependency-crossing-flows")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("baseline measured 3"), check.detail)
    }

    // ---- async-recall (P6) -------------------------------------------------------

    @Test
    fun asyncRecallPassesAtTheTargetOnItsOwnDenominator() {
        val current = throughBaseline(
            result(
                row("fixture-a", flowPositives = 100, flowPositivesMatched = 100),
                row("async-a", tier = "async", flowPositives = 9, flowPositivesMatched = 9),
            ),
        )
        val check = check(Promotion.evaluate(current, null), "async-recall")
        assertEquals(Promotion.State.PASS, check.state)
        assertTrue(check.detail.contains("9 of 9 async flow expectations"), check.detail)
    }

    @Test
    fun asyncRecallFailsOnItsOwnDenominatorNotTheFixtureNumber() {
        // 7 async fixtures must not be diluted by the fixture tier: the
        // async misses fail the async check even with fixture recall at 1.0.
        val current = throughBaseline(
            result(
                row("fixture-a", flowPositives = 100, flowPositivesMatched = 100),
                row("async-a", tier = "async", flowPositives = 9, flowPositivesMatched = 8),
            ),
        )
        val check = check(Promotion.evaluate(current, null), "async-recall")
        assertEquals(Promotion.State.FAIL, check.state)
        assertTrue(check.detail.contains("8 of 9"), check.detail)
    }

    @Test
    fun asyncRecallIsNotEvaluatedWhenTheAsyncTierDidNotRun() {
        val current = throughBaseline(result(row("fixture-a", flowPositives = 10, flowPositivesMatched = 10)))
        val check = check(Promotion.evaluate(current, null), "async-recall")
        assertEquals(Promotion.State.NOT_EVALUATED, check.state)
        assertTrue(check.detail.contains("async tier did not run"), check.detail)
    }
}
