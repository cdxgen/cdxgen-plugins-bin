package io.cdxgen.kosi.bench

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The per-repo resolved-call-ratio gate (P1). Negative cases first: the check
 * must FAIL on a regression and on a repo falling through the target, and it
 * must report NOT_EVALUATED — never PASS — when it has nothing to look at.
 * A gate that cannot see the thing it checks was the P0 review's recurring
 * defect; these are the tests that fail if this one is disabled.
 */
class ResolvedRatioGateTest {

    private fun repo(slug: String, ratio: Double?, slot: String = "resolved"): BenchRunner.FixtureResult =
        BenchRunner.FixtureResult(
            slug = slug,
            tier = "medium",
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
            sliceCount = 0,
            integrityViolations = 0,
            wallMillis = 1,
            parseErrors = 0,
            resolvedCallRatio = ratio,
            digest = Digests.FixtureDigest(slug = slug, slot = slot, sections = emptyMap()),
        )

    private fun result(vararg results: BenchRunner.FixtureResult) = BenchRunner.BenchResult(
        results = results.toList(),
        toolCommit = "test",
        medianWallMillis = 1,
        worstWallMillis = 1,
        peakRssBytes = 1,
    )

    private fun check(
        current: BenchRunner.BenchResult,
        baseline: BenchRunner.BenchResult?,
    ): Promotion.Check =
        Promotion.evaluate(current, baseline).checks.single { it.name == "per-repo-resolved-call-ratio" }

    @Test
    fun aDropBelowTheBaselineFails() {
        val c = check(result(repo("spring-fu", 0.80)), result(repo("spring-fu", 0.94)))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("spring-fu" in c.detail, c.detail)
    }

    @Test
    fun fallingThroughTheTargetFails() {
        // Within tolerance of the baseline, but across the 0.90 line.
        val c = check(result(repo("spring-fu", 0.8995)), result(repo("spring-fu", 0.9000)))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
    }

    @Test
    fun holdingBelowTheTargetPassesButNamesTheRepo() {
        // Repos below the target are held at their measured value: the number
        // ratchets, and the detail line names them rather than hiding them.
        val c = check(result(repo("kampkit", 0.6639)), result(repo("kampkit", 0.6639)))
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("kampkit" in c.detail && "0.6639" in c.detail, c.detail)
    }

    @Test
    fun noRepoTiersIsNotEvaluatedRatherThanPass() {
        val fixtureOnly = repo("weak-crypto", 1.0).copy(tier = "fixtures")
        val c = check(result(fixtureOnly), result(fixtureOnly))
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
    }

    @Test
    fun aMissingRatioFailsInsteadOfBeingSkipped() {
        val c = check(result(repo("spring-fu", null)), result(repo("spring-fu", 0.94)))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
    }

    @Test
    fun noBaselineIsNotEvaluatedAndStillReportsTheMeasurement() {
        val c = check(result(repo("spring-fu", 0.94)), null)
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
        assertTrue("0.9400" in c.detail, c.detail)
    }
}
