package io.cdxgen.kosi.bench

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The findings ratchet. The vuln tiers' deliberately vulnerable apps
 * are the only repo-tier rows whose FINDINGS are the point, and until this
 * check a change could take any of them to zero with a green build — which
 * is exactly how kosi arrived at reporting zero findings on every real
 * repo. Negative cases first: below the floor fails, a missing warm
 * classpath fails, a materially-above-floor reading fails until the floor
 * is raised, and a run with no floors is NOT_EVALUATED, never a pass.
 */
class VulnFindingFloorGateTest {

    private fun vuln(
        slug: String,
        slices: Int,
        floor: Int?,
        classpathMissing: Boolean? = null,
        slot: String = MatrixSlot.RESOLVED_LABEL,
    ): BenchRunner.FixtureResult =
        BenchRunner.FixtureResult(
            slug = slug,
            tier = "vuln-repo",
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
            sliceCount = slices,
            integrityViolations = 0,
            wallMillis = 1,
            parseErrors = 0,
            minFindings = floor,
            classpathFileMissing = classpathMissing,
            digest = Digests.FixtureDigest(slug = slug, slot = slot, sections = emptyMap()),
        )

    private fun result(vararg results: BenchRunner.FixtureResult) = BenchRunner.BenchResult(
        results = results.toList(),
        toolCommit = "test",
        medianWallMillis = 1,
        worstWallMillis = 1,
        peakRssBytes = 1,
    )

    private fun check(vararg results: BenchRunner.FixtureResult): Promotion.Check =
        Promotion.evaluate(result(*results), null).checks.single { it.name == "vuln-finding-floor" }

    @Test
    fun aCountBelowTheFloorFailsNamingTheRepo() {
        val c = check(vuln("androgoat", slices = 3, floor = 17))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("androgoat" in c.detail && "3" in c.detail && "17" in c.detail, c.detail)
    }

    @Test
    fun zeroFindingsOnTheAnchorAppIsTheFailureThisGateExistsFor() {
        // The shape: every real repo at zero findings, build green.
        val c = check(vuln("tsp-vulnerable-app-kotlin-ktor", slices = 0, floor = 2))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
    }

    @Test
    fun aMissingWarmClasspathFailsEvenWhenTheCountHolds() {
        // The shape: the warming never downloaded anything, the floor
        // measures against an empty classpath, and the count happens to
        // hold. The floor was not measured — that is a failure, not a pass.
        val c = check(vuln("androgoat", slices = 17, floor = 17, classpathMissing = true))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("classpath" in c.detail, c.detail)
    }

    @Test
    fun aMaterialImprovementFailsUntilTheFloorIsRaised() {
        // Absorbing an improvement silently is the other half of the
        // ratchet: 40 against a floor of 17 is not noise.
        val c = check(vuln("androgoat", slices = 40, floor = 17))
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("raise the floor" in c.detail, c.detail)
    }

    @Test
    fun aSmallOvershootIsNoiseAndPasses() {
        // A couple of slices over the floor is re-modelling noise, not a
        // finding; the floor must not demand byte-identical counts.
        val c = check(vuln("androgoat", slices = 19, floor = 17))
        assertEquals(Promotion.State.PASS, c.state, c.detail)
    }

    @Test
    fun holdingTheFloorPassesWithBothNumbersNamed() {
        val c = check(
            vuln("androgoat", slices = 17, floor = 17),
            vuln("insecureshop", slices = 7, floor = 7),
            vuln("tsp-vulnerable-app-kotlin-ktor", slices = 2, floor = 2),
        )
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("androgoat=17 (floor 17)" in c.detail, c.detail)
        assertTrue("insecureshop=7 (floor 7)" in c.detail, c.detail)
    }

    @Test
    fun noFloorsInTheRunIsNotEvaluatedRatherThanPass() {
        val c = check(vuln("spring-fu", slices = 0, floor = null))
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
    }

    @Test
    fun floorsOnOtherSlotsDoNotFeedTheCheck() {
        // The floor names the RESOLVED slot's count; a deps- or
        // endpoint-slot row carrying the entry's floor must not be measured
        // against it (the entry-level field rides every row).
        val c = check(vuln("androgoat", slices = 99, floor = 17, slot = MatrixSlot.DEPS_LABEL))
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
    }
}
