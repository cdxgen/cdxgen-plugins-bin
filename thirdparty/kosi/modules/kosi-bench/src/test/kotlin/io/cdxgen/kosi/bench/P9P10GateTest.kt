package io.cdxgen.kosi.bench

import io.cdxgen.kosi.bench.Promotion.State
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Gates with TEETH: each check is driven to FAIL on constructed
 * rows before it is driven to PASS, because a gate only ever seen passing
 * is a gate that has not been tested (the plan's standing rule 5).
 */
class P9P10GateTest {

    private fun row(
        slug: String,
        tier: String = "small",
        slot: String = MatrixSlot.DEPS_LABEL,
        bytecodeSlices: Int = 2,
        bytecodeSummaries: Int = 5,
        bodyless: Int = 1,
        classes: Int = 12,
        wallMillis: Long = 1000,
        peakRss: Long? = 100_000_000L,
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
        sliceCount = bytecodeSlices,
        integrityViolations = 0,
        wallMillis = wallMillis,
        parseErrors = 0,
        bytecodeSummaries = bytecodeSummaries,
        crossDependencyBytecodeSlices = bytecodeSlices,
        bodylessRecords = bodyless,
        dependencyClasses = classes,
        peakRssBytes = peakRss,
        digest = Digests.FixtureDigest(slug, slot, emptyMap()),
    )

    private fun result(vararg rows: BenchRunner.FixtureResult): BenchRunner.BenchResult =
        BenchRunner.BenchResult(
            results = rows.toList(),
            toolCommit = "test",
            medianWallMillis = 0,
            worstWallMillis = 0,
            peakRssBytes = 0,
        )

    // ---- cross-dependency-bytecode --------------------------------------

    @Test
    fun theCrossDependencyGatePassesWhenTheBarIsMet() {
        // The bar is 1 since the per-repo re-measurement (docs/KOSI.md
        // carries the breakdown that lowered it from 5); any qualifying
        // repo must PASS and be named.
        val repos = (1..5).map { row("repo$it") }
        val report = Promotion.evaluate(result(*repos.toTypedArray()), baseline = null)
        val check = report.checks.first { it.name == "cross-dependency-bytecode" }
        assertEquals(State.PASS, check.state, check.detail)
        assertTrue("5 of 5 PINNED repo(s) qualify" in check.detail, check.detail)
        // A PASS must still publish the per-repo measurement. The bar is 1
        // and the corpus' one qualifier is the BUNDLED vulnerable service,
        // so a PASS line that printed only its qualifiers would hide the
        // pinned repos' zeros — the finding was run to produce.
        assertTrue("measured: repo1=" in check.detail, check.detail)
    }

    @Test
    fun theCrossDependencyGateFailsNamingTheZeroRepos() {
        val repos = (1..5).map { row("repo$it", bytecodeSlices = 0, bytecodeSummaries = 0) }
        val report = Promotion.evaluate(result(*repos.toTypedArray()), baseline = null)
        val check = report.checks.first { it.name == "cross-dependency-bytecode" }
        assertEquals(State.FAIL, check.state, "0 qualifying repos must FAIL the gate")
        assertTrue("repo1=0 slice(s)" in check.detail, "the zero repo must be named: ${check.detail}")
    }

    @Test
    fun theCrossDependencyGateIsNotEvaluatedWithoutDepsRows() {
        val report = Promotion.evaluate(result(row("repo1", slot = MatrixSlot.RESOLVED_LABEL)), baseline = null)
        val check = report.checks.first { it.name == "cross-dependency-bytecode" }
        assertEquals(State.NOT_EVALUATED, check.state)
    }

    // ---- deps-delta recording --------------------------------------------

    @Test
    fun theDepsDeltaIsRecordedPerRepoFromTheSameSession() {
        val rows = listOf(
            row("repo1", slot = MatrixSlot.RESOLVED_LABEL, wallMillis = 1000, peakRss = 100_000_000L),
            row("repo1", slot = MatrixSlot.DEPS_LABEL, wallMillis = 2500, peakRss = 260_000_000L),
        )
        val report = Promotion.evaluate(result(*rows.toTypedArray()), baseline = null)
        val check = report.checks.first { it.name == "deps-delta" }
        assertEquals(State.PASS, check.state, check.detail)
        assertTrue("2.50x" in check.detail, "the wall ratio must be recorded: ${check.detail}")
    }

    // ---- per-repo peak RSS ------------------------------------------------

    @Test
    fun perRepoRssPassesWithinBudget() {
        val rows = (1..3).map { row("repo$it", peakRss = 100_000_000L) }
        val baseline = result(*rows.map { row(it.slug, peakRss = 90_000_000L) }.toTypedArray())
        val report = Promotion.evaluate(result(*rows.toTypedArray()), baseline)
        val check = report.checks.first { it.name == "per-repo-rss" }
        assertEquals(State.PASS, check.state, check.detail)
    }

    @Test
    fun perRepoRssFailsNamingTheRepoThatExploded() {
        val rows = listOf(
            row("fine-repo", peakRss = 100_000_000L),
            row("greedy-repo", peakRss = 400_000_000L),
        )
        val baseline = result(
            row("fine-repo", peakRss = 90_000_000L),
            row("greedy-repo", peakRss = 90_000_000L),
        )
        val report = Promotion.evaluate(result(*rows.toTypedArray()), baseline)
        val check = report.checks.first { it.name == "per-repo-rss" }
        assertEquals(State.FAIL, check.state, "greedy-repo at 4.4x must fail the 1.5x ceiling")
        assertTrue("greedy-repo" in check.detail, check.detail)
        assertTrue("fine-repo" !in check.detail, check.detail)
    }

    @Test
    fun perRepoRssIsNotEvaluatedAgainstAFieldlessBaseline() {
        val rows = listOf(row("repo1", peakRss = 100_000_000L))
        val baselineRow = row("repo1", peakRss = null)
        val report = Promotion.evaluate(result(*rows.toTypedArray()), result(baselineRow))
        val check = report.checks.first { it.name == "per-repo-rss" }
        assertEquals(State.NOT_EVALUATED, check.state)
    }

    // ---- the recording fields travel the bench JSON -------------------------

    @Test
    fun benchResultJsonRoundTripsTheNewFields() {
        val original = result(row("repo1", bytecodeSlices = 7, bytecodeSummaries = 42, bodyless = 3, classes = 99))
        val parsed = BenchRunner.BenchResult.fromJson(original.toJson())
        val roundTripped = parsed.results.first()
        assertEquals(7, roundTripped.crossDependencyBytecodeSlices)
        assertEquals(42, roundTripped.bytecodeSummaries)
        assertEquals(3, roundTripped.bodylessRecords)
        assertEquals(99, roundTripped.dependencyClasses)
        assertEquals(100_000_000L, roundTripped.peakRssBytes)
    }
}
