package io.cdxgen.kosi.bench

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The baseline file is the only path by which a gate sees the previous run,
 * so anything a gate reads must survive write -> read. It did not:
 * `resolvedCallRatio` was written by `toJson` and never parsed by `fromJson`,
 * so every baseline loaded from disk carried null and the per-repo ratio
 * gate's two enforcing arms — regression, and falling through the target —
 * silently could not fire. The gate's own unit tests missed it because they
 * built `BenchResult` in memory and never went through the parser.
 *
 * [everyGateReadableFieldSurvivesTheBaselineFile] is the general guard: it
 * compares field by field over the whole data class, so the next field added
 * for a gate cannot go missing in the parser the same way.
 */
class FixtureResultJsonTest {

    /** Distinctive values throughout, so a dropped field cannot coincide with a default. */
    private fun sample() = BenchRunner.FixtureResult(
        slug = "some-repo",
        tier = "medium",
        slot = MatrixSlot.RESOLVED_LABEL,
        annotations = 11,
        positives = 7,
        negatives = 4,
        pass = 9,
        fail = 1,
        xfail = 2,
        xpass = 3,
        positivesPassed = 6,
        positivesRecallDenominator = 8,
        recall = 0.8125,
        connectivity = 0.5,
        sliceCount = 13,
        integrityViolations = 2,
        wallMillis = 4242,
        parseErrors = 5,
        resolvedCallRatio = 0.9405,
        callsTotal = 1000,
        callsResolved = 940,
        loweringFailures = linkedMapOf("b-construct" to 2, "a-construct" to 7),
        functionsLowered = 321,
        graphNodes = 41,
        graphEdges = 57,
        graphLocalNodes = 11,
        graphStdlibNodes = 13,
        graphDependencyNodes = 17,
        graphSyntheticNodes = 19,
        graphLocalEdges = 23,
        graphStdlibEdges = 29,
        graphDependencyEdges = 31,
        graphSyntheticEdges = 37,
        reachedNodes = 39,
        connectedNodes = 40,
        reachedViaEdge = 47,
        connectedViaEdge = 53,
        collapsedEdges = 42,
        publicCallables = 43,
        reachedPublicCallables = 44,
        graphAlgorithm = "vta",
        flowPositives = 51,
        flowPositivesMatched = 52,
        flowTruePositives = 53,
        crossDependencySlices = 54,
        fixpointCapHits = 55,
        functionsAnalysed = 56,
        summariesComputed = 57,
        summariesByOrigin = linkedMapOf("computed" to 5, "pack" to 3),
        defaultOriginSlices = 58,
        summaryCrossingSlices = 59,
        crossModuleSlices = 60,
        sccsProcessed = 61,
        sccIterationCapHits = 62,
        suspendCrossingSlices = 63,
        digest = Digests.FixtureDigest("some-repo", MatrixSlot.RESOLVED_LABEL, emptyMap()),
    )

    private fun roundTrip(result: BenchRunner.FixtureResult): BenchRunner.FixtureResult {
        val bench = BenchRunner.BenchResult(
            results = listOf(result),
            toolCommit = "deadbeef",
            medianWallMillis = 1,
            worstWallMillis = 2,
            peakRssBytes = 3,
        )
        val parsed = BenchRunner.BenchResult.fromJson(bench.toJson())
        return parsed.results.single()
    }

    @Test
    fun everyGateReadableFieldSurvivesTheBaselineFile() {
        val original = sample()
        val parsed = roundTrip(original)
        // `failures` and the digest's per-section map are deliberately not
        // carried in the baseline (details of a run, not gate inputs);
        // everything else must come back exactly.
        val notPersisted = setOf("failures", "digest")
        val dropped = BenchRunner.FixtureResult::class.java.declaredFields
            .map { it.name }
            .filterNot { it in notPersisted }
            .filterNot { name ->
                val field = BenchRunner.FixtureResult::class.java.getDeclaredField(name)
                field.isAccessible = true
                field.get(original) == field.get(parsed)
            }
        assertEquals(
            emptyList(), dropped,
            "these fields did not survive the baseline round-trip, so any gate reading them is dead: $dropped",
        )
    }

    @Test
    fun theSampleLeavesNoFieldAtItsDefault() {
        // The round-trip guard above compares field by field, which means a
        // NEW field left at its `null` default passes it vacuously — null in,
        // null out, no evidence the parser ever heard of it. That is R44's
        // shape one level up, so the sample itself is checked: every
        // persisted field must carry a distinctive value before the
        // comparison can prove anything about it.
        val original = sample()
        val notPersisted = setOf("failures", "digest")
        val atDefault = BenchRunner.FixtureResult::class.java.declaredFields
            .map { it.name }
            .filterNot { it in notPersisted }
            .filter { name ->
                val field = BenchRunner.FixtureResult::class.java.getDeclaredField(name)
                field.isAccessible = true
                when (val value = field.get(original)) {
                    null -> true
                    is Map<*, *> -> value.isEmpty()
                    is Collection<*> -> value.isEmpty()
                    else -> false
                }
            }
        assertEquals(
            emptyList(), atDefault,
            "add a distinctive value for these in sample(), or the round-trip test cannot see them: $atDefault",
        )
    }

    @Test
    fun theRatioAndItsCountsComeBackTogether() {
        val parsed = roundTrip(sample())
        assertEquals(0.9405, parsed.resolvedCallRatio)
        assertEquals(1000, parsed.callsTotal)
        assertEquals(940, parsed.callsResolved)
    }

    @Test
    fun aPreP2BaselineParsesWithAbsentCountsRatherThanZero() {
        // Old baselines have no counts. Absent must stay null — zero would
        // read as "a repo with no call sites" and quietly excuse the gate.
        val json = """
            {"results":[{"slug":"old","tier":"medium","slot":"resolved","annotations":1,
             "connectivity":1,"recall":1,"digest":"x","fail":0,"integrityViolations":0,
             "negatives":0,"parseErrors":0,"pass":1,"positives":1,"positivesPassed":1,
             "positivesRecallDenominator":1,"sliceCount":0,"wallMillis":1,"xfail":0,"xpass":0}],
             "toolCommit":"x","medianWallMillis":1,"worstWallMillis":1,"peakRssBytes":1}
        """.trimIndent()
        val parsed = BenchRunner.BenchResult.fromJson(json).results.single()
        assertEquals(null, parsed.callsTotal)
        assertEquals(null, parsed.functionsLowered)
        assertEquals(null, parsed.resolvedCallRatio)
        assertEquals(null, parsed.functionsAnalysed)
        assertEquals(null, parsed.fixpointCapHits)
        assertTrue(parsed.loweringFailures.isEmpty())
    }

    @Test
    fun aPreP4BaselineHasNoFlowCountsAndTheGateSeesThat() {
        // The P4 flow fields must be ABSENT in a pre-P4 baseline, not zero:
        // zero would read as "measured, nothing found" and let the
        // per-repo flow ratchet compare against a measurement never made.
        val json = """
            {"results":[{"slug":"old","tier":"medium","slot":"resolved","annotations":1,
             "connectivity":1,"recall":1,"digest":"x","fail":0,"integrityViolations":0,
             "negatives":0,"parseErrors":0,"pass":1,"positives":1,"positivesPassed":1,
             "positivesRecallDenominator":1,"sliceCount":0,"wallMillis":1,"xfail":0,"xpass":0}],
             "toolCommit":"x","medianWallMillis":1,"worstWallMillis":1,"peakRssBytes":1}
        """.trimIndent()
        val parsed = BenchRunner.BenchResult.fromJson(json).results.single()
        assertEquals(null, parsed.crossDependencySlices)
        assertEquals(null, parsed.functionsAnalysed)
        assertEquals(null, parsed.fixpointCapHits)
    }
}
