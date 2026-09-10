package io.cdxgen.kosi.bench

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The three P3 promotion checks, tested THROUGH THE PATH PRODUCTION USES:
 * every case writes its bench result to a baseline file and reads it back
 * with [Baseline.load] before the gate sees it. R44 is the lesson — a gate
 * whose input is a parsed artifact is not tested by in-memory objects, and a
 * field dropped by the parser turns every check here into the red "gate
 * cannot see what it checks" finding.
 */
class CallGraphGateTest {

    private fun row(
        slug: String,
        tier: String = "fixtures",
        slot: String = MatrixSlot.EXPORTED_LABEL,
        graphNodes: Int? = 3,
        graphEdges: Int? = 2,
        localNodes: Int? = 3,
        stdlibNodes: Int? = 0,
        dependencyNodes: Int? = 0,
        syntheticNodes: Int? = 0,
        localEdges: Int? = 2,
        stdlibEdges: Int? = 0,
        dependencyEdges: Int? = 0,
        syntheticEdges: Int? = 0,
        reached: Int? = 3,
        connected: Int? = 3,
        reachedViaEdge: Int? = 2,
        connectedViaEdge: Int? = 2,
        publicCallables: Int? = 3,
        reachedPublic: Int? = 3,
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
        sliceCount = 0,
        integrityViolations = 0,
        wallMillis = 1,
        parseErrors = 0,
        resolvedCallRatio = 1.0,
        callsTotal = 1,
        callsResolved = 1,
        graphNodes = graphNodes,
        graphEdges = graphEdges,
        graphLocalNodes = localNodes,
        graphStdlibNodes = stdlibNodes,
        graphDependencyNodes = dependencyNodes,
        graphSyntheticNodes = syntheticNodes,
        graphLocalEdges = localEdges,
        graphStdlibEdges = stdlibEdges,
        graphDependencyEdges = dependencyEdges,
        graphSyntheticEdges = syntheticEdges,
        reachedNodes = reached,
        connectedNodes = connected,
        reachedViaEdge = reachedViaEdge,
        connectedViaEdge = connectedViaEdge,
        collapsedEdges = 0,
        publicCallables = publicCallables,
        reachedPublicCallables = reachedPublic,
        graphAlgorithm = "vta",
        digest = Digests.FixtureDigest(slug, slot, emptyMap()),
    )

    private fun bench(vararg rows: BenchRunner.FixtureResult): BenchRunner.BenchResult =
        BenchRunner.BenchResult(
            results = rows.toList(),
            toolCommit = "test",
            medianWallMillis = 1,
            worstWallMillis = 1,
            peakRssBytes = 1,
        )

    /** Writes the bench result to disk and loads it back the way the gate reads it. */
    private fun throughBaseline(result: BenchRunner.BenchResult, dir: Path, name: String): BenchRunner.BenchResult {
        val file = dir.resolve("$name.json")
        Baseline.save(result, file)
        return Baseline.load(file) ?: throw AssertionError("baseline $name did not read back")
    }

    private fun check(bench: BenchRunner.BenchResult, name: String): Promotion.Check =
        Promotion.evaluate(bench, bench).checks.single { it.name == name }

    private fun tempDir(): Path = Files.createTempDirectory("kosi-gate-test")

    // ---- edge connectivity -------------------------------------------------

    @Test
    fun aSeveredPathFailsEdgeConnectivityThroughTheBaselineFile() {
        val severed = row("some-fixture", reachedViaEdge = 3, connectedViaEdge = 2)
        val loaded = throughBaseline(bench(severed), tempDir(), "severed")
        val c = check(loaded, "edge-connectivity")
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("2 of 3" in c.detail, c.detail)
    }

    @Test
    fun aRunThatReachedNothingIsNotEvaluatedRatherThanPassing() {
        // The vacuity guard: 0 reached nodes everywhere is the P0 shape, and
        // it must say so instead of reporting a vacuous 1.000.
        val empty = row("some-fixture", reached = 0, connected = 0, reachedViaEdge = 0, connectedViaEdge = 0)
        val loaded = throughBaseline(bench(empty), tempDir(), "vacuous")
        val c = check(loaded, "edge-connectivity")
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
        assertTrue("no edge was traversed" in c.detail, c.detail)
    }

    @Test
    fun aRunWhoseReachedNodesAreAllRootsIsNotEvaluatedRatherThanPassing() {
        // R50: this is the shape the P3 corpus actually had — 62 reached
        // nodes, every one of them a root at distance 0, confirmed by a walk
        // that followed no edge. Counting roots made a 1.000 out of nothing;
        // the denominator must be the edge-traversed subset, and when that is
        // empty the honest answer is NOT_EVALUATED.
        val allRoots = row("root-only", reached = 9, connected = 9, reachedViaEdge = 0, connectedViaEdge = 0)
        val loaded = throughBaseline(bench(allRoots), tempDir(), "all-roots")
        val c = check(loaded, "edge-connectivity")
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
        assertTrue("0 of 9 reached" in c.detail, c.detail)
    }

    @Test
    fun fullWitnessConnectivityPassesAndNamesTheDenominator() {
        val loaded = throughBaseline(
            bench(
                row("fixture-a"),
                row(
                    "fixture-b",
                    reached = 5, connected = 5, reachedViaEdge = 4, connectedViaEdge = 4,
                    graphEdges = 4, localEdges = 4,
                ),
            ),
            tempDir(),
            "connected",
        )
        val c = check(loaded, "edge-connectivity")
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("6 edge-reached node(s) (of 8 reached)" in c.detail, c.detail)
    }

    @Test
    fun theTotalRowIsNeverMistakenForAGraphRow() {
        // The totals row carries tier "all"; a check that reads it would sum
        // every fixture twice and the denominator would be a lie.
        val loaded = throughBaseline(
            bench(row("fixture-a"), row("TOTAL", tier = "all", slot = "all")),
            tempDir(),
            "total",
        )
        val c = check(loaded, "edge-connectivity")
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("2 edge-reached node(s) (of 3 reached)" in c.detail, "only the one real row counts: ${c.detail}")
    }

    // ---- exported reach -----------------------------------------------------

    @Test
    fun exportedReachBelowTheTargetFailsNamingTheWorstRows() {
        val loaded = throughBaseline(
            bench(row("lib", publicCallables = 100, reachedPublic = 90)),
            tempDir(),
            "reach-low",
        )
        val c = check(loaded, "exported-reach")
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("0.9000" in c.detail && "90 of 100" in c.detail, c.detail)
    }

    @Test
    fun exportedReachAtOrAboveTheTargetPassesWithBothCounts() {
        val loaded = throughBaseline(
            bench(row("lib", publicCallables = 100, reachedPublic = 96)),
            tempDir(),
            "reach-ok",
        )
        val c = check(loaded, "exported-reach")
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("96 of 100" in c.detail, c.detail)
    }

    @Test
    fun noExportedRowsIsNotEvaluatedRatherThanPassing() {
        val loaded = throughBaseline(
            bench(row("fixture", slot = MatrixSlot.RESOLVED_LABEL, publicCallables = null, reachedPublic = null)),
            tempDir(),
            "no-exported",
        )
        val c = check(loaded, "exported-reach")
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
    }

    @Test
    fun zeroPublicCallablesIsNotEvaluatedRatherThanPassing() {
        val loaded = throughBaseline(
            bench(row("opaque", publicCallables = 0, reachedPublic = 0)),
            tempDir(),
            "zero-public",
        )
        val c = check(loaded, "exported-reach")
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
        assertTrue("visibility facts" in c.detail, c.detail)
    }

    // ---- graph breakdown ------------------------------------------------------

    @Test
    fun aBreakdownThatDoesNotSumFails() {
        val loaded = throughBaseline(
            bench(
                row(
                    "broken",
                    graphNodes = 10,
                    localNodes = 3,
                ),
            ),
            tempDir(),
            "sum",
        )
        val c = check(loaded, "graph-breakdown")
        assertEquals(Promotion.State.FAIL, c.state, c.detail)
        assertTrue("nodes 3 != 10" in c.detail, c.detail)
    }

    @Test
    fun aRecordedBreakdownPassesAndPublishesItsSplit() {
        val loaded = throughBaseline(
            bench(
                row("ok", localNodes = 3, stdlibNodes = 1, graphNodes = 4, localEdges = 2, stdlibEdges = 1, graphEdges = 3),
            ),
            tempDir(),
            "sum-ok",
        )
        val c = check(loaded, "graph-breakdown")
        assertEquals(Promotion.State.PASS, c.state, c.detail)
        assertTrue("stdlib=1" in c.detail, c.detail)
    }

    @Test
    fun noGraphRowsIsNotEvaluatedRatherThanPassing() {
        val loaded = throughBaseline(
            bench(row("syntax-only", slot = MatrixSlot.SECURITY_LABEL, graphNodes = null, graphEdges = null)),
            tempDir(),
            "no-graph",
        )
        val c = check(loaded, "graph-breakdown")
        assertEquals(Promotion.State.NOT_EVALUATED, c.state, c.detail)
    }
}
