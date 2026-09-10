package io.cdxgen.kosi.bench

import io.cdxgen.kosi.schema.JsonReader
import io.cdxgen.kosi.schema.JsonWriter
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Baseline write/compare (golem's baseline.go shape). A baseline is the JSON
 * of a previous BenchResult; comparison is content-based (never timestamps)
 * and produces regressions plus the promotion-gate input.
 */
object Baseline {

    fun save(result: BenchRunner.BenchResult, file: Path) {
        Files.createDirectories(file.toAbsolutePath().parent)
        Files.writeString(file, result.toJson() + "\n", StandardCharsets.UTF_8)
    }

    fun load(file: Path): BenchRunner.BenchResult? =
        if (Files.isRegularFile(file)) BenchRunner.BenchResult.fromJson(Files.readString(file)) else null

    data class Regression(
        val slug: String,
        val slot: String,
        val metric: String,
        val baseline: String,
        val current: String,
        val blocking: Boolean,
    ) {
        fun render(): String =
            "${if (blocking) "BLOCK" else "warn "} $slug/$slot $metric: baseline=$baseline current=$current"
    }

    /**
     * Structural regressions independent of the promotion criteria:
     * expectations that regressed, unexpected passes, integrity violations,
     * connectivity drops, recall drops.
     */
    fun compare(current: BenchRunner.BenchResult, baseline: BenchRunner.BenchResult): List<Regression> {
        val regressions = mutableListOf<Regression>()
        val baselineByKey = baseline.results.associateBy { it.slug + "/" + it.slot }
        for (res in current.results) {
            val base = baselineByKey[res.slug + "/" + res.slot] ?: continue
            if (res.fail > base.fail) {
                regressions.add(
                    Regression(res.slug, res.slot, "failures", base.fail.toString(), res.fail.toString(), true),
                )
            }
            if (res.xpass > base.xpass) {
                regressions.add(
                    Regression(res.slug, res.slot, "xpass(known-fail started passing)", base.xpass.toString(), res.xpass.toString(), true),
                )
            }
            if (res.integrityViolations > base.integrityViolations) {
                regressions.add(
                    Regression(
                        res.slug, res.slot, "integrityViolations",
                        base.integrityViolations.toString(), res.integrityViolations.toString(), true,
                    ),
                )
            }
            if (res.connectivity < base.connectivity) {
                regressions.add(
                    Regression(
                        res.slug, res.slot, "connectivity",
                        base.connectivity.toString(), res.connectivity.toString(), true,
                    ),
                )
            }
            if (res.recall < base.recall) {
                regressions.add(
                    Regression(res.slug, res.slot, "recall", base.recall.toString(), res.recall.toString(), true),
                )
            }
        }
        // A fixture that vanished from the matrix is a coverage regression.
        val currentKeys = current.results.map { it.slug + "/" + it.slot }.toSet()
        for ((key, base) in baselineByKey) {
            if (key !in currentKeys) {
                regressions.add(
                    Regression(base.slug, base.slot, "coverage", "present", "missing", true),
                )
            }
        }
        return regressions
    }
}

/**
 * The promotion gate (06-CORPUS.md §4), adapted from golem's promotion.go plus
 * the two criteria it was missing (per-repo flow counts, per-repo wall clock).
 *
 * Phase-0 honesty rule: a criterion that cannot be evaluated with the current
 * engine is reported as NOT_EVALUATED with the reason — it is never counted
 * as a pass. While any criterion is NOT_EVALUATED the gate verdict is HOLD.
 */
object Promotion {

    data class Check(
        val name: String,
        val state: State,
        val detail: String,
    )

    enum class State { PASS, FAIL, NOT_EVALUATED }

    data class Report(
        val verdict: String,
        val checks: List<Check>,
    ) {
        val promotable: Boolean get() = verdict == "PROMOTE"

        fun render(): String {
            val lines = buildList {
                add("Promotion gate: $verdict")
                for (c in checks) {
                    add(String.format("  %-6s %-42s %s", c.state, c.name, c.detail))
                }
            }
            return lines.joinToString("\n")
        }
    }

    fun evaluate(current: BenchRunner.BenchResult, baseline: BenchRunner.BenchResult?): Report {
        val checks = mutableListOf<Check>()

        // 1. recall improves >= 0.15 or holds (non-engine phase)
        val curTotal = current.totals()
        if (baseline == null) {
            checks.add(Check("recall", State.NOT_EVALUATED, "no baseline to compare"))
        } else {
            val baseTotal = baseline.totals()
            val delta = curTotal.recall - baseTotal.recall
            checks.add(
                if (delta >= -1e-9) {
                    Check("recall", State.PASS, "recall ${baseTotal.recall} -> ${curTotal.recall} (holds or improves)")
                } else {
                    Check("recall", State.FAIL, "recall regressed: ${baseTotal.recall} -> ${curTotal.recall}")
                },
            )
        }

        // 2. precision per flow — needs slices (phase 3)
        checks.add(
            Check("precision-per-flow", State.NOT_EVALUATED, "no flow engine yet; slices do not exist at the syntax tier"),
        )

        // 3. connectivity 1.000, integrity 0 — evaluable, with the vacuity
        // caveat stated so a vacuous pass is never mistaken for a flow result.
        checks.add(
            if (curTotal.connectivity == 1.0) {
                Check(
                    "connectivity",
                    State.PASS,
                    if (curTotal.sliceCount == 0) {
                        "1.000 over 0 slices (vacuous: no slices exist yet at the syntax tier)"
                    } else {
                        "1.000 over ${curTotal.sliceCount} slice(s)"
                    },
                )
            } else {
                Check("connectivity", State.FAIL, "below 1.000: ${curTotal.connectivity}")
            },
        )
        checks.add(
            if (curTotal.integrityViolations == 0) {
                Check("integrity-violations", State.PASS, "0")
            } else {
                Check("integrity-violations", State.FAIL, "${curTotal.integrityViolations} violations")
            },
        )

        // 4. strictly fewer open known-fails
        if (baseline == null) {
            checks.add(Check("known-fails", State.NOT_EVALUATED, "no baseline to compare (open now: ${curTotal.xfail})"))
        } else {
            val baseOpen = baseline.totals().xfail
            checks.add(
                when {
                    curTotal.xfail < baseOpen -> Check("known-fails", State.PASS, "$baseOpen -> ${curTotal.xfail} (closed)")
                    curTotal.xfail == baseOpen -> Check("known-fails", State.PASS, "open count unchanged (${curTotal.xfail})")
                    else -> Check("known-fails", State.FAIL, "open known-fails grew: $baseOpen -> ${curTotal.xfail}")
                },
            )
        }

        // 5. dependency-crossing flows — needs slices
        checks.add(
            Check("dependency-crossing-flows", State.NOT_EVALUATED, "no slices exist at the syntax tier"),
        )

        // 6. time and memory ratios
        if (baseline == null) {
            checks.add(Check("wall-clock", State.NOT_EVALUATED, "no baseline to compare"))
            checks.add(Check("peak-rss", State.NOT_EVALUATED, "no baseline to compare"))
        } else {
            val baseMedian = baseline.medianWallMillis
            val curMedian = current.medianWallMillis
            checks.add(
                if (baseMedian == 0L || curMedian <= baseMedian * 1.20) {
                    Check("wall-clock", State.PASS, "median ${baseMedian}ms -> ${curMedian}ms (<= 1.20x)")
                } else {
                    Check("wall-clock", State.FAIL, "median ${baseMedian}ms -> ${curMedian}ms (> 1.20x)")
                },
            )
            val baseWorst = baseline.worstWallMillis
            val curWorst = current.worstWallMillis
            checks.add(
                if (baseWorst == 0L || curWorst <= baseWorst * 1.50) {
                    Check("worst-fixture", State.PASS, "worst ${baseWorst}ms -> ${curWorst}ms (<= 1.50x)")
                } else {
                    Check("worst-fixture", State.FAIL, "worst ${baseWorst}ms -> ${curWorst}ms (> 1.50x)")
                },
            )
            val baseRss = baseline.peakRssBytes
            val curRss = current.peakRssBytes
            checks.add(
                if (baseRss == 0L || curRss <= baseRss * 1.50) {
                    Check("peak-rss", State.PASS, "peak ${baseRss}B -> ${curRss}B (<= 1.50x)")
                } else {
                    Check("peak-rss", State.FAIL, "peak ${baseRss}B -> ${curRss}B (> 1.50x)")
                },
            )
        }

        // 7. full fixture coverage
        val slotsPerFixture = Matrix.defaultMatrix().size
        val coverageOk = current.results.map { it.slug }.toSortedSet().size * slotsPerFixture ==
            current.results.size && current.results.isNotEmpty()
        checks.add(
            if (coverageOk) {
                Check(
                    "fixture-coverage",
                    State.PASS,
                    "${current.results.size} slots run ($slotsPerFixture per fixture)",
                )
            } else {
                Check("fixture-coverage", State.FAIL, "fixture/slot coverage incomplete")
            },
        )

        // 8+9. per-real-repo flow counts and wall clock — flow counts need slices
        checks.add(
            Check("per-repo-flow-counts", State.NOT_EVALUATED, "real-repo tiers carry no flows yet"),
        )
        if (baseline != null) {
            val baselineRepoKeys = baseline.results.filter { it.tier != "fixtures" }.map { it.slug + "/" + it.slot }
            if (baselineRepoKeys.isEmpty()) {
                checks.add(Check("per-repo-wall-clock", State.NOT_EVALUATED, "no repo-tier entries in baseline"))
            } else {
                val curByKey = current.results.associateBy { it.slug + "/" + it.slot }
                val slow = baseline.results.filter { it.tier != "fixtures" }.filter { base ->
                    val cur = curByKey[base.slug + "/" + base.slot]
                    cur != null && base.wallMillis > 0 && cur.wallMillis > base.wallMillis * 1.5
                }
                checks.add(
                    if (slow.isEmpty()) {
                        Check("per-repo-wall-clock", State.PASS, "all repo-tier fixtures within 1.5x")
                    } else {
                        Check("per-repo-wall-clock", State.FAIL, "${slow.size} repo-tier fixtures above 1.5x")
                    },
                )
            }
        } else {
            checks.add(Check("per-repo-wall-clock", State.NOT_EVALUATED, "no baseline to compare"))
        }

        // 10. per-repo resolvedCallRatio (P1 gate). Reported PER REPO, never
        // as an average, and enforced two ways so neither direction can pass
        // unnoticed: a repo may not fall below its baseline ratio (a
        // regression), and a repo at or above the 0.90 target may not fall
        // through it. Repos below the target are named with their measured
        // value in the detail line — the number is the ratchet, so improving
        // one forces the baseline to be rewritten rather than accumulating an
        // exemption list.
        checks.add(resolvedRatioCheck(current, baseline))

        // 11. the P2 lowering gate: loweringFailures empty on every fixture
        // slot, and below LOWERING_FAILURE_RATE_MAX of the functions lowered
        // on the repo tiers. Enforced here rather than measured by hand once
        // in a PR body, because a lowering that regresses between phases is
        // exactly what a ratchet is for.
        checks.add(loweringCheck(current))

        // 12-14. the P3 call-graph gates: edge connectivity 1.000 with a REAL
        // denominator (witness-confirmed reached nodes), `--roots exported`
        // reaching >= 95% of a library's public API with both counts
        // published, and node/edge breakdowns that are recorded AND add up.
        // Each is evaluated over the bench result rows exactly as a baseline
        // comparison would feed them, never from in-memory report objects.
        checks.add(edgeConnectivityCheck(current))
        checks.add(exportedReachCheck(current))
        checks.add(graphBreakdownCheck(current))

        val verdict = when {
            checks.all { it.state == State.PASS } -> "PROMOTE"
            checks.any { it.state == State.FAIL } -> "HOLD (regressions)"
            else -> "HOLD (criteria unevaluated)"
        }
        return Report(verdict, checks)
    }

    /** The P1 gate's per-repo resolved-call-ratio target. */
    const val RESOLVED_RATIO_TARGET = 0.90

    /** The P2 gate's ceiling on the repo-tier lowering failure rate. */
    const val LOWERING_FAILURE_RATE_MAX = 0.005

    /**
     * `loweringFailures` must be empty on every fixture slot that lowered
     * anything, and under [LOWERING_FAILURE_RATE_MAX] on the repo tiers. Both
     * arms report the failure count over the function count it was measured
     * against — a rate with no denominator would repeat the defect this gate
     * exists to catch (R25).
     */
    private fun loweringCheck(current: BenchRunner.BenchResult): Check {
        val name = "lowering-failures"
        val lowered = current.results.filter { (it.functionsLowered ?: 0) > 0 }
        if (lowered.isEmpty()) {
            // Never pass by having nothing to look at: no slot lowered a
            // single function, so the gate saw nothing.
            return Check(name, State.NOT_EVALUATED, "no slot reported a lowered function (run the resolved slot)")
        }
        val fixtureFailures = lowered
            .filter { it.tier == "fixtures" && it.loweringFailures.isNotEmpty() }
            .sortedBy { it.slug }
        if (fixtureFailures.isNotEmpty()) {
            val detail = fixtureFailures.joinToString("; ") { r ->
                "${r.slug}/${r.slot} ${r.loweringFailures.values.sum()} of ${r.functionsLowered} functions " +
                    "(${r.loweringFailures.toSortedMap().entries.joinToString(", ") { "${it.key}=${it.value}" }})"
            }
            return Check(name, State.FAIL, "fixtures must lower cleanly: $detail")
        }
        val overRate = mutableListOf<String>()
        val repos = lowered.filter { it.tier != "fixtures" }.sortedBy { it.slug }
        for (repo in repos) {
            val total = repo.functionsLowered ?: continue
            val failed = repo.loweringFailures.values.sum()
            val rate = failed.toDouble() / total
            if (rate > LOWERING_FAILURE_RATE_MAX) {
                overRate.add(
                    "${repo.slug} $failed of $total functions (${"%.4f".format(rate)} > " +
                        "${"%.4f".format(LOWERING_FAILURE_RATE_MAX)}): " +
                        repo.loweringFailures.toSortedMap().entries
                            .sortedByDescending { it.value }
                            .take(5).joinToString(", ") { "${it.key}=${it.value}" },
                )
            }
        }
        if (overRate.isNotEmpty()) return Check(name, State.FAIL, overRate.joinToString("; "))
        val fixtureFunctions = lowered.filter { it.tier == "fixtures" }.sumOf { it.functionsLowered ?: 0 }
        val repoFailed = repos.sumOf { r -> r.loweringFailures.values.sum() }
        val repoFunctions = repos.sumOf { it.functionsLowered ?: 0 }
        val repoDetail = if (repos.isEmpty()) {
            "no repo tiers in this run"
        } else {
            "repos $repoFailed of $repoFunctions functions failed"
        }
        return Check(name, State.PASS, "fixtures clean over $fixtureFunctions functions; $repoDetail")
    }

    /** The P3 gate's bar for `--roots exported` public-API reach. */
    const val EXPORTED_REACH_TARGET = 0.95

    private const val RESOLVED_RATIO_TOLERANCE = 0.01

    private fun resolvedRatioCheck(
        current: BenchRunner.BenchResult,
        baseline: BenchRunner.BenchResult?,
    ): Check {
        val name = "per-repo-resolved-call-ratio"
        val repos = current.results
            .filter { it.tier != "fixtures" && it.slot == MatrixSlot.RESOLVED_LABEL }
            .sortedBy { it.slug }
        if (repos.isEmpty()) {
            // The check must never pass by having nothing to look at: a run
            // without repo tiers cannot evaluate the gate.
            return Check(name, State.NOT_EVALUATED, "no repo-tier resolved slots in this run (run --tier all)")
        }
        val measured = repos.joinToString(", ") { r ->
            "${r.slug}=" + (r.resolvedCallRatio?.let { String.format("%.4f", it) } ?: "n/a") +
                (r.callsTotal?.let { " (${r.callsResolved ?: 0}/$it)" } ?: "")
        }
        val missing = repos.filter { it.resolvedCallRatio == null }
        if (missing.isNotEmpty()) {
            return Check(name, State.FAIL, "no ratio reported for ${missing.joinToString(", ") { it.slug }}")
        }
        val baseByKey = baseline?.results
            ?.filter { it.slot == MatrixSlot.RESOLVED_LABEL }
            ?.associateBy { it.slug }
        if (baseByKey.isNullOrEmpty()) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "no baseline resolved slots to ratchet against; measured $measured " +
                    "(target ${"%.2f".format(RESOLVED_RATIO_TARGET)})",
            )
        }
        val regressed = mutableListOf<String>()
        for (repo in repos) {
            // A ratio over zero calls is vacuous: 0.0 there is "nothing to
            // resolve", not "resolved nothing", and comparing it against a
            // baseline would manufacture a regression out of an empty repo.
            if (repo.callsTotal == 0) continue
            val cur = repo.resolvedCallRatio ?: continue
            val base = baseByKey[repo.slug]?.resolvedCallRatio ?: continue
            if (cur < base - RESOLVED_RATIO_TOLERANCE) {
                regressed.add("${repo.slug} ${"%.4f".format(base)} -> ${"%.4f".format(cur)}")
            } else if (base >= RESOLVED_RATIO_TARGET && cur < RESOLVED_RATIO_TARGET) {
                regressed.add("${repo.slug} fell through the target: ${"%.4f".format(cur)}")
            }
        }
        if (regressed.isNotEmpty()) {
            return Check(name, State.FAIL, regressed.joinToString("; "))
        }
        val belowTarget = repos.filter {
            it.callsTotal != 0 && (it.resolvedCallRatio ?: 0.0) < RESOLVED_RATIO_TARGET
        }
        val detail = if (belowTarget.isEmpty()) {
            "$measured (all >= ${"%.2f".format(RESOLVED_RATIO_TARGET)})"
        } else {
            "$measured; below the ${"%.2f".format(RESOLVED_RATIO_TARGET)} target and held at the " +
                "baseline value: ${belowTarget.joinToString(", ") { it.slug }}"
        }
        return Check(name, State.PASS, detail)
    }

    /** Rows with a published call graph (the resolved tiers), TOTAL excluded. */
    private fun graphRows(current: BenchRunner.BenchResult): List<BenchRunner.FixtureResult> =
        current.results.filter { it.slug != "TOTAL" && it.tier != "all" && it.graphNodes != null }

    /**
     * Edge connectivity: every reached view node must be confirmed by a walk
     * over the EMITTED edges — a path a view filter cut must survive as a
     * collapsed edge, and this check is where a severed one fails.
     *
     * The denominator is the EDGE-TRAVERSED subset (distance > 0), not every
     * reached node. A root is reached at distance 0 by definition, so a run
     * whose reached set is entirely roots confirms 1.000 having followed no
     * edge at all — which is exactly what this gate reported before
     * `reachable-depth` gave the corpus a node an edge has to reach. A run
     * with no such node is NOT_EVALUATED, never a pass.
     */
    private fun edgeConnectivityCheck(current: BenchRunner.BenchResult): Check {
        val name = "edge-connectivity"
        val rows = graphRows(current)
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no slot published a call graph (run the resolved tier)")
        }
        val totalReached = rows.sumOf { it.reachedNodes ?: 0 }
        val viaEdge = rows.sumOf { it.reachedViaEdge ?: 0 }
        val confirmedViaEdge = rows.sumOf { it.connectedViaEdge ?: 0 }
        if (viaEdge == 0) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "0 of $totalReached reached node(s) across ${rows.size} graph slot(s) sit at distance > 0: " +
                    "every reached node is a root, so no edge was traversed and there is nothing to confirm",
            )
        }
        if (confirmedViaEdge < viaEdge) {
            val severed = rows
                .filter { (it.connectedViaEdge ?: 0) < (it.reachedViaEdge ?: 0) }
                .joinToString("; ") { "${it.slug}/${it.slot} ${it.connectedViaEdge} of ${it.reachedViaEdge}" }
            return Check(name, State.FAIL, "severed path(s): $severed")
        }
        return Check(
            name,
            State.PASS,
            "1.000 over $viaEdge edge-reached node(s) (of $totalReached reached) " +
                "across ${rows.size} graph slot(s)",
        )
    }

    /**
     * The exported-reach gate: on the exported slots, the fraction of public
     * API callables that became roots and are reached, with BOTH counts in
     * the detail line. A shortfall names where resolution lost visibility
     * facts — the 95% bar exists so `--roots exported` cannot silently root
     * nothing on a library (golem: with only `main`, a library yields no
     * graph at all).
     *
     * The denominator is `declarations`, not the graph's own public nodes.
     * Counting nodes made this a tautology — the exported selector picks
     * exactly the public local nodes and a root is reached at distance 0, so
     * it read 1.0000 on every fixture and all five repos and could not fail.
     * Against the front end's independent inventory, a public callable that
     * never became a node costs a point, which is the failure the gate is for.
     */
    private fun exportedReachCheck(current: BenchRunner.BenchResult): Check {
        val name = "exported-reach"
        val rows = current.results.filter {
            it.slug != "TOTAL" && it.slot == MatrixSlot.EXPORTED_LABEL && it.publicCallables != null
        }
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no exported slot published a call graph")
        }
        val totalPublic = rows.sumOf { it.publicCallables ?: 0 }
        val totalReached = rows.sumOf { it.reachedPublicCallables ?: 0 }
        if (totalPublic == 0) {
            return Check(name, State.NOT_EVALUATED, "exported slots name 0 public callables; visibility facts missing")
        }
        val fraction = totalReached.toDouble() / totalPublic
        if (fraction < EXPORTED_REACH_TARGET) {
            val worst = rows.sortedBy { r ->
                (r.reachedPublicCallables ?: 0).toDouble() / (r.publicCallables ?: 1)
            }.take(5).joinToString("; ") { r ->
                "${r.slug} ${(r.reachedPublicCallables ?: 0)} of ${r.publicCallables}"
            }
            return Check(
                name,
                State.FAIL,
                String.format("%.4f < %.2f: %s", fraction, EXPORTED_REACH_TARGET, worst),
            )
        }
        return Check(
            name,
            State.PASS,
            String.format("%.4f (%d of %d public callables)", fraction, totalReached, totalPublic),
        )
    }

    /**
     * The breakdown gate: an aggregate count is not a result (golem's 6178
     * nodes were 99.7% stdlib). Every graph slot must publish the four-way
     * node and edge split, and the parts must SUM to the totals — a
     * breakdown that does not add up is a breakdown nobody computed.
     */
    private fun graphBreakdownCheck(current: BenchRunner.BenchResult): Check {
        val name = "graph-breakdown"
        val rows = graphRows(current)
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no slot published a call graph (run the resolved tier)")
        }
        val mismatched = mutableListOf<String>()
        for (row in rows) {
            val nodeSum = (row.graphLocalNodes ?: 0) + (row.graphStdlibNodes ?: 0) +
                (row.graphDependencyNodes ?: 0) + (row.graphSyntheticNodes ?: 0)
            val edgeSum = (row.graphLocalEdges ?: 0) + (row.graphStdlibEdges ?: 0) +
                (row.graphDependencyEdges ?: 0) + (row.graphSyntheticEdges ?: 0)
            if (nodeSum != row.graphNodes || edgeSum != row.graphEdges) {
                mismatched.add("${row.slug}/${row.slot} nodes $nodeSum != ${row.graphNodes}, edges $edgeSum != ${row.graphEdges}")
            }
        }
        if (mismatched.isNotEmpty()) {
            return Check(name, State.FAIL, mismatched.joinToString("; "))
        }
        val totalNodes = rows.sumOf { it.graphNodes ?: 0 }
        val totalEdges = rows.sumOf { it.graphEdges ?: 0 }
        val local = rows.sumOf { it.graphLocalNodes ?: 0 }
        val stdlib = rows.sumOf { it.graphStdlibNodes ?: 0 }
        val dependency = rows.sumOf { it.graphDependencyNodes ?: 0 }
        val synthetic = rows.sumOf { it.graphSyntheticNodes ?: 0 }
        return Check(
            name,
            State.PASS,
            "$totalNodes node(s) / $totalEdges edge(s) over ${rows.size} slot(s) " +
                "split local=$local stdlib=$stdlib dependency=$dependency synthetic=$synthetic (nodes)",
        )
    }
}
