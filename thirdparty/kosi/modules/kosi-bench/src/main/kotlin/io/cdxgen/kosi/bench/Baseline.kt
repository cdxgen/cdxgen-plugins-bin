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

        // 2. precision per flow — LIVE since P4: over the fixture tier, the
        // fraction of reported slices some positive flow expectation actually
        // asked for, counted per FLOW and capped per expectation by its
        // count=. A slice nobody asked for is a false positive by definition.
        checks.add(precisionPerFlowCheck(current))

        // 2b. taint recall over flow expectations on the fixture tier, as a
        // fraction with BOTH counts (the P4 gate, raised to the P5 bar: 0.90).
        checks.add(taintRecallCheck(current))

        // 2c. the worklist cap AND the P5 SCC iteration cap: 0 hits, each
        // with its own denominator in the detail line.
        checks.add(fixpointCapCheck(current))

        // 2d-2f. the P5 gates: computed summaries with a multi-key origin
        // distribution, the default-origin share under 10%, and the async
        // tier's own recall (P6).
        checks.add(summariesComputedCheck(current))
        checks.add(defaultOriginShareCheck(current))
        checks.add(asyncRecallCheck(current))

        // 3. connectivity 1.000, integrity 0 — evaluable, with the vacuity
        // caveat stated so a vacuous pass is never mistaken for a flow result.
        // Since P4 the fixtures publish slices, so zero slices is
        // NOT_EVALUATED (the engine regressed) rather than a vacuous pass.
        checks.add(
            when {
                curTotal.connectivity == 1.0 && curTotal.sliceCount > 0 -> Check(
                    "connectivity",
                    State.PASS,
                    "1.000 over ${curTotal.sliceCount} slice(s)",
                )

                curTotal.connectivity == 1.0 -> Check(
                    "connectivity",
                    State.NOT_EVALUATED,
                    "1.000 over 0 slices (vacuous: the run produced no slices, so there is nothing to confirm)",
                )

                else -> Check("connectivity", State.FAIL, "below 1.000: ${curTotal.connectivity}")
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

        // 5. dependency-crossing flows, LIVE since P5. The summaries give a
        // slice two ENDS: source and sink functions with their own module
        // paths and purls, and the flags are computed from those ends — not
        // written as a constant the gate then reads back (R55's rule). Zero
        // crossings over slices is still NOT_EVALUATED, never a pass; and a
        // run that LOSES every crossing its baseline measured is a
        // regression, the same two-way discipline the corpus ratchet uses.
        checks.add(dependencyCrossingCheck(current, baseline))

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

        // 8+9. per-real-repo flow counts and wall clock. The flow-count arm
        // is LIVE since P4: a repo whose slice count drops below its
        // baseline is golem's SEAM regression, seen exactly where it happens.
        checks.add(perRepoFlowCountCheck(current, baseline))
        if (baseline != null) {
            val baselineRepoKeys = baseline.results.filter { it.tier in REPO_TIERS }.map { it.slug + "/" + it.slot }
            if (baselineRepoKeys.isEmpty()) {
                checks.add(Check("per-repo-wall-clock", State.NOT_EVALUATED, "no repo-tier entries in baseline"))
            } else {
                val curByKey = current.results.associateBy { it.slug + "/" + it.slot }
                val slow = baseline.results.filter { it.tier in REPO_TIERS }.filter { base ->
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
        checks.add(perRepoExportedReachCheck(current, baseline))
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

    /** The P4 gate, raised to the P5 bar: taint recall over flow expectations. */
    const val TAINT_RECALL_TARGET = 0.90

    /** The P4 gate: precision per flow (slices asked-for over slices reported). */
    const val TAINT_PRECISION_TARGET = 0.95

    private fun fixtureRows(current: BenchRunner.BenchResult): List<BenchRunner.FixtureResult> =
        current.results.filter { it.tier == "fixtures" && it.slug != "TOTAL" }

    /** The async tier's rows (P6): bundled coroutine/Flow fixtures, gated separately. */
    private fun asyncRows(current: BenchRunner.BenchResult): List<BenchRunner.FixtureResult> =
        current.results.filter { it.tier == "async" && it.slug != "TOTAL" }

    /**
     * Taint recall on the single-function corpus tier: satisfied flow
     * EXPECTATIONS over evaluated flow expectations, both counts in the
     * detail line. A run with no live flow expectation cannot evaluate the
     * gate and never passes by having nothing to look at.
     */
    private fun taintRecallCheck(current: BenchRunner.BenchResult): Check {
        val name = "taint-recall"
        val rows = fixtureRows(current)
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no fixture-tier rows in this run")
        }
        val positives = rows.sumOf { it.flowPositives }
        val matched = rows.sumOf { it.flowPositivesMatched }
        if (positives == 0) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "no non-known-fail flow expectation was evaluated on the fixture tier, so there is nothing to recall",
            )
        }
        val fraction = matched.toDouble() / positives
        val worst = rows.filter { it.flowPositives > 0 && it.flowPositivesMatched < it.flowPositives }
            .sortedBy { it.flowPositivesMatched.toDouble() / it.flowPositives }
            .take(5)
            .joinToString("; ") { "${it.slug}/${it.slot} ${it.flowPositivesMatched} of ${it.flowPositives}" }
        return if (fraction < TAINT_RECALL_TARGET) {
            Check(
                name,
                State.FAIL,
                String.format("%.4f < %.2f (%d of %d flow expectations)%s", fraction, TAINT_RECALL_TARGET, matched, positives, worst.let { if (it.isEmpty()) "" else ": $it" }),
            )
        } else {
            Check(name, State.PASS, String.format("%.4f (%d of %d flow expectations)", fraction, matched, positives))
        }
    }

    /**
     * Precision per flow on the fixture tier: slices some positive flow
     * expectation asked for, over ALL reported slices. A slice nobody asked
     * for is a false positive — including one in a fixture whose annotations
     * deliberately expect none. Not evaluated while no slices exist (a run
     * without slices can neither pass nor fail it).
     */
    private fun precisionPerFlowCheck(current: BenchRunner.BenchResult): Check {
        val name = "precision-per-flow"
        // Precision holds across fixtures AND async tiers together: async is
        // where over-broad propagation is most tempting, and its seven
        // fixtures would be diluted into silence inside the fixture number.
        val rows = fixtureRows(current) + asyncRows(current)
        val reported = rows.sumOf { it.sliceCount }
        if (reported == 0) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "no slices reported on the fixture tier, so there is nothing to be precise about",
            )
        }
        val truePositives = rows.sumOf { it.flowTruePositives }
        val fraction = truePositives.toDouble() / reported
        val offenders = rows.filter { row ->
            row.sliceCount > 0 && row.flowTruePositives < row.sliceCount
        }.sortedBy { row -> row.flowTruePositives.toDouble() / row.sliceCount }
            .take(5)
            .joinToString("; ") { "${it.slug}/${it.slot} ${it.flowTruePositives} of ${it.sliceCount}" }
        return if (fraction < TAINT_PRECISION_TARGET) {
            Check(
                name,
                State.FAIL,
                String.format("%.4f < %.2f (%d of %d slices)%s", fraction, TAINT_PRECISION_TARGET, truePositives, reported, offenders.let { if (it.isEmpty()) "" else ": $it" }),
            )
        } else {
            Check(name, State.PASS, String.format("%.4f (%d of %d slices)", fraction, truePositives, reported))
        }
    }

    /**
     * The worklist cap: on the fixture tier, `fixpointCapHits` must be 0 —
     * and the detail line carries the functions-analysed denominator, because
     * a cap count without the population it was measured over is R25's shape
     * one phase later. A run that analysed nothing cannot evaluate this.
     */
    private fun fixpointCapCheck(current: BenchRunner.BenchResult): Check {
        val name = "fixpoint-cap"
        val rows = fixtureRows(current).filter { it.functionsAnalysed != null }
        if (rows.isEmpty()) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "no fixture-tier slot reported a functions-analysed count (run the resolved tier)",
            )
        }
        val analysed = rows.sumOf { it.functionsAnalysed ?: 0 }
        val hits = rows.sumOf { it.fixpointCapHits ?: 0 }
        // The P5 SCC iteration cap is a SECOND counter with its own
        // denominator (SCCs processed) — a cap without its population is
        // R25's shape, in either counter.
        val sccs = rows.sumOf { it.sccsProcessed ?: 0 }
        val sccHits = rows.sumOf { it.sccIterationCapHits ?: 0 }
        return if (hits == 0 && sccHits == 0) {
            Check(name, State.PASS, "0 worklist cap hits over $analysed analysed function(s); 0 SCC " +
                "iteration cap hits over $sccs SCC(s)")
        } else {
            val offenders = rows.filter { (it.fixpointCapHits ?: 0) > 0 || (it.sccIterationCapHits ?: 0) > 0 }
                .joinToString("; ") {
                    "${it.slug}/${it.slot} worklist ${it.fixpointCapHits}/${it.functionsAnalysed}, " +
                        "SCC ${it.sccIterationCapHits}/${it.sccsProcessed}"
                }
            Check(name, State.FAIL, "$hits worklist cap hit(s) over $analysed function(s), " +
                "$sccHits SCC cap hit(s) over $sccs SCC(s): $offenders")
        }
    }

    /**
     * Per-repo flow counts, two-way: a repo may not lose slices against its
     * baseline. Baselines written before the engine shipped carry no flow
     * data at all, and the check says so rather than passing vacuously.
     */
    private fun perRepoFlowCountCheck(current: BenchRunner.BenchResult, baseline: BenchRunner.BenchResult?): Check {
        val name = "per-repo-flow-counts"
        val rows = current.results.filter { it.tier in REPO_TIERS && it.slug != "TOTAL" && it.slot != "all" }
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no repo-tier rows in this run")
        }
        val baseByKey = baseline?.results?.associateBy { it.slug + "/" + it.slot }
        if (baseByKey == null || baseByKey.values.all { it.flowPositives == 0 && it.sliceCount == 0 && it.flowTruePositives == 0 && it.functionsAnalysed == null }) {
            val counts = rows.sortedBy { it.slug }.joinToString(", ") { "${it.slug}/${it.slot}=${it.sliceCount}" }
            return Check(
                name,
                State.NOT_EVALUATED,
                "the baseline carries no flow data to ratchet against; measured slices: $counts",
            )
        }
        val regressed = mutableListOf<String>()
        for (row in rows) {
            val base = baseByKey[row.slug + "/" + row.slot]
            if (base == null) continue
            if (base.sliceCount > row.sliceCount) {
                regressed.add("${row.slug}/${row.slot} slices ${base.sliceCount} -> ${row.sliceCount}")
            }
            if (base.functionsAnalysed != null && (row.functionsAnalysed ?: 0) < base.functionsAnalysed) {
                regressed.add(
                    "${row.slug}/${row.slot} analysed functions ${base.functionsAnalysed} -> ${row.functionsAnalysed}",
                )
            }
        }
        val counts = rows.sortedBy { it.slug }.joinToString(", ") { "${it.slug}/${it.slot}=${it.sliceCount}" }
        return if (regressed.isEmpty()) {
            Check(name, State.PASS, "no repo lost slices or analysis coverage; slices: $counts")
        } else {
            Check(name, State.FAIL, regressed.joinToString("; "))
        }
    }

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
        val repos = lowered.filter { it.tier in REPO_TIERS }.sortedBy { it.slug }
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
            .filter { it.tier in REPO_TIERS && it.slot == MatrixSlot.RESOLVED_LABEL }
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
     * The exported-reach gate: on the fixture tier's exported slots, the
     * fraction of public API callables that became roots and are reached,
     * with BOTH counts in the detail line. A shortfall names where
     * resolution lost visibility facts — the 95% bar exists so `--roots
     * exported` cannot silently root nothing on a library (golem: with only
     * `main`, a library yields no graph at all).
     *
     * The denominator is `declarations`, not the graph's own public nodes.
     * Counting nodes made this a tautology — the exported selector picks
     * exactly the public local nodes and a root is reached at distance 0, so
     * it read 1.0000 on every fixture and all five repos and could not fail.
     * Against the front end's independent inventory, a public callable that
     * never became a node costs a point, which is the failure the gate is for.
     *
     * Scope: the FIXTURE tier, as the P3 roadmap defined it ("a library
     * fixture"). The pinned repos are REPORTED in the detail line but do not
     * hold the bar: their denominators only became honest with R49's fix,
     * and the real repo figures name a known, owned gap — public methods
     * DECLARED IN JAVA, whose bodies the Kotlin-only lowering never produces
     * (R49's `Greeter.greet` at repo scale; P9's bytecode tier closes it).
     * A per-repo bar returns when that tier lands.
     */
    private fun exportedReachCheck(current: BenchRunner.BenchResult): Check {
        val name = "exported-reach"
        val rows = current.results.filter {
            it.slug != "TOTAL" && it.slot == MatrixSlot.EXPORTED_LABEL && it.publicCallables != null
        }
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no exported slot published a call graph")
        }
        val fixtureRows = rows.filter { it.tier == "fixtures" }
        val totalPublic = fixtureRows.sumOf { it.publicCallables ?: 0 }
        val totalReached = fixtureRows.sumOf { it.reachedPublicCallables ?: 0 }
        val repoRows = rows.filter { it.tier in REPO_TIERS }.sortedBy { it.slug }
        val repoDetail = repoRows.joinToString(", ") { r ->
            val pub = r.publicCallables ?: 0
            val reached = r.reachedPublicCallables ?: 0
            "${r.slug}=" + if (pub == 0) "n/a" else String.format("%.4f (%d/%d)", reached.toDouble() / pub, reached, pub)
        }
        val repoSummary = if (repoRows.isEmpty()) {
            ""
        } else {
            "; repos (reported, not gated — Java-declared bodies await P9): $repoDetail"
        }
        if (fixtureRows.isEmpty() || totalPublic == 0) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "fixture exported slots name 0 public callables; visibility facts missing$repoSummary",
            )
        }
        val fraction = totalReached.toDouble() / totalPublic
        if (fraction < EXPORTED_REACH_TARGET) {
            val worst = fixtureRows.sortedBy { r ->
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
            String.format("%.4f (%d of %d public callables)", fraction, totalReached, totalPublic) + repoSummary,
        )
    }

    /**
     * The repo half of exported reach, as a RATCHET rather than a bar.
     *
     * P4 moved the 0.95 bar to the fixture tier for a defensible reason —
     * the repo denominators only became honest with R49's fix, and the real
     * figures are dominated by public methods declared in Java, whose bodies
     * P9's bytecode tier owns. But narrowing a gate's population in the same
     * change that would have made it fail leaves the excluded population
     * measured by nothing, and "reported in a detail line" is not a check:
     * spring-fu could fall from 0.5359 to 0.05 and every gate would still be
     * green. So the repo fractions hold no absolute bar and instead may not
     * DROP against the baseline — the same two-way discipline the corpus
     * ratchet uses, and it costs this phase nothing because the numbers are
     * already measured.
     */
    private fun perRepoExportedReachCheck(
        current: BenchRunner.BenchResult,
        baseline: BenchRunner.BenchResult?,
    ): Check {
        val name = "per-repo-exported-reach"
        val rows = current.results.filter {
            it.tier in REPO_TIERS && it.slug != "TOTAL" && it.slot == MatrixSlot.EXPORTED_LABEL &&
                (it.publicCallables ?: 0) > 0
        }.sortedBy { it.slug }
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no repo-tier exported slot named any public callable")
        }
        fun fractionOf(r: BenchRunner.FixtureResult): Double =
            (r.reachedPublicCallables ?: 0).toDouble() / (r.publicCallables ?: 1)
        val measured = rows.joinToString(", ") { String.format("%s=%.4f (%d/%d)", it.slug, fractionOf(it), it.reachedPublicCallables ?: 0, it.publicCallables ?: 0) }
        val baseByKey = baseline?.results
            ?.filter { (it.publicCallables ?: 0) > 0 }
            ?.associateBy { it.slug + "/" + it.slot }
            .orEmpty()
        if (baseByKey.isEmpty()) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "the baseline carries no per-repo exported-reach to ratchet against; measured: $measured",
            )
        }
        val dropped = rows.mapNotNull { row ->
            val base = baseByKey[row.slug + "/" + row.slot] ?: return@mapNotNull null
            val before = fractionOf(base)
            val after = fractionOf(row)
            // A hair of movement is re-resolution noise, not a regression.
            if (after < before - 0.005) {
                String.format("%s %.4f -> %.4f", row.slug, before, after)
            } else {
                null
            }
        }
        return if (dropped.isEmpty()) {
            Check(name, State.PASS, "no repo lost exported reach; $measured")
        } else {
            Check(name, State.FAIL, "exported reach fell on ${dropped.size} repo(s): " + dropped.joinToString("; "))
        }
    }

    /**
     * The LIVE dependency-crossing check. Both counts are read from the
     * bench rows (which the bench read from the slices), the detail line
     * carries both populations, zero is NOT_EVALUATED with the reason, and
     * losing every crossing the baseline measured is a FAIL.
     */
    private fun dependencyCrossingCheck(
        current: BenchRunner.BenchResult,
        baseline: BenchRunner.BenchResult?,
    ): Check {
        val name = "dependency-crossing-flows"
        val rows = fixtureRows(current) + asyncRows(current)
        val crossDep = rows.sumOf { it.crossDependencySlices ?: 0 }
        val crossMod = rows.sumOf { it.crossModuleSlices ?: 0 }
        if (rows.sumOf { it.sliceCount } == 0) {
            return Check(name, State.NOT_EVALUATED, "no slices reported on the fixture or async tiers")
        }
        // The regression arm BEFORE the zero arm: losing every crossing the
        // baseline measured must FAIL, not read NOT_EVALUATED past it.
        val baseRows = baseline?.results?.filter { it.tier == "fixtures" || it.tier == "async" }.orEmpty()
        val baseCross = baseRows.sumOf { it.crossDependencySlices ?: 0 } + baseRows.sumOf { it.crossModuleSlices ?: 0 }
        if (baseCross > 0 && crossDep + crossMod == 0) {
            return Check(name, State.FAIL, "baseline measured $baseCross crossing slice(s), this run measured 0")
        }
        if (crossDep == 0 && crossMod == 0) {
            return Check(
                name,
                State.NOT_EVALUATED,
                "0 crossing slices over ${rows.sumOf { it.sliceCount }} slice(s): no slice's source and sink " +
                    "landed in different modules or dependencies (P5's cross-module fixture should make this nonzero)",
            )
        }
        return Check(
            name,
            State.PASS,
            "$crossMod cross-module and $crossDep cross-dependency slice(s) over ${rows.sumOf { it.sliceCount }} " +
                "fixture/async slices, flags computed from the slice ends",
        )
    }

    /**
     * The P5 summaries gate: computed summaries must EXIST and their origin
     * distribution must name more than one producer — a single aggregate
     * number cannot answer the question the `origin` field exists to ask.
     * NOT_EVALUATED when no slot ran summaries — never a pass.
     */
    private fun summariesComputedCheck(current: BenchRunner.BenchResult): Check {
        val name = "summaries-computed"
        val rows = fixtureRows(current).filter { it.summariesComputed != null }
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no fixture-tier slot published summaries (run the resolved tier)")
        }
        val computed = rows.sumOf { it.summariesComputed ?: 0 }
        val byOrigin = rows
            .flatMap { r -> r.summariesByOrigin.entries.map { e -> e.key to e.value } }
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, vs) -> vs.sum() }
        val keys = byOrigin.keys.sorted()
        return if (computed > 0 && keys.size > 1) {
            Check(
                name,
                State.PASS,
                "$computed computed summar(ies) over ${rows.size} slot(s); origins: " +
                    keys.joinToString(", ") { "$it=${byOrigin[it]}" },
            )
        } else if (computed == 0) {
            Check(name, State.FAIL, "0 computed summaries over ${rows.size} slot(s): the interprocedural " +
                "engine regressed to intraprocedural")
        } else {
            Check(name, State.FAIL, "origins carry a single key ($keys): the origin provenance is not " +
                "distinguishing computed summaries from pack/default propagation")
        }
    }

    /**
     * The roadmap's P5 gate on blanket propagation: the fraction of slices
     * whose existence depends ONLY on `origin=default` must stay under 10%.
     * The denominator is the slices whose trace crossed at least one summary
     * boundary — an intraprocedural slice depends on no propagation at all —
     * and BOTH counts are published. NOT_EVALUATED over zero such slices.
     */
    private fun defaultOriginShareCheck(current: BenchRunner.BenchResult): Check {
        val name = "default-origin-share"
        val rows = fixtureRows(current) + asyncRows(current)
        val crossing = rows.sumOf { it.summaryCrossingSlices ?: 0 }
        val defaultOnly = rows.sumOf { it.defaultOriginSlices ?: 0 }
        if (rows.sumOf { it.sliceCount } == 0) {
            return Check(name, State.NOT_EVALUATED, "no slices reported on the fixture or async tiers")
        }
        if (crossing == 0) {
            return Check(name, State.NOT_EVALUATED, "0 slices crossed a summary boundary, so no slice's " +
                "existence depends on propagation")
        }
        val fraction = defaultOnly.toDouble() / crossing
        val detail = String.format("%.4f (%d of %d summary-crossing slices depend only on origin=default)",
            fraction, defaultOnly, crossing)
        return if (fraction < DEFAULT_ORIGIN_SHARE_MAX) {
            Check(name, State.PASS, detail)
        } else {
            Check(name, State.FAIL, "$detail >= $DEFAULT_ORIGIN_SHARE_MAX")
        }
    }

    /**
     * The P6 async gate: recall >= 0.90 on the async tier SPECIFICALLY, as
     * its own fraction with both counts — not folded into the fixture-tier
     * number, where seven async fixtures would be diluted by thirty others.
     * NOT_EVALUATED when the async tier did not run.
     */
    private fun asyncRecallCheck(current: BenchRunner.BenchResult): Check {
        val name = "async-recall"
        val rows = asyncRows(current)
        if (rows.isEmpty()) {
            return Check(name, State.NOT_EVALUATED, "no async-tier rows in this run (the async tier did not run)")
        }
        val positives = rows.sumOf { it.flowPositives }
        val matched = rows.sumOf { it.flowPositivesMatched }
        if (positives == 0) {
            return Check(name, State.NOT_EVALUATED, "the async tier ran but evaluated no flow expectation")
        }
        val fraction = matched.toDouble() / positives
        val detail = String.format("%.4f (%d of %d async flow expectations)", fraction, matched, positives)
        return if (fraction < ASYNC_RECALL_TARGET) {
            val worst = rows.filter { it.flowPositives > 0 && it.flowPositivesMatched < it.flowPositives }
                .sortedBy { it.flowPositivesMatched.toDouble() / it.flowPositives }
                .take(5).joinToString("; ") { "${it.slug}/${it.slot} ${it.flowPositivesMatched} of ${it.flowPositives}" }
            Check(name, State.FAIL, "$detail < $ASYNC_RECALL_TARGET" + worst.let { if (it.isEmpty()) "" else ": $it" })
        } else {
            Check(name, State.PASS, detail)
        }
    }

    /** The roadmap P5 gate's ceiling on default-only propagation. */
    const val DEFAULT_ORIGIN_SHARE_MAX = 0.10

    /** The roadmap P6 gate: async-tier recall. */
    const val ASYNC_RECALL_TARGET = 0.90

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
