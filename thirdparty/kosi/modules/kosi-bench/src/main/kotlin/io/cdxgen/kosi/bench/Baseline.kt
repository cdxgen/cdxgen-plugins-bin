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
                Check("fixture-coverage", State.PASS, "${current.results.size} slots run (both modes)")
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

        val verdict = when {
            checks.all { it.state == State.PASS } -> "PROMOTE"
            checks.any { it.state == State.FAIL } -> "HOLD (regressions)"
            else -> "HOLD (criteria unevaluated)"
        }
        return Report(verdict, checks)
    }

    /** The P1 gate's per-repo resolved-call-ratio target. */
    const val RESOLVED_RATIO_TARGET = 0.90

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
            "${r.slug}=" + (r.resolvedCallRatio?.let { String.format("%.4f", it) } ?: "n/a")
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
        val belowTarget = repos.filter { (it.resolvedCallRatio ?: 0.0) < RESOLVED_RATIO_TARGET }
        val detail = if (belowTarget.isEmpty()) {
            "$measured (all >= ${"%.2f".format(RESOLVED_RATIO_TARGET)})"
        } else {
            "$measured; below the ${"%.2f".format(RESOLVED_RATIO_TARGET)} target and held at the " +
                "baseline value: ${belowTarget.joinToString(", ") { it.slug }}"
        }
        return Check(name, State.PASS, detail)
    }
}
