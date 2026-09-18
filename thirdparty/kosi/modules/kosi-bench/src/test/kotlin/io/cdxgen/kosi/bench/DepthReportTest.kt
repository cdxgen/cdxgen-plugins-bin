package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.CorpusManifest
import io.cdxgen.kosi.endpoints.Endpoints
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.JsonWriter
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P20 §0: publish the depth you actually have, before improving it — a
 * claim about precision without a denominator is the thing this project
 * does not do. For every bundled fixture this gate answers three questions
 * and commits the answers as a golden ([depth-report.json]):
 *
 *  1. VALUE RESOLUTION — of every value the endpoint consumers asked the
 *     folder for, what fraction folded, and of the rest, how many failed
 *     for each named reason: cross-block, depth cap, parameter,
 *     non-constant producer. Measured BOTH ways over one captured front
 *     end: the shipped cross-block fold, and `crossBlock = false` — the
 *     pre-P20 block-local scan, whose breakdown is the design input the
 *     §2 extension was judged against.
 *  2. TAINT — sources seeded (pack sites + endpoint parameters), sinks
 *     reached, slices published, and the three ways a finding dies before
 *     or degrades at publication: no provable path, fixpoint cap,
 *     missing summary. The sanitizers that actually cleared a fact are
 *     named; the ones that never fired in any measured fixture are named
 *     louder — a sanitizer that never fires is R63 for the security pack.
 *  3. REACHABILITY — of the published findings, how many carry a COMPLETE
 *     entrypoint→sink path, how many a PARTIAL one (elided, endpoints
 *     guaranteed), and how many carry NONE and stand on the strength of a
 *     symbol match alone. That last number is the one an SCA consumer
 *     cares about most.
 *
 * The report carries counters only — no paths, no commit, no walls — so
 * the golden is byte-stable across machines. Regenerate a deliberate move:
 *
 *     KOSI_UPDATE_DEPTH_REPORT=1 ./gradlew :kosi-bench:test --tests 'io.cdxgen.kosi.bench.DepthReportTest'
 */
class DepthReportTest {

    private val repoRoot: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            if (Files.isRegularFile(current.resolve("corpus.toml"))) return@run current
            current = current.parent
        }
        error("corpus.toml not found upward from the working directory")
    }

    private val reportFile = Path.of("src/test/resources/depth/depth-report.json")

    private val bundledTiers = setOf("fixtures", "frameworks", "crypto", "async", "vuln")

    private class ValueRow(
        val asked: Int,
        val folded: Int,
        val crossBlock: Int,
        val crossBlockRefused: Int,
        val crossBlockResolved: Int,
        val depthCap: Int,
        val parameter: Int,
        val producer: Int,
    )

    private class FixtureRow(
        val slug: String,
        val valueBlockLocal: ValueRow,
        val valueCrossBlock: ValueRow,
        val configTotal: Int,
        val configResolved: Int,
        val sourceSites: Int,
        val entryFactsSeeded: Int,
        val sinkSites: Int,
        val slicesPublished: Int,
        val droppedUnprovable: Int,
        val capAffectedHits: Int,
        val summaryMissing: Int,
        val sanitizersFired: Set<String>,
        val findings: Int,
        val completePath: Int,
        val partialPath: Int,
        val noPath: Int,
        val integrityViolations: Int,
    )

    @Test
    fun depthReportMatchesGolden() {
        val manifest = CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        val entries = manifest.entries.filter { it.tier in bundledTiers && it.path != null }
        assertTrue(entries.isNotEmpty(), "no bundled corpus entries found for the depth report")

        val pack = ModelPacks.loadBuiltin()
        val rows = mutableListOf<FixtureRow>()
        for (entry in entries) {
            val root = repoRoot.resolve(entry.path!!)
            var held: Analyzer.EndpointCapture? = null
            val report = Analyzer.analyze(
                root,
                AnalyzeOptions(backend = Backend.RESOLVED, classpathFile = entry.classpathFile, endpointSources = true),
                commit = "depth",
                endpointCapture = { held = it },
            )
            val capture = held ?: continue
            val endpoints = capture.endpoints ?: continue
            val depth = capture.flowDepth ?: continue

            // The baseline column: the same detection pass over the same
            // captured inputs, with the fold confined to its own block.
            val blockLocalStats = io.cdxgen.kosi.kir.KirValueFolder.FoldStats()
            Endpoints.analyze(
                capture.module, root, capture.sourceTexts, capture.annotationValues,
                Endpoints.Attribution(emptyMap(), emptyMap()), includeManifests = true,
                dependencyCoordinates = capture.dependencyCoordinates,
                foldStats = blockLocalStats,
                crossBlock = false,
            )

            val dataFlow = report?.dataFlow
            val slices = dataFlow?.slices.orEmpty()
            val nodesById = dataFlow?.nodes?.associateBy { it.id } ?: emptyMap()
            var complete = 0
            var partial = 0
            var none = 0
            for (slice in slices) {
                val headKind = nodesById[slice.nodeIds.firstOrNull()]?.kind
                val tailKind = nodesById[slice.nodeIds.lastOrNull()]?.kind
                when {
                    slice.elided == true -> partial++
                    slice.nodeIds.size >= 2 && headKind == "source" && tailKind == "sink" -> complete++
                    else -> none++
                }
            }
            val fired = depth.sanitizersApplied.toSet()
            rows.add(
                FixtureRow(
                    slug = entry.slug,
                    valueBlockLocal = blockLocalStats.toValueRow(),
                    valueCrossBlock = capture.foldStats.toValueRow(),
                    configTotal = endpoints.configValuesTotal,
                    configResolved = endpoints.configValuesResolved,
                    sourceSites = depth.sourceSites,
                    entryFactsSeeded = depth.entryFactsSeeded,
                    sinkSites = depth.sinkSites,
                    slicesPublished = slices.size,
                    droppedUnprovable = depth.slicesDroppedUnprovable,
                    capAffectedHits = depth.capAffectedSinkHits,
                    summaryMissing = depth.summaryMissingEvents,
                    sanitizersFired = fired,
                    findings = slices.size,
                    completePath = complete,
                    partialPath = partial,
                    noPath = none,
                    integrityViolations = dataFlow?.stats?.integrityViolations ?: 0,
                ),
            )
        }
        assertTrue(rows.isNotEmpty(), "no fixture produced a depth row")

        val json = render(pack, rows)
        if (System.getenv("KOSI_UPDATE_DEPTH_REPORT") == "1") {
            Files.createDirectories(reportFile.parent)
            Files.writeString(repoRoot.resolve("modules/kosi-bench").resolve(reportFile), json)
            println("depth-report: regenerated ${rows.size} rows")
            return
        }
        val golden = repoRoot.resolve("modules/kosi-bench").resolve(reportFile)
        assertTrue(Files.exists(golden), "depth report golden missing: $reportFile (run with KOSI_UPDATE_DEPTH_REPORT=1)")
        val expected = Files.readString(golden)
        assertTrue(
            json == expected,
            "depth report moved against the golden — an intentional depth change regenerates it " +
                "(KOSI_UPDATE_DEPTH_REPORT=1) and the phase report accounts for the delta by name",
        )
        println("depth-report: ${rows.size} fixtures measured, golden matched")
    }

    /**
     * P21 §4: the cheap structural gate the corpusChanged replay earned.
     * corpusChanged and corpusFull both answer "did a behaviour move" and
     * NEITHER answers "is this code reachable from any input we have" —
     * R131 ran green through every tier because no corpus input reached the
     * new code. The gate that answers THAT is a fixture, so every named
     * way the fold can fail must be non-zero in the committed report: a new
     * [FoldFailure] constant, or a widening that reclassifies an existing
     * one, cannot ship without a bundled fixture that drives it — the same
     * two-way ratchet the known-fail markers apply to expectations, applied
     * to the failure vocabulary itself.
     */
    @Test
    fun everyFoldFailureBucketIsNonZeroInTheCommittedReport() {
        val report = repoRoot.resolve("modules/kosi-bench").resolve(reportFile)
        assertTrue(Files.exists(report), "depth report golden missing: $reportFile")
        val totals = io.cdxgen.kosi.schema.JsonReader(Files.readString(report))
            .read().asObject()
            .obj("totals")
            ?.obj("valueResolution.crossBlock")
            ?: error("committed depth report has no totals.valueResolution.crossBlock object")
        for (failure in io.cdxgen.kosi.kir.KirValueFolder.FoldFailure.entries) {
            // CROSS_BLOCK -> "crossBlock", DEPTH_CAP -> "depthCap": the
            // report's keys are the enum names in lower camel case.
            val key = failure.name.split('_')
                .mapIndexed { i, part ->
                    if (i == 0) part.lowercase() else part.lowercase().replaceFirstChar { it.uppercase() }
                }
                .joinToString("")
            val counted = totals.long(key)
            assertTrue(
                counted != null,
                "FoldFailure.$failure is named by the folder but the depth report publishes no '$key' bucket — " +
                    "add the counter to ValueRow before shipping the constant",
            )
            assertTrue(
                counted!! > 0,
                "FoldFailure.$failure has never fired: its '$key' bucket is zero in the committed depth report. " +
                    "A capability no fixture exercises does not exist (R63) — add the fixture that drives it " +
                    "through Analyzer.analyze, or delete the constant (the P21 phase rule, written against R131)",
            )
        }
    }

    /**
     * P21 §2's bar, moved into the PASS line (rule 9). The phase took the
     * pack's fired-sanitizer count from 2 of 12 to 12 of 12 and recorded it
     * in the committed report — but a count that only lives in a golden
     * moves whenever the golden is regenerated, and P21 also removed the
     * liveness sweep's blanket sanitizer allowance that had covered the
     * other ten. So the count is asserted here instead: every sanitizer the
     * pack ships fires in at least one measured fixture, or it is not a
     * sanitizer this project can claim (R63).
     */
    @Test
    fun everySanitizerFiresInTheCommittedReport() {
        val report = repoRoot.resolve("modules/kosi-bench").resolve(reportFile)
        assertTrue(Files.exists(report), "depth report golden missing: $reportFile")
        val entries = io.cdxgen.kosi.schema.JsonReader(Files.readString(report))
            .read().asObject()
            .arr("sanitizers")
            ?.objects()
            ?: error("committed depth report has no sanitizers array")
        val packPatterns = ModelPacks.loadBuiltin().sanitizers.map { it.pattern }.toSortedSet()
        val recorded = entries.mapNotNull { it.str("pattern") }.toSortedSet()
        assertEquals(
            packPatterns,
            recorded,
            "the committed report must name every pack sanitizer — regenerate it (KOSI_UPDATE_DEPTH_REPORT=1)",
        )
        val inert = entries.asSequence()
            .filter { it.bool("fired") != true }
            .mapNotNull { it.str("pattern") }
            .toList()
        assertTrue(
            inert.isEmpty(),
            "sanitizers that fire in no measured fixture: $inert — a sanitizer nothing exercises is a silent " +
                "false-negative guarantee. Give it the R129 shape in fixtures/sanitizer-gallery (the sanitized " +
                "result reaches the sink directly, so removing the entry violates a want-not), or delete it. " +
                "P21 §2 took this count from 2 of 12 to 12 of 12; it only goes up.",
        )
    }

    private fun io.cdxgen.kosi.kir.KirValueFolder.FoldStats.toValueRow() = ValueRow(
        asked,
        folded,
        crossBlock,
        crossBlockRefused,
        crossBlockResolved,
        depthCap,
        parameter,
        producer,
    )

    private fun sum(rows: List<FixtureRow>, pick: (FixtureRow) -> Int): Int = rows.sumOf(pick)

    private fun render(pack: io.cdxgen.kosi.models.ModelPack, rows: List<FixtureRow>): String {
        val w = JsonWriter()
        w.beginObject()

        w.beginObject("totals")
        w.beginObject("valueResolution.blockLocal")
        for ((key, value) in summedValue(rows) { it.valueBlockLocal }) w.num(key, value.toLong())
        w.endObject()
        w.beginObject("valueResolution.crossBlock")
        for ((key, value) in summedValue(rows) { it.valueCrossBlock }) w.num(key, value.toLong())
        w.endObject()
        w.num("configValuesTotal", sum(rows) { it.configTotal }.toLong())
        w.num("configValuesResolved", sum(rows) { it.configResolved }.toLong())
        w.num("sourceSites", sum(rows) { it.sourceSites }.toLong())
        w.num("entryFactsSeeded", sum(rows) { it.entryFactsSeeded }.toLong())
        w.num("sinkSites", sum(rows) { it.sinkSites }.toLong())
        w.num("slicesPublished", sum(rows) { it.slicesPublished }.toLong())
        w.num("droppedUnprovable", sum(rows) { it.droppedUnprovable }.toLong())
        w.num("capAffectedSinkHits", sum(rows) { it.capAffectedHits }.toLong())
        w.num("summaryMissing", sum(rows) { it.summaryMissing }.toLong())
        w.num("findings", sum(rows) { it.findings }.toLong())
        w.num("completePath", sum(rows) { it.completePath }.toLong())
        w.num("partialPath", sum(rows) { it.partialPath }.toLong())
        w.num("noPath", sum(rows) { it.noPath }.toLong())
        w.num("integrityViolations", sum(rows) { it.integrityViolations }.toLong())
        w.endObject()

        // The sanitizer verdict is the security pack's R63 line: a pack
        // sanitizer no measured fixture ever cleared is named, never
        // silently skipped.
        val fired = rows.flatMapTo(sortedSetOf()) { it.sanitizersFired }
        w.beginArray("sanitizers")
        for (sanitizer in pack.sanitizers.sortedBy { it.pattern }) {
            w.beginObject()
            w.str("pattern", sanitizer.pattern)
            w.bool("fired", sanitizer.pattern in fired)
            w.endObject()
        }
        w.endArray()

        w.beginObject("fixtures")
        for (row in rows.sortedBy { it.slug }) {
            w.beginObject(row.slug)
            w.beginObject("valueResolution.blockLocal")
            for ((key, value) in row.valueBlockLocal.asMap()) w.num(key, value.toLong())
            w.endObject()
            w.beginObject("valueResolution.crossBlock")
            for ((key, value) in row.valueCrossBlock.asMap()) w.num(key, value.toLong())
            w.endObject()
            w.num("configValuesTotal", row.configTotal.toLong())
            w.num("configValuesResolved", row.configResolved.toLong())
            w.num("sourceSites", row.sourceSites.toLong())
            w.num("entryFactsSeeded", row.entryFactsSeeded.toLong())
            w.num("sinkSites", row.sinkSites.toLong())
            w.num("slicesPublished", row.slicesPublished.toLong())
            w.num("droppedUnprovable", row.droppedUnprovable.toLong())
            w.num("capAffectedSinkHits", row.capAffectedHits.toLong())
            w.num("summaryMissing", row.summaryMissing.toLong())
            w.beginArray("sanitizersFired")
            for (fqn in row.sanitizersFired.sorted()) w.str(fqn)
            w.endArray()
            w.num("findings", row.findings.toLong())
            w.num("completePath", row.completePath.toLong())
            w.num("partialPath", row.partialPath.toLong())
            w.num("noPath", row.noPath.toLong())
            w.num("integrityViolations", row.integrityViolations.toLong())
            w.endObject()
        }
        w.endObject()

        w.endObject()
        return w.render()
    }

    private fun summedValue(rows: List<FixtureRow>, pick: (FixtureRow) -> ValueRow): Map<String, Int> = sortedMapOf(
        "asked" to sum(rows) { pick(it).asked },
        "crossBlock" to sum(rows) { pick(it).crossBlock },
        "crossBlockRefused" to sum(rows) { pick(it).crossBlockRefused },
        "crossBlockResolved" to sum(rows) { pick(it).crossBlockResolved },
        "depthCap" to sum(rows) { pick(it).depthCap },
        "folded" to sum(rows) { pick(it).folded },
        "parameter" to sum(rows) { pick(it).parameter },
        "producer" to sum(rows) { pick(it).producer },
    )

    private fun ValueRow.asMap(): Map<String, Int> = sortedMapOf(
        "asked" to asked,
        "crossBlock" to crossBlock,
        "crossBlockRefused" to crossBlockRefused,
        "crossBlockResolved" to crossBlockResolved,
        "depthCap" to depthCap,
        "folded" to folded,
        "parameter" to parameter,
        "producer" to producer,
    )
}
