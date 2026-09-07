package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.Annotation
import io.cdxgen.kosi.corpus.AnnotationParser
import io.cdxgen.kosi.corpus.CorpusEntry
import io.cdxgen.kosi.corpus.CorpusManifest
import io.cdxgen.kosi.corpus.Evaluator
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.JsonReader
import io.cdxgen.kosi.schema.JsonWriter
import java.nio.file.Files
import java.nio.file.Path

/**
 * Runs the corpus matrix and computes the metrics (06-CORPUS.md §4).
 * Structural recall, per-mode, per fixture; flow recall/precision become
 * measurable once slices exist (phase 3) and are reported as
 * not-yet-evaluatable until then, never as zeros that look like results.
 */
object BenchRunner {

    data class FixtureResult(
        val slug: String,
        val tier: String,
        val slot: String,
        val annotations: Int,
        val positives: Int,
        val negatives: Int,
        val pass: Int,
        val fail: Int,
        val xfail: Int,
        val xpass: Int,
        val positivesPassed: Int,
        val positivesRecallDenominator: Int,
        val recall: Double,
        val connectivity: Double,
        val integrityViolations: Int,
        val wallMillis: Long,
        val parseErrors: Int,
        val digest: Digests.FixtureDigest,
        val failures: List<String> = emptyList(),
    ) {
        fun toJson(w: JsonWriter, key: String? = null) {
            w.beginObject(key)
            w.num("annotations", annotations)
            w.dbl("connectivity", connectivity)
            w.str("digest", digest.sections["report"] ?: "")
            w.num("fail", fail)
            w.num("integrityViolations", integrityViolations)
            w.num("negatives", negatives)
            w.num("parseErrors", parseErrors)
            w.num("pass", pass)
            w.num("positives", positives)
            w.num("positivesPassed", positivesPassed)
            w.num("positivesRecallDenominator", positivesRecallDenominator)
            w.dbl("recall", recall)
            w.str("slot", slot)
            w.str("slug", slug)
            w.num("wallMillis", wallMillis)
            w.num("xfail", xfail)
            w.num("xpass", xpass)
            w.str("tier", tier)
            w.endObject()
        }

        fun failuresJson(w: JsonWriter, key: String? = null) {
            w.beginArray(key)
            for (f in failures) w.str(f)
            w.endArray()
        }
    }

    data class BenchResult(
        val results: List<FixtureResult>,
        val toolCommit: String,
        val medianWallMillis: Long,
        val worstWallMillis: Long,
        val peakRssBytes: Long,
    ) {
        fun toJson(): String {
            val w = JsonWriter()
            w.beginObject()
            w.str("toolCommit", toolCommit)
            w.num("medianWallMillis", medianWallMillis)
            w.num("worstWallMillis", worstWallMillis)
            w.num("peakRssBytes", peakRssBytes)
            w.beginObject("failures")
            for (r in results.filter { it.failures.isNotEmpty() }) {
                r.failuresJson(w, r.slug + "/" + r.slot)
            }
            w.endObject()
            w.beginArray("results")
            for (r in results) r.toJson(w)
            w.endArray()
            totals().toJson(w, "totals")
            w.endObject()
            return w.render()
        }

        fun totals(): FixtureResult {
            val pass = results.sumOf { it.pass }
            val fail = results.sumOf { it.fail }
            val xfail = results.sumOf { it.xfail }
            val xpass = results.sumOf { it.xpass }
            val positives = results.sumOf { it.positives }
            val positivesPassed = results.sumOf { it.positivesPassed }
            val recallDenominator = results.sumOf { it.positivesRecallDenominator }
            val negatives = results.sumOf { it.negatives }
            val annotations = results.sumOf { it.annotations }
            val parseErrors = results.sumOf { it.parseErrors }
            val integrity = results.sumOf { it.integrityViolations }
            val recall = if (recallDenominator == 0) 1.0 else positivesPassed.toDouble() / recallDenominator
            val connectivity = if (results.isEmpty()) {
                1.0
            } else {
                results.minOf { it.connectivity }
            }
            return FixtureResult(
                slug = "TOTAL",
                tier = "all",
                slot = "all",
                annotations = annotations,
                positives = positives,
                negatives = negatives,
                pass = pass,
                fail = fail,
                xfail = xfail,
                xpass = xpass,
                positivesPassed = positivesPassed,
                positivesRecallDenominator = recallDenominator,
                recall = recall,
                connectivity = connectivity,
                integrityViolations = integrity,
                wallMillis = results.sumOf { it.wallMillis },
                parseErrors = parseErrors,
                digest = Digests.FixtureDigest("TOTAL", "all", emptyMap()),
            )
        }

        companion object {
            fun fromJson(text: String): BenchResult {
                val root = JsonReader.parse(text).asObject()
                val results = root.arr("results")?.objects()?.map { r ->
                    FixtureResult(
                        slug = r.str("slug") ?: "",
                        tier = r.str("tier") ?: "",
                        slot = r.str("slot") ?: "",
                        annotations = (r.long("annotations") ?: 0).toInt(),
                        positives = (r.long("positives") ?: 0).toInt(),
                        negatives = (r.long("negatives") ?: 0).toInt(),
                        pass = (r.long("pass") ?: 0).toInt(),
                        fail = (r.long("fail") ?: 0).toInt(),
                        xfail = (r.long("xfail") ?: 0).toInt(),
                        xpass = (r.long("xpass") ?: 0).toInt(),
                        positivesPassed = (r.long("positivesPassed") ?: 0).toInt(),
                        positivesRecallDenominator = (r.long("positivesRecallDenominator") ?: 0).toInt(),
                        recall = r.dbl("recall") ?: 0.0,
                        connectivity = r.dbl("connectivity") ?: 0.0,
                        integrityViolations = (r.long("integrityViolations") ?: 0).toInt(),
                        wallMillis = r.long("wallMillis") ?: 0,
                        parseErrors = (r.long("parseErrors") ?: 0).toInt(),
                        digest = Digests.FixtureDigest(r.str("slug") ?: "", r.str("slot") ?: "", emptyMap()),
                    )
                } ?: emptyList()
                return BenchResult(
                    results = results,
                    toolCommit = root.str("toolCommit") ?: "",
                    medianWallMillis = root.long("medianWallMillis") ?: 0,
                    worstWallMillis = root.long("worstWallMillis") ?: 0,
                    peakRssBytes = root.long("peakRssBytes") ?: 0,
                )
            }
        }
    }

    class BenchException(message: String) : RuntimeException(message)

    data class RunOptions(
        val tiers: Set<String> = setOf("fixtures"),
        val only: String? = null,
        val skipMissingRepos: Boolean = false,
    )

    fun run(repoRoot: Path, runOptions: RunOptions, commit: String): BenchResult {
        val manifest = CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        val entries = manifest.select(runOptions.tiers, runOptions.only)
        if (entries.isEmpty()) {
            throw BenchException(
                "no corpus entries for tiers ${runOptions.tiers} (check corpus.toml)",
            )
        }
        val results = mutableListOf<FixtureResult>()
        for (entry in entries) {
            val dir = materialize(repoRoot, entry, runOptions.skipMissingRepos) ?: continue
            val annotations = parseAnnotations(dir, entry)
            for (slot in Matrix.defaultMatrix()) {
                results.add(runSlot(entry, dir, annotations, slot, commit))
            }
        }
        val walls = results.map { it.wallMillis }.sorted()
        return BenchResult(
            results = results.sortedWith(compareBy({ it.slug }, { it.slot })),
            toolCommit = commit,
            medianWallMillis = if (walls.isEmpty()) 0 else walls[walls.size / 2],
            worstWallMillis = walls.maxOrNull() ?: 0,
            peakRssBytes = Analyzer.peakRssBytes(),
        )
    }

    private fun materialize(repoRoot: Path, entry: CorpusEntry, skipMissing: Boolean): Path? {
        if (entry.path != null) {
            val dir = repoRoot.resolve(entry.path)
            if (!Files.isDirectory(dir)) {
                if (skipMissing) return null
                throw BenchException("fixture ${entry.slug}: missing directory ${entry.path}")
            }
            return dir
        }
        // Pinned upstream repo, cached under .corpus-cache/<slug>/ at an exact sha.
        val cache = repoRoot.resolve(".corpus-cache").resolve(entry.slug)
        if (isCheckedOutAt(cache, entry.sha!!)) return cache
        val fetch = ProcessBuilder(
            "git", "clone", "--quiet", entry.repo!!, cache.toString(),
        ).redirectErrorStream(true).start()
        val output = fetch.inputStream.bufferedReader().readText()
        fetch.waitFor()
        if (fetch.exitValue() != 0) {
            if (skipMissing) return null
            throw BenchException("fixture ${entry.slug}: git clone failed:\n$output")
        }
        val checkout = ProcessBuilder("git", "-C", cache.toString(), "checkout", "--quiet", entry.sha)
            .redirectErrorStream(true).start()
        checkout.waitFor()
        if (checkout.exitValue() != 0) {
            throw BenchException("fixture ${entry.slug}: checkout ${entry.sha} failed")
        }
        return cache
    }

    private fun isCheckedOutAt(dir: Path, sha: String): Boolean {
        if (!Files.isDirectory(dir)) return false
        val process = ProcessBuilder("git", "-C", dir.toString(), "rev-parse", "HEAD")
            .redirectErrorStream(true).start()
        val out = process.inputStream.bufferedReader().readText().trim()
        process.waitFor()
        return process.exitValue() == 0 && out == sha
    }

    private fun parseAnnotations(dir: Path, entry: CorpusEntry): List<Annotation> {
        val parsed = AnnotationParser.parseDir(dir, dir)
        val failures = parsed.filterIsInstance<AnnotationParser.Failure>()
        if (failures.isNotEmpty()) {
            throw BenchException(
                "fixture ${entry.slug}: annotation errors:\n" +
                    failures.joinToString("\n") { "  ${it.file}:${it.line}: ${it.error}" },
            )
        }
        return parsed.filterIsInstance<AnnotationParser.Success>().map { it.annotation }
    }

    private fun runSlot(
        entry: CorpusEntry,
        dir: Path,
        annotations: List<Annotation>,
        slot: MatrixSlot,
        commit: String,
    ): FixtureResult {
        val options = slot.options()
        // Wall clock is measured OUTSIDE the report: the report itself must
        // stay byte-identical across runs on the same input.
        val start = System.nanoTime()
        val report = Analyzer.analyze(dir, options, commit, pretty = false)
        val wallMillis = (System.nanoTime() - start) / 1_000_000
        val evaluation = Evaluator.evaluate(report, annotations, mode = slot.label, backend = options.backend.id)
        val failureDetails = (evaluation.fail + evaluation.xpass).map { outcome ->
            val status = if (outcome.status == Evaluator.Status.XPASS) "XPASS" else "FAIL"
            "${outcome.annotation.file}:${outcome.annotation.line}: $status ${outcome.annotation.kind.id} " +
                "(${outcome.detail}) [${outcome.annotation.want} at line ${outcome.annotation.line}]"
        }
        val connectivity = Connectivity.of(report)
        val integrity = Connectivity.integrityViolations(report)
        // Fixture digest: full report serialization is deterministic; reuse it.
        val digest = Digests.FixtureDigest(
            slug = entry.slug,
            slot = slot.label,
            sections = Digests.compute(report.toJson(pretty = false)),
        )
        return FixtureResult(
            slug = entry.slug,
            tier = entry.tier,
            slot = slot.label,
            annotations = annotations.size,
            positives = annotations.count { !it.isNegative },
            negatives = annotations.count { it.isNegative },
            pass = evaluation.pass.size,
            positivesPassed = evaluation.pass.count { it.annotation.want },
            positivesRecallDenominator = evaluation.outcomes.count { it.annotation.want && it.annotation.knownFailFor(options.backend.id) == null },
            fail = evaluation.fail.size,
            xfail = evaluation.xfail.size,
            xpass = evaluation.xpass.size,
            recall = evaluation.recall(options.backend.id),
            connectivity = connectivity,
            integrityViolations = integrity,
            wallMillis = wallMillis,
            parseErrors = report.diagnostics.count { it.code == "parse-error" },
            digest = digest,
            failures = failureDetails,
        )
    }
}

/** Slice connectivity and integrity invariants (03-SCHEMA.md). */
object Connectivity {

    /**
     * Fraction of slices whose edgeIds form a connected path from sourceId to
     * sinkId. With zero slices the value is 1.0 (vacuously true) — reported
     * with that caveat by the promotion gate, never as a flow result.
     */
    fun of(report: io.cdxgen.kosi.schema.KosiReport): Double {
        val dataFlow = report.dataFlow ?: return 1.0
        if (dataFlow.slices.isEmpty()) return 1.0
        val edgesById = dataFlow.edges.associateBy { it.id }
        val connected = dataFlow.slices.count { isConnected(it, edgesById) }
        return connected.toDouble() / dataFlow.slices.size
    }

    fun integrityViolations(report: io.cdxgen.kosi.schema.KosiReport): Int {
        val dataFlow = report.dataFlow ?: return 0
        val edgesById = dataFlow.edges.associateBy { it.id }
        return dataFlow.slices.count { !invariantsHold(it, edgesById) }
    }

    /** sourceId ∈ nodeIds, sinkId ∈ nodeIds, and edgeIds walk source -> sink. */
    fun isConnected(
        slice: io.cdxgen.kosi.schema.FlowSlice,
        edgesById: Map<String, io.cdxgen.kosi.schema.FlowEdge>,
    ): Boolean {
        val nodeIds = slice.nodeIds.toSet()
        if (slice.sourceId !in nodeIds) return false
        if (slice.sinkId !in nodeIds) return false
        if (slice.edgeIds.isEmpty()) return slice.sourceId == slice.sinkId
        var current = slice.sourceId
        for (edgeId in slice.edgeIds) {
            val edge = edgesById[edgeId] ?: return false
            if (edge.sourceId != current) return false
            current = edge.targetId
        }
        return current == slice.sinkId
    }

    /** Full invariant set asserted by `kosi golden` on every slice. */
    fun invariantsHold(
        slice: io.cdxgen.kosi.schema.FlowSlice,
        edgesById: Map<String, io.cdxgen.kosi.schema.FlowEdge>,
    ): Boolean {
        if (!isConnected(slice, edgesById)) return false
        if (slice.ruleId.isBlank()) return false
        if (slice.severity.isBlank()) return false
        if (slice.confidence.isBlank()) return false
        if (slice.riskScore.isBlank()) return false
        if (slice.flowKey.isBlank()) return false
        return true
    }
}
