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
        /**
         * Number of slices connectivity was computed over. Zero means the
         * 1.0 above is vacuous, which is why the count travels with it (an
         * unbroken-down metric is not a result).
         */
        val sliceCount: Int,
        val integrityViolations: Int,
        val wallMillis: Long,
        val parseErrors: Int,
        /**
         * stats.resolvedCallRatio of this slot's report, surfaced so the P1
         * gate reads per-repo ratios directly from the bench result (the
         * gate is per repo, never an average). Null only for legacy
         * baselines written before P1.
         */
        val resolvedCallRatio: Double? = null,
        /**
         * The counts [resolvedCallRatio] was computed from, carried across
         * the bench boundary rather than left behind in the report. The gate
         * reads its ratios from here, so dropping the denominator here makes
         * the GATE unable to tell 0 of 0 calls (a fixture with no call sites)
         * from 0 of 400 (a resolved tier that resolved nothing). Null only
         * for baselines written before P2.
         */
        val callsTotal: Int? = null,
        val callsResolved: Int? = null,
        /**
         * The lowering's failures by construct and the function count they
         * were computed over (03-SCHEMA.md `stats.loweringFailures` /
         * `stats.functionsLowered`), surfaced so the P2 lowering gate reads
         * them from the bench result instead of being measured by hand once
         * and never again. Empty map + null count is a pre-P2 baseline.
         */
        val loweringFailures: Map<String, Int> = emptyMap(),
        val functionsLowered: Int? = null,
        /**
         * P3 call-graph facts, read from the slot's report. Null only for
         * slots that publish no graph (the syntax tiers) or baselines
         * written before P3 — never defaulted to zero, which would read as
         * an empty graph that was actually measured.
         */
        val graphNodes: Int? = null,
        val graphEdges: Int? = null,
        val graphLocalNodes: Int? = null,
        val graphStdlibNodes: Int? = null,
        val graphDependencyNodes: Int? = null,
        val graphSyntheticNodes: Int? = null,
        val graphLocalEdges: Int? = null,
        val graphStdlibEdges: Int? = null,
        val graphDependencyEdges: Int? = null,
        val graphSyntheticEdges: Int? = null,
        val reachedNodes: Int? = null,
        val connectedNodes: Int? = null,
        /**
         * The edge-traversed subset of the above: nodes at distance > 0 and
         * how many of them a walk over the emitted edges confirms. Roots are
         * excluded on purpose — being a root is not evidence about edges.
         */
        val reachedViaEdge: Int? = null,
        val connectedViaEdge: Int? = null,
        val collapsedEdges: Int? = null,
        val publicCallables: Int? = null,
        val reachedPublicCallables: Int? = null,
        val graphAlgorithm: String? = null,
        val digest: Digests.FixtureDigest,
        val failures: List<String> = emptyList(),
    ) {
        fun toJson(w: JsonWriter, key: String? = null) {
            w.beginObject(key)
            w.num("annotations", annotations)
            callsResolved?.let { w.num("callsResolved", it) }
            callsTotal?.let { w.num("callsTotal", it) }
            collapsedEdges?.let { w.num("collapsedEdges", it) }
            w.dbl("connectivity", connectivity)
            connectedNodes?.let { w.num("connectedNodes", it) }
            connectedViaEdge?.let { w.num("connectedViaEdge", it) }
            resolvedCallRatio?.let { w.dbl("resolvedCallRatio", it) }
            w.str("digest", digest.combined)
            w.num("fail", fail)
            functionsLowered?.let { w.num("functionsLowered", it) }
            graphAlgorithm?.let { w.str("graphAlgorithm", it) }
            graphDependencyEdges?.let { w.num("graphDependencyEdges", it) }
            graphDependencyNodes?.let { w.num("graphDependencyNodes", it) }
            graphEdges?.let { w.num("graphEdges", it) }
            graphLocalEdges?.let { w.num("graphLocalEdges", it) }
            graphLocalNodes?.let { w.num("graphLocalNodes", it) }
            graphNodes?.let { w.num("graphNodes", it) }
            graphStdlibEdges?.let { w.num("graphStdlibEdges", it) }
            graphStdlibNodes?.let { w.num("graphStdlibNodes", it) }
            graphSyntheticEdges?.let { w.num("graphSyntheticEdges", it) }
            graphSyntheticNodes?.let { w.num("graphSyntheticNodes", it) }
            w.beginObject("loweringFailures")
            for (construct in loweringFailures.keys.sorted()) {
                w.num(construct, (loweringFailures[construct] ?: 0).toLong())
            }
            w.endObject()
            w.num("integrityViolations", integrityViolations)
            w.num("negatives", negatives)
            w.num("parseErrors", parseErrors)
            w.num("pass", pass)
            w.num("positives", positives)
            w.num("positivesPassed", positivesPassed)
            w.num("positivesRecallDenominator", positivesRecallDenominator)
            publicCallables?.let { w.num("publicCallables", it) }
            reachedNodes?.let { w.num("reachedNodes", it) }
            reachedPublicCallables?.let { w.num("reachedPublicCallables", it) }
            reachedViaEdge?.let { w.num("reachedViaEdge", it) }
            w.dbl("recall", recall)
            w.num("sliceCount", sliceCount)
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
                sliceCount = results.sumOf { it.sliceCount },
                integrityViolations = integrity,
                wallMillis = results.sumOf { it.wallMillis },
                parseErrors = parseErrors,
                // One digest over every fixture digest, so the totals row
                // changes whenever any fixture's report changes. An empty
                // section map here would publish the digest of the empty
                // string, which never changes and means nothing.
                digest = Digests.FixtureDigest(
                    slug = "TOTAL",
                    slot = "all",
                    sections = results.associate { "${it.slug}/${it.slot}" to it.digest.combined },
                ),
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
                        sliceCount = (r.long("sliceCount") ?: 0).toInt(),
                        integrityViolations = (r.long("integrityViolations") ?: 0).toInt(),
                        wallMillis = r.long("wallMillis") ?: 0,
                        parseErrors = (r.long("parseErrors") ?: 0).toInt(),
                        // Every field the gates read must be read back here.
                        // resolvedCallRatio was written but never parsed, so
                        // every baseline loaded from disk carried null and the
                        // per-repo ratio gate's regression and target arms
                        // could not fire at all (see FixtureResultJsonTest,
                        // which round-trips through this parser).
                        resolvedCallRatio = r.dbl("resolvedCallRatio"),
                        callsTotal = r.long("callsTotal")?.toInt(),
                        callsResolved = r.long("callsResolved")?.toInt(),
                        loweringFailures = r.obj("loweringFailures")?.members.orEmpty()
                            .mapValues { (_, v) -> v.asLong().toInt() },
                        functionsLowered = r.long("functionsLowered")?.toInt(),
                        graphNodes = r.long("graphNodes")?.toInt(),
                        graphEdges = r.long("graphEdges")?.toInt(),
                        graphLocalNodes = r.long("graphLocalNodes")?.toInt(),
                        graphStdlibNodes = r.long("graphStdlibNodes")?.toInt(),
                        graphDependencyNodes = r.long("graphDependencyNodes")?.toInt(),
                        graphSyntheticNodes = r.long("graphSyntheticNodes")?.toInt(),
                        graphLocalEdges = r.long("graphLocalEdges")?.toInt(),
                        graphStdlibEdges = r.long("graphStdlibEdges")?.toInt(),
                        graphDependencyEdges = r.long("graphDependencyEdges")?.toInt(),
                        graphSyntheticEdges = r.long("graphSyntheticEdges")?.toInt(),
                        reachedNodes = r.long("reachedNodes")?.toInt(),
                        connectedNodes = r.long("connectedNodes")?.toInt(),
                        reachedViaEdge = r.long("reachedViaEdge")?.toInt(),
                        connectedViaEdge = r.long("connectedViaEdge")?.toInt(),
                        collapsedEdges = r.long("collapsedEdges")?.toInt(),
                        publicCallables = r.long("publicCallables")?.toInt(),
                        reachedPublicCallables = r.long("reachedPublicCallables")?.toInt(),
                        graphAlgorithm = r.str("graphAlgorithm"),
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
            peakRssBytes = PeakRss.bytes(),
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
        val sha = entry.sha
            ?: throw BenchException("fixture ${entry.slug}: repo entries must pin a sha (corpus.toml)")
        val repoUrl = entry.repo
            ?: throw BenchException("fixture ${entry.slug}: neither path nor repo is set (corpus.toml)")
        val cache = repoRoot.resolve(".corpus-cache").resolve(entry.slug)
        if (isCheckedOutAt(cache, sha)) return cache
        if (Files.isDirectory(cache)) {
            if (Files.isDirectory(cache.resolve(".git"))) {
                // Cache present but not at the pinned sha (another tier may
                // have checked out a different one): fetch and hard-checkout
                // rather than failing with a "destination exists" clone error.
                git(cache, entry.slug, "fetch", "--quiet", "--all", "--tags")
                git(cache, entry.slug, "checkout", "--quiet", "--force", sha)
            }
            if (!isCheckedOutAt(cache, sha)) {
                // Not a usable repo (interrupted clone, corrupted cache):
                // start over rather than analyse a stale tree.
                cache.toFile().deleteRecursively()
            }
        }
        if (!isCheckedOutAt(cache, sha)) {
            Files.createDirectories(cache.parent)
            val fetch = ProcessBuilder(
                "git", "clone", "--quiet", repoUrl, cache.toString(),
            ).redirectErrorStream(true).start()
            val output = fetch.inputStream.bufferedReader().readText()
            fetch.waitFor()
            if (fetch.exitValue() != 0) {
                if (skipMissing) return null
                throw BenchException("fixture ${entry.slug}: git clone failed:\n$output")
            }
            git(cache, entry.slug, "checkout", "--quiet", sha)
        }
        if (!isCheckedOutAt(cache, sha)) {
            if (skipMissing) return null
            throw BenchException("fixture ${entry.slug}: could not check out $sha")
        }
        return cache
    }

    private fun git(dir: Path, slug: String, vararg args: String) {
        val process = ProcessBuilder("git", "-C", dir.toString(), *args)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()
        if (process.exitValue() != 0) {
            throw BenchException("fixture $slug: git ${args.first()} failed:\n$output")
        }
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
        // A build-produced classpath file (warm-corpus-classpath.sh) rides
        // the entry; kosi itself never executes the project's build to make
        // one. Absent file -> offline resolution, gaps diagnosed.
        val options = entry.classpathFile
            ?.let { entryDir -> dir.resolve(entryDir) }
            ?.takeIf { Files.isRegularFile(it) }
            ?.let { slot.options().copy(classpathFile = it.toString()) }
            ?: slot.options()
        // Wall clock is measured OUTSIDE the report: the report itself must
        // stay byte-identical across runs on the same input.
        val start = System.nanoTime()
        val report = Analyzer.analyze(dir, options, commit)
        val wallMillis = (System.nanoTime() - start) / 1_000_000
        val evaluation = Evaluator.evaluate(report, annotations, mode = slot.label, backend = options.backend.id)
        val failureDetails = (evaluation.fail + evaluation.xpass).map { outcome ->
            val status = if (outcome.status == Evaluator.Status.XPASS) "XPASS" else "FAIL"
            "${outcome.annotation.file}:${outcome.annotation.line}: $status ${outcome.annotation.kind.id} " +
                "(${outcome.detail}) [${outcome.annotation.want} at line ${outcome.annotation.line}]"
        }
        val connectivity = Connectivity.of(report)
        val integrity = Connectivity.integrityViolations(report)
        val graphMetrics = GraphMetrics.of(report)
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
            sliceCount = report.dataFlow?.slices?.size ?: 0,
            integrityViolations = integrity,
            wallMillis = wallMillis,
            parseErrors = report.diagnostics.count { it.code == "parse-error" },
            resolvedCallRatio = report.stats.resolvedCallRatio,
            callsTotal = report.stats.callsTotal,
            callsResolved = report.stats.callsResolved,
            loweringFailures = report.stats.loweringFailures,
            functionsLowered = report.stats.functionsLowered,
            graphNodes = graphMetrics.nodeCount,
            graphEdges = graphMetrics.edgeCount,
            graphLocalNodes = graphMetrics.localNodes,
            graphStdlibNodes = graphMetrics.stdlibNodes,
            graphDependencyNodes = graphMetrics.dependencyNodes,
            graphSyntheticNodes = graphMetrics.syntheticNodes,
            graphLocalEdges = graphMetrics.localEdges,
            graphStdlibEdges = graphMetrics.stdlibEdges,
            graphDependencyEdges = graphMetrics.dependencyEdges,
            graphSyntheticEdges = graphMetrics.syntheticEdges,
            reachedNodes = graphMetrics.reachedNodes,
            connectedNodes = graphMetrics.connectedNodes,
            reachedViaEdge = graphMetrics.reachedViaEdge,
            connectedViaEdge = graphMetrics.connectedViaEdge,
            collapsedEdges = graphMetrics.collapsedEdges,
            publicCallables = graphMetrics.publicCallables,
            reachedPublicCallables = graphMetrics.reachedPublicCallables,
            graphAlgorithm = graphMetrics.algorithm,
            digest = digest,
            failures = failureDetails,
        )
    }
}

/**
 * Call-graph metrics read from a slot's report (the artifact production
 * publishes — never recomputed from in-memory structures). [connectedNodes]
 * is the numerator of edge connectivity: reached view nodes a breadth-first
 * walk over the EMITTED edges confirms, root nodes (distance 0) included.
 * A view filter that severed a path without re-bridging it shows up here as
 * connectedNodes < reachedNodes, which is exactly what the P3 gate fails on.
 *
 * [reachedViaEdge] is the honest denominator underneath that. A ROOT is
 * reached at distance 0 by definition — no edge is involved — so a gate that
 * divides by [reachedNodes] can read 1.000 having followed no edge at all,
 * which is what the P3 corpus did before `reachable-depth` existed. Only
 * nodes at distance > 0 are reached BECAUSE of an edge, and only those can
 * witness a severance.
 */
data class GraphMetrics(
    val nodeCount: Int?,
    val edgeCount: Int?,
    val localNodes: Int?,
    val stdlibNodes: Int?,
    val dependencyNodes: Int?,
    val syntheticNodes: Int?,
    val localEdges: Int?,
    val stdlibEdges: Int?,
    val dependencyEdges: Int?,
    val syntheticEdges: Int?,
    val reachedNodes: Int?,
    val connectedNodes: Int?,
    val reachedViaEdge: Int?,
    val connectedViaEdge: Int?,
    val collapsedEdges: Int?,
    val publicCallables: Int?,
    val reachedPublicCallables: Int?,
    val algorithm: String?,
) {
    companion object {

        fun of(report: io.cdxgen.kosi.schema.KosiReport): GraphMetrics {
            val graph = report.callGraph ?: return GraphMetrics(
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
            )
            val adjacency = graph.edges.groupBy({ it.sourceId }) { it.targetId }
            val rootIds = graph.reachability.filter { it.distance == 0 }.map { it.nodeId }.toSet()
            val reachedIds = graph.reachability.filter { it.reached }.map { it.nodeId }.toSet()
            val viaEdgeIds = graph.reachability
                .filter { it.reached && it.distance > 0 }
                .map { it.nodeId }
                .toSet()
            val confirmed = GraphConnectivity.connectedCount(rootIds, reachedIds, adjacency)
            val confirmedViaEdge = GraphConnectivity.connectedCount(rootIds, viaEdgeIds, adjacency)
            // The exported-reach denominator comes from `declarations`, NOT
            // from the graph's own node set. Counting public NODES made the
            // gate a tautology: the exported root selector picks exactly the
            // public local nodes, a root is reached at distance 0, so the
            // fraction was 1.0000 by construction on every fixture and every
            // repo. `declarations` is published by the front end independently
            // of graph construction, so a public callable that never became a
            // node — the failure the gate exists to catch — now costs a point.
            val declaredPublic = publicCallableNames(report.declarations)
            val reachedNames = graph.nodes
                .filter { it.id in reachedIds }
                .map { it.canonicalName }
                .toSet()
            return GraphMetrics(
                nodeCount = graph.nodes.size,
                edgeCount = graph.edges.size,
                localNodes = graph.stats.localNodes,
                stdlibNodes = graph.stats.stdlibNodes,
                dependencyNodes = graph.stats.dependencyNodes,
                syntheticNodes = graph.stats.syntheticNodes,
                localEdges = graph.stats.localEdges,
                stdlibEdges = graph.stats.stdlibEdges,
                dependencyEdges = graph.stats.dependencyEdges,
                syntheticEdges = graph.stats.syntheticEdges,
                reachedNodes = reachedIds.size,
                connectedNodes = confirmed,
                reachedViaEdge = viaEdgeIds.size,
                connectedViaEdge = confirmedViaEdge,
                collapsedEdges = graph.edges.count { it.callType == "collapsed" },
                publicCallables = declaredPublic.size,
                reachedPublicCallables = declaredPublic.count { it in reachedNames },
                algorithm = graph.algorithmUsed,
            )
        }

        /** Declaration kinds that are callable, i.e. can be a graph node. */
        private val CALLABLE_KINDS = setOf("function", "method", "extension-function", "constructor")

        /** Declaration kinds that own members and can hide them. */
        private val OWNER_KINDS = setOf(
            "class", "interface", "enum", "annotation", "data-class", "sealed-class", "object", "companion",
        )

        private val API_VISIBILITIES = setOf("public", "protected", "unknown")

        /**
         * Public API callables as `declarations` records them: a callable
         * whose own visibility is consumer-nameable and whose enclosing
         * declaration, if any, is too. Kotlin's default visibility is public,
         * so an absent or `unknown` visibility counts IN — the denominator
         * must never shrink because a fact was missing.
         */
        fun publicCallableNames(declarations: List<io.cdxgen.kosi.schema.Declaration>): Set<String> {
            val ownerVisibility = declarations
                .filter { it.kind in OWNER_KINDS }
                .associate { it.canonicalName to it.visibility }
            return declarations
                .filter { decl ->
                    decl.kind in CALLABLE_KINDS &&
                        decl.visibility in API_VISIBILITIES &&
                        (ownerVisibility[decl.canonicalName.substringBeforeLast('.', "")]
                            ?: "unknown") in API_VISIBILITIES
                }
                .map { it.canonicalName }
                .toSet()
        }
    }
}

/** BFS over the emitted view; the path-existence check behind connectivity. */
object GraphConnectivity {

    fun connectedCount(
        rootIds: Set<String>,
        reachedIds: Set<String>,
        adjacency: Map<String, List<String>>,
    ): Int {
        if (reachedIds.isEmpty()) return 0
        val seen = mutableSetOf<String>()
        val queue = ArrayDeque<String>()
        for (root in rootIds.sorted()) {
            if (seen.add(root)) queue.addLast(root)
        }
        while (queue.isNotEmpty()) {
            for (next in adjacency[queue.removeFirst()].orEmpty()) {
                if (seen.add(next)) queue.addLast(next)
            }
        }
        return reachedIds.count { it in seen }
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
