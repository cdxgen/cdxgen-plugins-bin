package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.CorpusManifest
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DataflowMode
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P24 §4's gate, in test form (rule 9: the measurement moves into the PASS
 * line). Over every DEEP-tier fixture, at the DEFAULT configuration:
 *
 *  1. **No cap binds.** The five caps 09-PRECISION.md §3 names — the
 *     access-path `*` collapse, the trace-node cap (as `pathKind=partial`),
 *     `maxPathsPerSymbol`, the const-fold depth (the depth report's
 *     DEPTH_CAP bucket, zero on this tier), and `deps-class-limit` — are
 *     zero. `generated-functions` is SCOPE, not a cap: the skipped bodies
 *     are the lowering's own synthetics (data-class members, synthesised
 *     primary constructors), which contain no sinks and whose summaries
 *     still apply.
 *  2. **"No limits" is true where it matters**: the same fixtures with every
 *     option-level cap raised to infinity produce BYTE-IDENTICAL reports.
 *     A cap that changes nothing when raised is not binding; one that does
 *     fails here with the section that moved.
 *  3. **The depth numbers are real**: every published slice carries frames,
 *     every frame list is complete (`pathKind != partial`), and the tier's
 *     deepest flow is at least six named hops (the axis 10-DEEP-EVIDENCE
 *     §1 demands).
 */
class DeepTierTest {

    private val repoRoot: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            if (Files.isRegularFile(current.resolve("corpus.toml"))) return@run current
            current = current.parent
        }
        error("corpus.toml not found upward from the working directory")
    }

    private fun deepEntries(): List<io.cdxgen.kosi.corpus.CorpusEntry> {
        val manifest = CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        return manifest.entries.filter { it.tier == "deep" && it.path != null }
    }

    private fun defaultOptions(entry: io.cdxgen.kosi.corpus.CorpusEntry): AnalyzeOptions =
        AnalyzeOptions(
            dataflow = DataflowMode.SECURITY,
            backend = Backend.RESOLVED,
        ).let { opts -> entry.classpathFile?.let { opts.copy(classpathFile = it) } ?: opts }

    /** Every option-level cap, raised past any population the tier can reach. */
    private fun capFreeOptions(entry: io.cdxgen.kosi.corpus.CorpusEntry): AnalyzeOptions =
        defaultOptions(entry).copy(
            accessPathDepth = 64,
            dataflowMaxSlices = Int.MAX_VALUE,
            dataflowMaxTraceNodes = Int.MAX_VALUE,
            dataflowMaxTraceEdges = Int.MAX_VALUE,
            dataflowMaxFunctionInstructions = Int.MAX_VALUE,
            dataflowMaxSummarySinkEffects = Int.MAX_VALUE,
            // Named in the doc-comment above and left at its default by the
            // first version of this leg, which made the comment a claim the
            // code did not check (R117's shape, one level up).
            maxPathsPerSymbol = Int.MAX_VALUE,
            depsMaxClasses = Int.MAX_VALUE,
        )

    @Test
    fun noNamedCapBindsOnTheDeepTierAtDefaults() {
        val binding = mutableListOf<String>()
        for (entry in deepEntries()) {
            val report = Analyzer.analyze(repoRoot.resolve(entry.path!!), defaultOptions(entry), "test")
            val truncations = report.dataFlow?.stats?.truncations.orEmpty()
            for (cap in listOf("access-path-collapse", "slices", "composed-path-depth", "summary-effect-budget", "summary-state-budget")) {
                if ((truncations[cap] ?: 0) > 0) binding.add("${entry.slug}: $cap=${truncations[cap]}")
            }
            val partial = report.dataFlow?.slices.orEmpty().count { it.pathKind == "partial" }
            if (partial > 0) binding.add("${entry.slug}: partial-traces=$partial")
            val fixpointCaps = report.stats.fixpointCapHits + report.stats.sccIterationCapHits
            if (fixpointCaps > 0) binding.add("${entry.slug}: iteration-caps=$fixpointCaps")
        }
        assertTrue(binding.isEmpty(), "caps binding on the deep tier at the default configuration: $binding")
    }

    @Test
    fun raisingEveryCapToInfinityChangesNoByte() {
        for (entry in deepEntries()) {
            val dir = repoRoot.resolve(entry.path!!)
            // The options section NAMES the configuration (that is its job),
            // so both legs are normalised to the same options object before
            // the byte comparison: everything OUTSIDE `options` must be
            // identical, or a cap is binding somewhere the tier cannot
            // afford.
            val defaults = Analyzer.analyze(dir, defaultOptions(entry), "test")
                .let { it.copy(options = defaultOptions(entry)) }.toJson(pretty = false)
            val raised = Analyzer.analyze(dir, capFreeOptions(entry), "test")
                .let { it.copy(options = defaultOptions(entry)) }.toJson(pretty = false)
            assertEquals(defaults, raised, "${entry.slug}: a raised cap changed the report")
        }
    }

    @Test
    fun everySliceCarriesCompleteFramesAndTheTierIsDeep() {
        var deepest = 0
        for (entry in deepEntries()) {
            val report = Analyzer.analyze(repoRoot.resolve(entry.path!!), defaultOptions(entry), "test")
            for (slice in report.dataFlow?.slices.orEmpty()) {
                assertTrue(slice.frames.isNotEmpty(), "${entry.slug}/${slice.id}: a published slice with no named frames")
                assertTrue(slice.frames.first().role == "source" && slice.frames.last().role == "sink",
                    "${entry.slug}/${slice.id}: the frame list does not run source to sink")
                assertEquals(null, slice.framesCutBy, "${entry.slug}/${slice.id}: frames cut by ${slice.framesCutBy}")
                deepest = maxOf(deepest, slice.frames.size)
            }
        }
        assertTrue(deepest >= 6, "the deep tier's deepest named flow is $deepest frames; the axis demands six")
    }
}
