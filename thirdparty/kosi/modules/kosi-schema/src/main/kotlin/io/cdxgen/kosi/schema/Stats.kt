package io.cdxgen.kosi.schema

/**
 * Report stats (03-SCHEMA.md). The full key set is always emitted so consumers
 * can rely on it; phases that do not populate a counter emit zero rather than
 * omitting the key, and the diagnostic log explains why a counter is zero.
 *
 * Deliberate deviation from the v1 sketch, recorded for the PR: the
 * `analysisMillis` and `peakRssBytes` keys are NOT in the report. Embedding a
 * process's own timings inside an artifact whose contract is byte-identical
 * output makes the contract impossible; wall clock and peak RSS are measured
 * by the bench harness (BenchResult), which is a measurement tool, not a
 * deterministic artifact.
 */
data class Stats(
    val fileCount: Int,
    val declarationCount: Int,
    val usageCount: Int,
    val importCount: Int,
    val resolvedCallRatio: Double,
    /**
     * The denominator and numerator of [resolvedCallRatio], published next to
     * it: a ratio of 0.0 over zero calls (a fixture with no call expressions)
     * and a ratio of 0.0 over 400 calls (a resolved tier that resolved
     * nothing) are the same number and opposite facts. An unbroken-down
     * metric is not a result — the same reason `sliceCount` travels with
     * `connectivity`.
     */
    val callsTotal: Int,
    val callsResolved: Int,
    val unknownCallPropagations: Int,
    val loweringFailures: Map<String, Int>,
    /**
     * How many functions the lowering attempted — the denominator the
     * loweringFailures map was computed over. "0 failures" means nothing
     * until the function count says what was lowered; the map and the count
     * travel together (the P2 gate's rule for the lowering rate).
     */
    val functionsLowered: Int,
    val fixpointCapHits: Int,
    /**
     * How many functions the P4 taint engine's worklist actually ran over —
     * the denominator [fixpointCapHits] was measured against, exactly as
     * [functionsLowered] is the denominator of [loweringFailures]. Zero with
     * no flow run (the syntax tier, or `--dataflow none`); a run that
     * analysed something never publishes the cap count without it.
     */
    val functionsAnalysed: Int,
    val sourceCount: Int,
    val sinkCount: Int,
    val sliceCount: Int,
    val crossDependencySliceCount: Int,
    val crossModuleSliceCount: Int = 0,
    val reachableSliceCount: Int,
    /** P5: SCCs the summary fixpoint processed — the cap counter's denominator. */
    val sccsProcessed: Int = 0,
    val sccIterationCapHits: Int = 0,
    /** P6: slices whose source and sink are separated by a suspend boundary. */
    val suspendCrossingSliceCount: Int = 0,
    /**
     * P9, the `--deps` tier: class-file records whose body does not exist —
     * abstract/interface/native methods, stripped or non-`-parameters` classes,
     * methods the bytecode lowering declines. They are IGNORED ENTIRELY, never
     * concluded about: an empty body is indistinguishable from a no-op, so a
     * record summarised as "no flow" would be an invented sanitiser. The count
     * is the population excluded from every dependency-tier denominator.
     */
    val bodylessRecords: Int = 0,
    /** P9: classes actually lowered from dependency jars (the tier's denominator). */
    val dependencyClasses: Int = 0,
    /** P9: dependency methods lowered WITH bodies (the summary count's denominator). */
    val dependencyFunctions: Int = 0,
    val truncations: Map<String, Int>,
    /**
     * P28 (R176): skips BY POLICY (`generated-functions` under
     * `--dataflow-skip-generated`) — deliberate, lossless exclusions whose
     * summaries still apply. Beside [truncations] so the two vocabularies
     * stay separate: a cap that binds is a defect (09-PRECISION §3b), a
     * policy skip is working as intended.
     */
    val policySkips: Map<String, Int> = emptyMap(),
    val degraded: String?,
    /** P28 §1: how the classpath was acquired, and what each strategy found. */
    val classpath: ClasspathStats = ClasspathStats(),
    /** P28 §4 (R179): source files discovered against source files present. */
    val sourceCoverage: SourceCoverage = SourceCoverage(),
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("bodylessRecords", bodylessRecords)
        w.num("dependencyClasses", dependencyClasses)
        w.num("dependencyFunctions", dependencyFunctions)
        w.num("callsResolved", callsResolved)
        w.num("callsTotal", callsTotal)
        w.num("crossDependencySliceCount", crossDependencySliceCount)
        w.num("crossModuleSliceCount", crossModuleSliceCount)
        classpath.writeJson(w, "classpath")
        w.str("degraded", degraded)
        w.num("declarationCount", declarationCount)
        w.num("fileCount", fileCount)
        w.beginObject("loweringFailures")
        for (key in loweringFailures.keys.sorted()) {
            w.num(key, (loweringFailures[key] ?: 0).toLong())
        }
        w.endObject()
        w.num("fixpointCapHits", fixpointCapHits)
        w.num("functionsAnalysed", functionsAnalysed)
        w.num("functionsLowered", functionsLowered)
        w.num("importCount", importCount)
        w.num("reachableSliceCount", reachableSliceCount)
        w.num("sccIterationCapHits", sccIterationCapHits)
        w.num("sccsProcessed", sccsProcessed)
        w.dbl("resolvedCallRatio", resolvedCallRatio)
        w.num("suspendCrossingSliceCount", suspendCrossingSliceCount)
        w.num("sliceCount", sliceCount)
        w.num("sinkCount", sinkCount)
        w.num("sourceCount", sourceCount)
        w.beginObject("truncations")
        for (key in truncations.keys.sorted()) {
            w.num(key, (truncations[key] ?: 0).toLong())
        }
        w.endObject()
        w.beginObject("policySkips")
        for (key in policySkips.keys.sorted()) {
            w.num(key, (policySkips[key] ?: 0).toLong())
        }
        w.endObject()
        w.num("unknownCallPropagations", unknownCallPropagations)
        w.num("usageCount", usageCount)
        sourceCoverage.writeJson(w, "sourceCoverage")
        w.endObject()
    }
}

/**
 * P28 §4 (R179): the coverage denominator. `discovered` is files[]
 * (.kt/.java); `present` counts the same extensions under the analysed root
 * with the collector's own exclusion policy, so the two numbers answer one
 * question. kotlinx.coroutines published 1/1 039 as a CLEAN report before
 * this existed; now the ratio is data and a large gap is a diagnostic, not
 * silence.
 */
data class SourceCoverage(
    val discovered: Int = 0,
    val present: Int = 0,
) {
    /** present == 0 is full coverage of an empty tree, not a division by zero. */
    val ratio: Double get() = if (present <= 0) 1.0 else discovered.toDouble() / present

    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("discovered", discovered.toLong())
        w.num("present", present.toLong())
        w.dbl("ratio", ratio)
        w.endObject()
    }
}

/**
 * P28 §1: the classpath acquisition record. `strategy` names the ONE
 * strategy that produced the attached classpath — or `none` when nothing
 * attached, which is stated EXPLICITLY because a classpath-less run and a
 * run that found nothing produce the same sparse graph and are opposite
 * facts (R173's measured zero, R179's healthy-looking zero). `attempts[]`
 * records every strategy the chain tried and whether it fired, so "cache
 * located 4 of 41 declared coordinates" is readable from the report without
 * re-running anything. `note` is portable vocabulary — no absolute paths,
 * which is what keeps the golden digests location-independent.
 */
data class ClasspathStats(
    /** The winning [ClasspathStrategy] id, or `none`. */
    val strategy: String = "none",
    /** Jars the winner attached (the stdlib kosi itself adds is not counted). */
    val entries: Int = 0,
    /** Coordinates or files a fired strategy named but could not attach. */
    val missing: Int = 0,
    val attempts: List<ClasspathAttempt> = emptyList(),
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("attempts")
        for (attempt in attempts) {
            w.beginObject()
            w.str("strategy", attempt.strategy)
            w.num("jars", attempt.jars.toLong())
            w.str("note", attempt.note)
            w.endObject()
        }
        w.endArray()
        w.num("entries", entries.toLong())
        w.num("missing", missing.toLong())
        w.str("strategy", strategy)
        w.endObject()
    }
}

/** One acquisition attempt: jars > 0 means it fired. */
data class ClasspathAttempt(
    val strategy: String,
    val jars: Int,
    /** What the attempt looked at, in portable vocabulary (no absolute paths). */
    val note: String?,
)
