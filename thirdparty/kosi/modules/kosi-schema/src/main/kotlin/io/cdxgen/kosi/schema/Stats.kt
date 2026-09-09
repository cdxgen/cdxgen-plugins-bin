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
    val fixpointCapHits: Int,
    val sourceCount: Int,
    val sinkCount: Int,
    val sliceCount: Int,
    val crossDependencySliceCount: Int,
    val reachableSliceCount: Int,
    val truncations: Map<String, Int>,
    val degraded: String?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("callsResolved", callsResolved)
        w.num("callsTotal", callsTotal)
        w.num("crossDependencySliceCount", crossDependencySliceCount)
        w.str("degraded", degraded)
        w.num("declarationCount", declarationCount)
        w.num("fileCount", fileCount)
        w.beginObject("loweringFailures")
        for (key in loweringFailures.keys.sorted()) {
            w.num(key, (loweringFailures[key] ?: 0).toLong())
        }
        w.endObject()
        w.num("fixpointCapHits", fixpointCapHits)
        w.num("importCount", importCount)
        w.num("reachableSliceCount", reachableSliceCount)
        w.dbl("resolvedCallRatio", resolvedCallRatio)
        w.num("sliceCount", sliceCount)
        w.num("sinkCount", sinkCount)
        w.num("sourceCount", sourceCount)
        w.beginObject("truncations")
        for (key in truncations.keys.sorted()) {
            w.num(key, (truncations[key] ?: 0).toLong())
        }
        w.endObject()
        w.num("unknownCallPropagations", unknownCallPropagations)
        w.num("usageCount", usageCount)
        w.endObject()
    }
}
