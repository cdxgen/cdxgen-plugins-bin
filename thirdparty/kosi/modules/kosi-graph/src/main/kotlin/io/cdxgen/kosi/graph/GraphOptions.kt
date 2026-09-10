package io.cdxgen.kosi.graph

import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.DependencyDetail
import io.cdxgen.kosi.schema.RootScope

/**
 * The call-graph run configuration, mapped from [io.cdxgen.kosi.schema.AnalyzeOptions]
 * by the front end (which owns option parsing). Nothing here defaults on its
 * own: the defaults live in AnalyzeOptions, and this type carries exactly
 * what the run declared.
 */
data class GraphOptions(
    val mode: CallGraphMode,
    val roots: List<Pair<RootScope, String?>>,
    val includeStdlib: Boolean,
    val dependencyDetail: DependencyDetail,
    val maxPathsPerSymbol: Int,
    /**
     * The `--callgraph-timeout` value. DELIBERATE DEVIATION from the plan's
     * wall-clock reading (recorded in docs/KOSI.md): the budget is units of
     * deterministic work (worklist pops), `WORK_UNITS_PER_SECOND` per declared
     * second, so a fallback near the boundary cannot make two runs of the same
     * input disagree — byte-identical output is a P3 gate, and a wall-clock
     * trigger would break it precisely on the largest inputs the fallback
     * exists for.
     */
    val timeoutSeconds: Int,
) {
    companion object {
        const val WORK_UNITS_PER_SECOND: Int = 1_000_000

        /** Parses `AnalyzeOptions.roots` (`main`, `symbol:regex`) into scope pairs. */
        fun rootsOf(texts: List<String>): List<Pair<RootScope, String?>> =
            texts.mapNotNull { RootScope.parse(it) }
    }
}
