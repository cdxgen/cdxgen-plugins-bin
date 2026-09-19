package io.cdxgen.kosi.schema

/**
 * A source position. `filename` is relative to the analysis root with POSIX
 * separators; `line` and `column` are 1-based.
 */
data class Position(
    val filename: String,
    val line: Int,
    val column: Int,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("filename", filename)
        w.num("line", line)
        w.num("column", column)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<Position> { it.filename }.thenBy { it.line }.thenBy { it.column }
    }
}

/** severity for [Diagnostic]. */
enum class Severity(val id: String) {
    INFO("info"),
    WARNING("warning"),
    ERROR("error"),
    ;

    companion object {
        fun fromId(id: String): Severity? = entries.firstOrNull { it.id == id }
    }
}

/**
 * The closed registry of diagnostic codes, mirroring
 * JSON_ATTRIBUTE_REFERENCE.md §diagnostics. It lives here rather than in the
 * corpus module so there is exactly one list: [Diagnostic] rejects an
 * unregistered code, and a corpus annotation naming an unregistered code is an
 * annotation error instead of a negative expectation that passes vacuously.
 * A phase that emits a new code adds it here and to the reference doc.
 */
object DiagnosticCodes {
    const val PARSE_ERROR = "parse-error"
    const val SYNTAX_BACKEND_NO_RESOLUTION = "syntax-backend-no-resolution"
    const val JAVA_SOURCE_NOT_PARSED = "java-source-not-parsed"
    const val KOTLIN_LANGUAGE_VERSION = "kotlin-language-version"
    const val KOTLIN_VERSION = "kotlin-version"
    const val KOTLIN_API_VERSION = "kotlin-api-version"
    const val VERSION_OVERRIDE = "version-override"
    const val CLASSPATH_PARTIAL = "classpath-partial"
    const val RESOLUTION_ERRORS = "resolution-errors"
    const val SYMBOL_RESOLUTION_FAILED = "symbol-resolution-failed"

    /** A construct the P2 lowering could not perform; the message names it. */
    const val LOWERING_FAILED = "lowering-failed"

    /** P3 call graph: an `auto` mode fell back down the chain (vta -> rta -> sealed). */
    const val CALLGRAPH_TIMEOUT = "callgraph-timeout"

    /** P3 call graph: call sites that resolved to no callee and therefore emit no edge. */
    const val CALLGRAPH_UNRESOLVED_CALLS = "callgraph-unresolved-calls"

    /** P3 call graph: a declared root scope matched no function. */
    const val CALLGRAPH_ROOT_NOT_FOUND = "callgraph-root-not-found"

    /**
     * P4 taint: the worklist over one function's CFG hit its iteration
     * budget before converging. The function's slices are best-effort, the
     * hit is counted in `stats.fixpointCapHits` over
     * `stats.functionsAnalysed`, and a fixed-cap engine that silently loses
     * loop-carried flows is exactly the defect this makes visible.
     */
    const val FIXPOINT_CAP = "fixpoint-cap"

    /**
     * P4 taint: a limit shortened the analysis — a function skipped for
     * exceeding `--dataflow-max-function-instructions`, or the slice cap
     * reached. Every hit is itemised in `stats.truncations`.
     */
    const val DATAFLOW_TRUNCATED = "dataflow-truncated"

    /**
     * P5 summaries: a strongly connected component of the call graph hit
     * its summary iteration budget before its members' summaries converged.
     * The last iterate is what callers applied — labelled
     * `origin=recursive-approx` — and the count is published over the SCC
     * count in `stats.sccIterationCapHits` / `stats.sccsProcessed`.
     */
    const val SUMMARY_ITERATION_CAP = "summary-iteration-cap"

    /**
     * P5 summaries: a virtual call site joined more dispatch-target
     * summaries than the width budget; the JOIN was applied and precision
     * may suffer where the targets disagree. The histogram stays in
     * `dataFlow.stats.dispatchJoins{}`.
     */
    const val DISPATCH_JOIN_WIDTH = "dispatch-join-width"

    /**
     * P5 summaries: a lambda value the engine could not resolve to an
     * extracted body (a callable reference `Foo::bar`, a local function
     * value) — no summary was applied through it. Counted, never silent.
     */
    const val LAMBDA_UNRESOLVED = "lambda-unresolved"

    const val NO_BUILD_FILES = "no-build-files"
    const val NO_SOURCES = "no-sources"
    /**
     * P28 §4 (R179): discovery collected a small share of the source files
     * present under the analysed root. The threshold (half of ≥20 files) is
     * chosen so a dropped-module failure — which typically leaves under
     * 10% (kotlinx.coroutines: 1/1039) — is loud while normal partial
     * collection (a module with generated sources only) is not.
     */
    const val SOURCE_COVERAGE_GAP = "source-coverage-gap"
    const val UNREADABLE_SOURCE = "unreadable-source"

    /**
     * P9 `--deps`: a body-less class-file record (abstract/interface/native,
     * stripped, or declined by the lowering) was counted and EXCLUDED from
     * the dependency tier — never summarised as "no flow".
     */
    const val DEPS_BODYLESS = "deps-bodyless"

    /** P9: a workspace call names a class absent from every classpath jar. */
    const val DEPS_CLASS_NOT_FOUND = "deps-class-not-found"

    /** P9: the dependency-class budget capped the lowered set; the rest is absent. */
    const val DEPS_CLASS_LIMIT = "deps-class-limit"

    /**
     * P9: constructs the bytecode lowering could not translate (itemised by
     * construct in `stats.loweringFailures`'s deps map); a method whose body
     * cannot be fully lowered is treated as BODY-LESS — ignored, never
     * concluded about.
     */
    const val BYTECODE_UNLOWERED = "bytecode-unlowered"

    /**
     * P10: the `--max-analysis-seconds` budget tripped. The run DEGRADED:
     * the named diagnostic ships and the partial report with it — never a
     * panic, never a discarded evidence report.
     */
    const val ANALYSIS_TIME_BUDGET = "analysis-time-budget"

    /** P10: the `--max-rss-mb` budget tripped; same degradation contract. */
    const val RSS_BUDGET = "rss-budget"

    /**
     * P10, golem's guardAlgorithm lesson: the call graph crashed, so the
     * graph section is absent NAMED as such while the already-computed
     * evidence report still ships.
     */
    const val CALLGRAPH_FAILED = "callgraph-failed"

    /** P9: `--backend compile` runs the resolved tier; this names the gap. */
    const val COMPILE_BACKEND_GAP = "compile-backend-gap"

    /**
     * P23 §0: the four codes below name an accepted OPTION PAIRING that
     * cannot deliver what it names. They are produced from one predicate
     * (`AnalyzeOptions.degradations()`), so the CLI's refusals and the
     * report's diagnostics cannot drift apart, and `OptionMatrixTest` walks
     * the accepted product of the option enums to keep every cell examined.
     */
    const val DATAFLOW_NOT_RUN = "dataflow-not-run"

    /** P23 §0: a call graph was asked for on a tier that resolves no calls. */
    const val CALLGRAPH_NOT_RUN = "callgraph-not-run"

    /** P23 §0: R137's pairing — reachability asked for with no graph to intersect. */
    const val REACHABLE_WITHOUT_CALLGRAPH = "reachable-without-callgraph"

    /** P23 §0: the dependency tier built for a run with no taint engine to use it. */
    const val DEPS_WITHOUT_DATAFLOW = "deps-without-dataflow"

    /** P28 §1: a forced `--classpath-strategy` that contradicts the explicit classpath flags. */
    const val CLASSPATH_STRATEGY_CONFLICT = "classpath-strategy-conflict"

    val ALL: Set<String> = setOf(
        PARSE_ERROR,
        SYNTAX_BACKEND_NO_RESOLUTION,
        JAVA_SOURCE_NOT_PARSED,
        KOTLIN_LANGUAGE_VERSION,
        KOTLIN_VERSION,
        KOTLIN_API_VERSION,
        VERSION_OVERRIDE,
        CLASSPATH_PARTIAL,
        RESOLUTION_ERRORS,
        SYMBOL_RESOLUTION_FAILED,
        LOWERING_FAILED,
        CALLGRAPH_TIMEOUT,
        CALLGRAPH_UNRESOLVED_CALLS,
        CALLGRAPH_ROOT_NOT_FOUND,
        FIXPOINT_CAP,
        DATAFLOW_TRUNCATED,
        SUMMARY_ITERATION_CAP,
        DISPATCH_JOIN_WIDTH,
        LAMBDA_UNRESOLVED,
        NO_BUILD_FILES,
        NO_SOURCES,
        SOURCE_COVERAGE_GAP,
        UNREADABLE_SOURCE,
        DEPS_BODYLESS,
        DEPS_CLASS_NOT_FOUND,
        DEPS_CLASS_LIMIT,
        BYTECODE_UNLOWERED,
        ANALYSIS_TIME_BUDGET,
        RSS_BUDGET,
        CALLGRAPH_FAILED,
        COMPILE_BACKEND_GAP,
        DATAFLOW_NOT_RUN,
        CALLGRAPH_NOT_RUN,
        REACHABLE_WITHOUT_CALLGRAPH,
        DEPS_WITHOUT_DATAFLOW,
        CLASSPATH_STRATEGY_CONFLICT,
    )
}

/**
 * Every truncation, cap, fallback and unresolved thing becomes one of these
 * (03-SCHEMA.md rule 5). Codes are machine-readable and stable; see
 * [DiagnosticCodes] and JSON_ATTRIBUTE_REFERENCE.md §diagnostics.
 */
data class Diagnostic(
    val code: String,
    val severity: Severity,
    val message: String,
    val position: Position? = null,
    val count: Int? = null,
) {
    init {
        require(code in DiagnosticCodes.ALL) {
            "unregistered diagnostic code '$code'; add it to DiagnosticCodes and " +
                "JSON_ATTRIBUTE_REFERENCE.md"
        }
    }

    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("code", code)
        w.str("severity", severity.id)
        w.str("message", message)
        position?.writeJson(w, "position")
        if (count != null) w.num("count", count)
        w.endObject()
    }

    companion object {
        val COMPARATOR =
            compareBy<Diagnostic>({ it.code }, { it.severity.id }, { it.message })
                .thenComparing { it.position?.filename ?: "" }
                .thenComparing { it.position?.line ?: 0 }
    }
}
