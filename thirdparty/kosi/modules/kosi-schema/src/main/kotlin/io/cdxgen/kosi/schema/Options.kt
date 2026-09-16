package io.cdxgen.kosi.schema

/**
 * Analysis tiers (02-ARCHITECTURE.md §3). Phase 0 implements `syntax`; the
 * others exist so option validation and the report contract are stable before
 * the engines behind them land.
 */
enum class Backend(val id: String) {
    SYNTAX("syntax"),
    RESOLVED("resolved"),
    /**
     * P9, opt-in (`--backend compile`): a real compilation for generated
     * sources (KSP/Compose/Room). DECLARED GAP: this release cannot execute
     * the analysed build offline, so selecting `compile` runs the resolved
     * tier and stamps a `compile-backend-gap` diagnostic on the report — the
     * gap is named where a consumer will see it, and no report ever claims
     * generated sources were analysed when they were not.
     */
    COMPILE("compile"),
    ;

    companion object {
        fun fromId(id: String): Backend? = entries.firstOrNull { it.id == id }
    }
}

/** `--dataflow` modes. */
enum class DataflowMode(val id: String) {
    NONE("none"),
    SECURITY("security"),
    CRYPTO("crypto"),
    REACHABLE("reachable"),
    SECURITY_DEPS("security-deps"),
    ALL("all"),
    ;

    companion object {
        /** Modes that run taint analysis; used by the corpus mode filter. */
        val FLOW_MODES = entries.filter { it != NONE }

        fun fromId(id: String): DataflowMode? = entries.firstOrNull { it.id == id }
    }
}

/** `--callgraph` modes (02-ARCHITECTURE.md §5). */
enum class CallGraphMode(val id: String) {
    NONE("none"),
    STATIC("static"),
    CHA("cha"),
    SEALED("sealed"),
    RTA("rta"),
    VTA("vta"),
    AUTO("auto"),
    ;

    companion object {
        fun fromId(id: String): CallGraphMode? = entries.firstOrNull { it.id == id }
    }
}

/** `--dependency-detail` view applied after reachability. */
enum class DependencyDetail(val id: String) {
    COLLAPSE("collapse"),
    DROP("drop"),
    FULL("full"),
    ;

    companion object {
        fun fromId(id: String): DependencyDetail? = entries.firstOrNull { it.id == id }
    }
}

/** Root scopes (02-ARCHITECTURE.md §5); `symbol:<regex>` is represented by [Scope.SYMBOL]. */
enum class RootScope(val id: String, val needsValue: Boolean = false) {
    MAIN("main"),
    EXPORTED("exported"),
    HANDLERS("handlers"),
    TESTS("tests"),
    ANDROID("android"),
    ALL("all"),
    SYMBOL("symbol", needsValue = true),
    ;

    companion object {
        /** Parses `main`, `symbol:.*Repo.*`, ... */
        fun parse(text: String): Pair<RootScope, String?>? {
            val idx = text.indexOf(':')
            return if (idx >= 0) {
                val scope = entries.firstOrNull { it.id == text.substring(0, idx) } ?: return null
                scope to text.substring(idx + 1)
            } else {
                entries.firstOrNull { it.id == text && !it.needsValue }?.let { it to null }
            }
        }
    }
}

/**
 * Every effective option, including defaults (03-SCHEMA.md). The defaults on
 * this type ARE the CLI defaults: the bench harness constructs its slots from
 * this object so harness numbers and CLI numbers cannot drift. A test in
 * kosi-bench asserts the equality, and a test in kosi-cli asserts the parser
 * produces exactly this object when no flags are given.
 */
data class AnalyzeOptions(
    val backend: Backend = Backend.SYNTAX,
    val dataflow: DataflowMode = DataflowMode.SECURITY,
    val callgraph: CallGraphMode = CallGraphMode.AUTO,
    val dependencyDetail: DependencyDetail = DependencyDetail.COLLAPSE,
    val roots: List<String> = listOf(RootScope.MAIN.id),
    val dataflowMaxSlices: Int = 1000,
    val dataflowWorkers: Int = 1,
    val dataflowMaxFunctionInstructions: Int = 20000,
    val dataflowMaxTraceNodes: Int = 64,
    val dataflowMaxTraceEdges: Int = 128,
    val accessPathDepth: Int = 5,
    val dataflowSkipGenerated: Boolean = true,
    val callgraphTimeoutSeconds: Int = 60,
    val maxPathsPerSymbol: Int = 3,
    val includeStdlib: Boolean = false,
    val unknownCall: String = "propagate",
    /**
     * P7: endpoint handlers' parameters are taint sources (`--endpoint-sources`),
     * so `--dataflow` links slices to the endpoint they enter through. The
     * default is off: without the flag a run's slices start only at pack
     * sources, exactly as before.
     */
    val endpointSources: Boolean = false,
    /**
     * P9 (`--deps`): read dependency jars from the resolved classpath, lower
     * their class files into the SAME KIR, summarise them with the SAME
     * engine (summaries carry `origin=bytecode`), and feed
     * `paramToSink`/`paramToReturn` effects back into the workspace analysis.
     * `--dataflow security-deps` implies this. Off by default: without it the
     * analysis is workspace-only and byte-identical to every pre-P9 run —
     * the invariance the corpus asserts.
     */
    val deps: Boolean = false,
    /**
     * P9: the cap on dependency classes lowered in one run (bounded tier).
     * 500, not larger: the tier's lowered bodies and their summaries share
     * the pinned 2 GiB corpus JVM with the workspace session, and a 2000-class
     * tier on an Android repo OOMed the run (ExitOnOutOfMemoryError fired —
     * loud, but dead). A bounded tier that ships beats an unbounded one that
     * dies; `deps-class-limit` names every truncation.
     */
    val depsMaxClasses: Int = 500,
    /**
     * P16 §2 (`--max-summary-sink-effects`): the summary escape-set budget
     * (P15's `summary-effect-budget` degradation). The default is P15's;
     * the flag exists so the budget's cost is a MEASUREMENT (findings at
     * default, 4x, 64k) rather than an assumption, reproducible from the
     * report's own options section.
     */
    val dataflowMaxSummarySinkEffects: Int = 8192,
    /**
     * P10 (`--max-analysis-seconds`): wall-clock budget. Null or omitted =
     * off. When the budget trips the run DEGRADES — every trip emits a named
     * `analysis-time-budget` diagnostic and the partial report still ships;
     * it never panics and never discards already-computed evidence.
     */
    val maxAnalysisSeconds: Int? = null,
    /**
     * P10 (`--max-rss-mb`): peak-RSS budget, sampled while the analysis runs.
     * Tripping emits `rss-budget` and ships the partial report, like the time
     * budget. Off (null) by default.
     */
    val maxRssMb: Int? = null,
    val languageVersion: String? = null,
    val apiVersion: String? = null,
    val jvmTarget: String? = null,
    val progressive: Boolean = false,
    val optIn: List<String> = emptyList(),
    val multiplatformTarget: String? = null,
    // Resolved-tier classpath acquisition (02-ARCHITECTURE.md §3, in order:
    // explicit --classpath/--classpath-file first, then offline resolution;
    // --jdk-home names the SDK module, defaulting to the running JDK).
    val classpath: List<String> = emptyList(),
    val classpathFile: String? = null,
    val jdkHome: String? = null,
    val pretty: Boolean = false,
    val format: String = "json",
) {
    /** Serialised into report `options` (sorted, minified, like everything else). */
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("accessPathDepth", accessPathDepth)
        w.str("apiVersion", apiVersion)
        w.str("backend", backend.id)
        w.str("callgraph", callgraph.id)
        w.num("callgraphTimeoutSeconds", callgraphTimeoutSeconds)
        w.beginArray("classpath")
        for (value in classpath.sorted()) w.str(value)
        w.endArray()
        w.bool("endpointSources", endpointSources)
        w.str("classpathFile", classpathFile)
        w.str("dataflow", dataflow.id)
        w.num("dataflowMaxFunctionInstructions", dataflowMaxFunctionInstructions)
        w.num("dataflowMaxSlices", dataflowMaxSlices)
        w.num("dataflowMaxSummarySinkEffects", dataflowMaxSummarySinkEffects)
        w.num("dataflowMaxTraceEdges", dataflowMaxTraceEdges)
        w.num("dataflowMaxTraceNodes", dataflowMaxTraceNodes)
        w.bool("dataflowSkipGenerated", dataflowSkipGenerated)
        w.num("dataflowWorkers", dataflowWorkers)
        w.str("dependencyDetail", dependencyDetail.id)
        w.bool("deps", deps)
        w.num("depsMaxClasses", depsMaxClasses)
        w.str("format", format)
        w.bool("includeStdlib", includeStdlib)
        w.str("jdkHome", jdkHome)
        w.str("jvmTarget", jvmTarget)
        w.str("languageVersion", languageVersion)
        maxAnalysisSeconds?.let { w.num("maxAnalysisSeconds", it) }
        w.num("maxPathsPerSymbol", maxPathsPerSymbol)
        maxRssMb?.let { w.num("maxRssMb", it) }
        w.str("multiplatformTarget", multiplatformTarget)
        w.beginArray("optIn")
        for (value in optIn.sorted()) {
            w.str(value)
        }
        w.endArray()
        w.bool("pretty", pretty)
        w.bool("progressive", progressive)
        w.beginArray("roots")
        for (value in roots.sorted()) {
            w.str(value)
        }
        w.endArray()
        w.str("unknownCall", unknownCall)
        w.endObject()
    }
}
