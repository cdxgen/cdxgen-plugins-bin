package io.cdxgen.kosi.schema

/**
 * Analysis tiers (02-ARCHITECTURE.md §3). Phase 0 implements `syntax`; the
 * others exist so option validation and the report contract are stable before
 * the engines behind them land.
 */
enum class Backend(val id: String) {
    SYNTAX("syntax"),
    RESOLVED("resolved"),
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
    val languageVersion: String? = null,
    val apiVersion: String? = null,
    val jvmTarget: String? = null,
    val progressive: Boolean = false,
    val optIn: List<String> = emptyList(),
    val multiplatformTarget: String? = null,
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
        w.str("dataflow", dataflow.id)
        w.num("dataflowMaxFunctionInstructions", dataflowMaxFunctionInstructions)
        w.num("dataflowMaxSlices", dataflowMaxSlices)
        w.num("dataflowMaxTraceEdges", dataflowMaxTraceEdges)
        w.num("dataflowMaxTraceNodes", dataflowMaxTraceNodes)
        w.bool("dataflowSkipGenerated", dataflowSkipGenerated)
        w.num("dataflowWorkers", dataflowWorkers)
        w.str("dependencyDetail", dependencyDetail.id)
        w.str("format", format)
        w.str("jvmTarget", jvmTarget)
        w.str("languageVersion", languageVersion)
        w.num("maxPathsPerSymbol", maxPathsPerSymbol)
        w.beginArray("optIn")
        for (value in optIn.sorted()) {
            w.str(value)
        }
        w.endArray()
        w.bool("pretty", pretty)
        w.beginArray("roots")
        for (value in roots.sorted()) {
            w.str(value)
        }
        w.endArray()
        w.str("unknownCall", unknownCall)
        w.endObject()
    }
}
