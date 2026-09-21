package io.cdxgen.kosi.schema

/**
 * Analysis tiers. `syntax` needs no classpath; the
 * others exist so option validation and the report contract are stable before
 * the engines behind them land.
 */
enum class Backend(val id: String) {
    SYNTAX("syntax"),
    RESOLVED("resolved"),
    /**
     * Opt-in (`--backend compile`): a real compilation for generated
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

/**
 * How the resolved tier ACQUIRES its classpath. Every strategy kosi
 * itself runs is READ-ONLY (THREAT_MODEL.md — kosi never executes the
 * analysed build); the build-executing strategies (Gradle dependency
 * reports, `mvn dependency:build-classpath`) belong to the OPERATOR-side
 * acquisition script, which writes the `classpath.txt` the `file` strategy
 * then reads. The ids are the report vocabulary: `stats.classpath.strategy`
 * names exactly one of these (or `none`) on every resolved-tier run.
 */
enum class ClasspathStrategy(val id: String) {
    /** Try the chain in order: explicit -> file -> jars -> cache. */
    AUTO("auto"),
    /** `--classpath` / `--classpath-file` flags only (what cdxgen passes). */
    EXPLICIT("explicit"),
    /** A classpath file already present in the analysed tree: `classpath.txt` (the warmed convention) or an Eclipse `.classpath`. */
    FILE("file"),
    /** A jar directory already present in the analysed tree (`libs/` at the root or a module dir). */
    JARS("jars"),
    /** Offline scan: coordinates parsed as text from build files, located in `~/.gradle/caches/modules-2` / `~/.m2/repository` and project build outputs. */
    CACHE("cache"),
    /** No acquisition at all: the analysis runs classpath-less and says so. */
    NONE("none"),
    ;

    companion object {
        fun fromId(id: String): ClasspathStrategy? = entries.firstOrNull { it.id == id }
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
     * Endpoint handlers' parameters are taint sources (`--endpoint-sources`),
     * so `--dataflow` links slices to the endpoint they enter through. The
     * default is off: without the flag a run's slices start only at pack
     * sources, exactly as before.
     */
    val endpointSources: Boolean = false,
    /**
     * (`--deps`): read dependency jars from the resolved classpath, lower
     * their class files into the SAME KIR, summarise them with the SAME
     * engine (summaries carry `origin=bytecode`), and feed
     * `paramToSink`/`paramToReturn` effects back into the workspace analysis.
     * `--dataflow security-deps` implies this. Off by default: without it the
     * analysis is workspace-only and byte-identical to every earlier run —
     * the invariance the corpus asserts.
     */
    val deps: Boolean = false,
    /**
     * The cap on dependency classes lowered in one run (bounded tier).
     * 500, not larger: the tier's lowered bodies and their summaries share
     * the pinned 2 GiB corpus JVM with the workspace session, and a 2000-class
     * tier on an Android repo OOMed the run (ExitOnOutOfMemoryError fired —
     * loud, but dead). A bounded tier that ships beats an unbounded one that
     * dies; `deps-class-limit` names every truncation.
     */
    val depsMaxClasses: Int = 500,
    /**
     * (`--max-summary-sink-effects`): the summary escape-set budget
     * (the `summary-effect-budget` degradation). The default is 's;
     * the flag exists so the budget's cost is a MEASUREMENT (findings at
     * default, 4x, 64k) rather than an assumption, reproducible from the
     * report's own options section.
     */
    val dataflowMaxSummarySinkEffects: Int = 8192,
    /**
     * (`--max-analysis-seconds`): wall-clock budget. Null or omitted =
     * off. When the budget trips the run DEGRADES — every trip emits a named
     * `analysis-time-budget` diagnostic and the partial report still ships;
     * it never panics and never discards already-computed evidence.
     */
    val maxAnalysisSeconds: Int? = null,
    /**
     * (`--max-rss-mb`): peak-RSS budget, sampled while the analysis runs.
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
    /**
     * (`--classpath-strategy`): force one acquisition strategy, or
     * `auto` for the chain explicit -> file -> jars -> cache. The winner —
     * or `none` — is published in `stats.classpath` on every resolved-tier
     * run; a forced strategy removes the fall-through, so a test (or a
     * user) can measure exactly one mechanism.
     */
    val classpathStrategy: ClasspathStrategy = ClasspathStrategy.AUTO,
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
        w.str("classpathStrategy", classpathStrategy.id)
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

/**
 * One accepted-but-degenerate option pairing — a run that names
 * something it cannot deliver.
 *
 * The whole point is that there is ONE definition. The CLI refuses the
 * [usageError] subset before a run starts; the Analyzer stamps every one of
 * them on the report, because the Analyzer is also a library (the bench, the
 * corpus and evinse call it directly and never see a usage message). Before
 * neither existed: `--dataflow reachable --callgraph none` was accepted,
 * computed no reachability, and published a count claiming every slice was
 * reachable (a later review), and the default pairing — the syntax
 * backend with `--dataflow security` — silently produced no `dataFlow` at
 * all, with the only hint a diagnostic that talks about `resolvedCallRatio`.
 */
data class OptionDegradation(
    /** A registered diagnostic code (`DiagnosticCodes`). */
    val code: String,
    /** Names what was asked for, what is produced instead, and why. */
    val message: String,
    /**
     * True when the CLI refuses this pairing outright rather than running
     * it. Reserved for pairings whose OUTPUT would mislead — the precedent
     * is `--reachable-symbols` and `--format graphml`, both of which refuse
     * a run with no call graph. A pairing that merely produces LESS (the
     * syntax backend's missing dataflow, which is the default invocation)
     * is named, never refused.
     */
    val usageError: Boolean,
)

/**
 * Every accepted pairing in [AnalyzeOptions] that cannot deliver
 * what it names, in a stable order. Empty for a coherent run.
 *
 * `OptionMatrixTest` walks the accepted product of the option enums and
 * asserts each cell against its declared contract, so a pairing cannot be
 * both accepted and unexamined — the state came out of.
 */
fun AnalyzeOptions.degradations(): List<OptionDegradation> {
    val out = mutableListOf<OptionDegradation>()
    val wantsFlow = dataflow != DataflowMode.NONE
    val wantsGraph = callgraph != CallGraphMode.NONE
    // The syntax tier parses without a classpath: no KIR is lowered, so
    // neither engine can run whatever the flags asked for.
    if (backend == Backend.SYNTAX && wantsFlow) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.DATAFLOW_NOT_RUN,
                "--dataflow ${dataflow.id} needs the resolved backend: the syntax tier lowers no IR, " +
                    "so no dataFlow is published and sliceCount is 0 because nothing ran, not because " +
                    "nothing was found",
                usageError = false,
            ),
        )
    }
    if (backend == Backend.SYNTAX && wantsGraph) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.CALLGRAPH_NOT_RUN,
                "--callgraph ${callgraph.id} needs the resolved backend: the syntax tier resolves no " +
                    "calls, so no callGraph is published",
                usageError = false,
            ),
        )
    }
    // The pairing. Reachability is an INTERSECTION with the call graph;
    // with no graph there is nothing to intersect, and a consumer reading
    // `reachable` in `dataFlow.mode` would take the published slices for
    // reachable ones.
    if (dataflow == DataflowMode.REACHABLE && !wantsGraph) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.REACHABLE_WITHOUT_CALLGRAPH,
                "--dataflow reachable intersects the slices with the call graph's reachability and " +
                    "--callgraph none builds no graph: no reachability is computed, every published " +
                    "slice is unfiltered, and stats.reachableSliceCount is 0 meaning NOT MEASURED",
                usageError = true,
            ),
        )
    }
    // The dependency tier costs a jar walk, a lowering and a summarisation,
    // and only the taint engine consumes it.
    if (deps && !wantsFlow) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.DEPS_WITHOUT_DATAFLOW,
                "--deps lowers and summarises dependency classes for the taint engine and " +
                    "--dataflow none runs no taint engine: the tier is built and discarded",
                usageError = false,
            ),
        )
    }
    // A forced classpath strategy that contradicts the explicit
    // flags is refused before the run — the alternative is a run whose
    // report names a strategy the flags silently overrode (or one that
    // ignored them), which is exactly the unattributable state §1 exists
    // to end.
    val hasExplicitClasspath = classpath.isNotEmpty() || classpathFile != null
    if (classpathStrategy == ClasspathStrategy.NONE && hasExplicitClasspath) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.CLASSPATH_STRATEGY_CONFLICT,
                "--classpath-strategy none refuses every classpath acquisition while " +
                    "--classpath/--classpath-file name one: the run would report strategy none " +
                    "against jars the flags supplied",
                usageError = true,
            ),
        )
    }
    if (classpathStrategy != ClasspathStrategy.AUTO && classpathStrategy != ClasspathStrategy.EXPLICIT &&
        hasExplicitClasspath
    ) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.CLASSPATH_STRATEGY_CONFLICT,
                "--classpath-strategy ${classpathStrategy.id} conflicts with --classpath/--classpath-file: " +
                    "explicit flags are the explicit strategy; drop the flags or force explicit/auto",
                usageError = true,
            ),
        )
    }
    if (classpathStrategy == ClasspathStrategy.EXPLICIT && !hasExplicitClasspath) {
        out.add(
            OptionDegradation(
                DiagnosticCodes.CLASSPATH_STRATEGY_CONFLICT,
                "--classpath-strategy explicit names no --classpath/--classpath-file: the run would " +
                    "acquire nothing and report it as the explicit strategy",
                usageError = true,
            ),
        )
    }
    return out
}
