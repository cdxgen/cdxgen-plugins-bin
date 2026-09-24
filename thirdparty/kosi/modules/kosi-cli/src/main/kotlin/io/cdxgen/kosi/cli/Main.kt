package io.cdxgen.kosi.cli

import io.cdxgen.kosi.bench.Baseline
import io.cdxgen.kosi.bench.BenchRunner
import io.cdxgen.kosi.bench.Digests
import io.cdxgen.kosi.bench.Promotion
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.front.KirDumper
import io.cdxgen.kosi.kir.KirReader
import io.cdxgen.kosi.kir.KirValidator
import io.cdxgen.kosi.kir.KirWriter
import io.cdxgen.kosi.front.StandaloneSessionProbe
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.DataflowMode
import io.cdxgen.kosi.schema.DependencyDetail
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.RootScope
import io.cdxgen.kosi.schema.Severity
import io.cdxgen.kosi.schema.degradations
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists

/**
 * The kosi command line: analyze, bench, golden, version. Exit codes in
 * [ExitCodes]; every option default lives in [AnalyzeOptions], never here.
 */
object Main {

    /**
     * The kosi commit, injected into a resource at build time. There is
     * deliberately no `git rev-parse` fallback: at analysis time the working
     * directory is the *analysed* project, so shelling out to git would stamp
     * the analysed repository's commit onto kosi's own provenance (and run a
     * subprocess the threat model does not allow).
     */
    private val commit: String by lazy {
        try {
            javaClass.getResourceAsStream("/kosi-commit.txt")
                ?.bufferedReader()?.use { it.readText().trim() }
                ?.takeIf { it.isNotEmpty() }
                ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    fun run(args: Array<String>): Int {
        return try {
            when (args.firstOrNull()) {
                null, "help", "--help", "-h" -> {
                    printUsage()
                    ExitCodes.OK
                }
                "analyze" -> analyze(args.drop(1))
                "kir" -> kir(args.drop(1))
                "bench" -> bench(args.drop(1))
                "golden" -> golden(args.drop(1))
                "version", "--version" -> version(args.drop(1))
                else -> {
                    System.err.println("kosi: unknown command '${args[0]}' (try: analyze, kir, bench, golden, version)")
                    ExitCodes.USAGE
                }
            }
        } catch (e: UsageException) {
            System.err.println("kosi: ${e.message}")
            ExitCodes.USAGE
        } catch (e: Analyzer.AnalysisException) {
            System.err.println("kosi: ${e.message}")
            ExitCodes.RUNTIME
        } catch (e: BenchRunner.BenchException) {
            System.err.println("kosi: ${e.message}")
            ExitCodes.RUNTIME
        }
    }

    // ---- analyze ----------------------------------------------------------

    // Flag vocabularies. Every accepted flag is listed here: an unknown flag
    // is a usage error (exit 2), never a silently dropped option.
    private val ANALYZE_VALUE_FLAGS = setOf(
        "dir", "out", "output", "backend", "dataflow", "callgraph", "roots", "root", "dependency-detail",
        "dataflow-max-slices", "dataflow-workers", "dataflow-max-function-instructions",
        "dataflow-max-trace-nodes", "dataflow-max-trace-edges", "access-path-depth",
        "callgraph-timeout", "max-paths-per-symbol", "unknown-call", "language-version",
        "api-version", "jvm-target", "opt-in", "multiplatform-target", "format",
        "classpath", "classpath-file", "classpath-strategy", "jdk-home", "reachable-symbols", "sarif-out",
        "max-analysis-seconds", "max-rss-mb", "deps-max-classes", "max-summary-sink-effects",
    )
    private val ANALYZE_BOOLEAN_FLAGS = setOf(
        "help", "pretty", "include-stdlib", "dataflow-skip-generated", "dataflow-path-widening", "progressive", "endpoint-sources",
        "deps",
    )
    private val BENCH_VALUE_FLAGS = setOf("tier", "only", "repo-root", "baseline", "compare")
    private val BENCH_BOOLEAN_FLAGS =
        setOf("help", "write-baseline", "fail-unless-promotable", "skip-missing-repos", "verbose")
    private val GOLDEN_VALUE_FLAGS = setOf("only", "goldens", "repo-root")
    private val GOLDEN_BOOLEAN_FLAGS = setOf("help", "update-goldens")
    private val VERSION_BOOLEAN_FLAGS = setOf("help", "pretty")

    /** `--output` is the suite alias for `--out`; whichever was given wins. */
    private fun ParsedArgs.outPath(): String? = value("out") ?: value("output")

    private fun analyze(args: List<String>): Int {
        val parsed = ParsedArgs.parse(
            args,
            known = ANALYZE_VALUE_FLAGS + ANALYZE_BOOLEAN_FLAGS,
            booleans = ANALYZE_BOOLEAN_FLAGS,
        )
        if (parsed.bool("help")) {
            printAnalyzeUsage()
            return ExitCodes.OK
        }
        parsed.requireNoPositionals("analyze", "--dir <path>")
        val dir = Path.of(parsed.value("dir", "."))
        if (!dir.exists()) throw UsageException("--dir ${dir} does not exist")
        // Taxonomy: a FILE path analysed "successfully" as an empty
        // tree — no build files, no sources, a clean-looking report about
        // nothing. Kir dump already refuses it; analyze does too now.
        if (!Files.isDirectory(dir)) throw UsageException("--dir ${dir} is not a directory")
        val options = optionsFrom(parsed)
        // A pairing whose OUTPUT would mislead is refused before the
        // run, in the same spirit as `--reachable-symbols` and `--format
        // graphml` below — but derived from `AnalyzeOptions.degradations()`,
        // the one predicate the report's diagnostics also come from, so a
        // refusal and a diagnostic can never describe different sets. The
        // pairings that merely produce LESS (the syntax tier's absent
        // dataflow, which is the DEFAULT invocation) are named on the report
        // and run.
        options.degradations().firstOrNull { it.usageError }?.let {
            throw UsageException(it.message)
        }
        val out = parsed.outPath()
        val report = Analyzer.analyze(dir.toAbsolutePath(), options, commit)
        val reachableSymbols = parsed.value("reachable-symbols")
        when (val format = parsed.value("format", "json")) {
            "json" -> {
                val json = report.toJson(options.pretty)
                if (out != null) {
                    val outPath = Path.of(out)
                    outPath.toAbsolutePath().parent?.let { Files.createDirectories(it) }
                    Files.writeString(outPath, json)
                } else {
                    println(json)
                }
            }

            "graphml", "gexf" -> {
                // The graph exporters need a graph; the syntax tier and
                // --callgraph none produce none, and that is a usage error
                // rather than an empty file a consumer would misread.
                val graph = report.callGraph ?: throw UsageException(
                    "--format $format needs a call graph: run the resolved backend without --callgraph none " +
                        "(the syntax tier builds no graph)",
                )
                val rendered = when (format) {
                    "graphml" -> io.cdxgen.kosi.export.GraphMl.write(graph, dir.fileName.toString())
                    else -> io.cdxgen.kosi.export.Gexf.write(graph, dir.fileName.toString())
                }
                if (out != null) {
                    val outPath = Path.of(out)
                    outPath.toAbsolutePath().parent?.let { Files.createDirectories(it) }
                    Files.writeString(outPath, rendered)
                } else {
                    println(rendered)
                }
            }

            else -> throw UsageException("unknown format '$format' (json, graphml, gexf)")
        }
        // Shortest witness paths for every reached symbol, for consumers that
        // want the walks rather than the whole report.
        if (reachableSymbols != null) {
            val graph = report.callGraph ?: throw UsageException(
                "--reachable-symbols needs a call graph: run the resolved backend without --callgraph none",
            )
            val target = Path.of(reachableSymbols)
            target.toAbsolutePath().parent?.let { Files.createDirectories(it) }
            Files.writeString(target, io.cdxgen.kosi.graph.WitnessPaths.write(graph, options.maxPathsPerSymbol))
        }
        // SARIF export of the data-flow slices, the trace as related
        // locations. A sidecar beside the report, the shape evinse and
        // SARIF consumers read; a run with no dataFlow writes no file.
        parsed.value("sarif-out")?.let { sarifOut ->
            val dataFlow = report.dataFlow ?: throw UsageException(
                "--sarif-out needs data-flow evidence: run with --dataflow security or all " +
                    "(the none mode produces no slices to export)",
            )
            val target = Path.of(sarifOut)
            target.toAbsolutePath().parent?.let { Files.createDirectories(it) }
            Files.writeString(
                target,
                io.cdxgen.kosi.export.Sarif.write(
                    dataFlow,
                    report.tool.name,
                    report.tool.version,
                    report.apiEndpoints,
                ),
            )
        }
        // Error-severity diagnostics mean the analysis is incomplete; surface
        // them without failing the run (they are data, not a crash).
        val errors = report.diagnostics.count { it.severity == Severity.ERROR }
        if (errors > 0 && out != null) {
            System.err.println("kosi: report contains $errors error diagnostic(s) (see diagnostics[] in the report)")
        }
        return ExitCodes.OK
    }

    /** Maps parsed flags onto [AnalyzeOptions]; defaults come only from there. */
    private fun optionsFrom(parsed: ParsedArgs): AnalyzeOptions {
        val defaults = AnalyzeOptions()
        val backend = parsed.value("backend")?.let {
            Backend.fromId(it) ?: throw UsageException("unknown backend '$it' (syntax, resolved, compile)")
        } ?: defaults.backend
        val dataflow = parsed.value("dataflow")?.let {
            DataflowMode.fromId(it) ?: throw UsageException("unknown dataflow mode '$it'")
        } ?: defaults.dataflow
        val callgraph = parsed.value("callgraph")?.let {
            CallGraphMode.fromId(it) ?: throw UsageException("unknown callgraph mode '$it'")
        } ?: defaults.callgraph
        val dependencyDetail = parsed.value("dependency-detail")?.let {
            DependencyDetail.fromId(it) ?: throw UsageException("unknown dependency-detail '$it'")
        } ?: defaults.dependencyDetail
        val roots = parsed.values("roots").ifEmpty { parsed.values("root") }
            .map { value ->
                RootScope.parse(value) ?: throw UsageException("unknown root scope '$value'")
            }
            .map { (scope, arg) -> if (arg != null) "${scope.id}:$arg" else scope.id }
            .ifEmpty { defaults.roots }
        return defaults.copy(
            backend = backend,
            dataflow = dataflow,
            callgraph = callgraph,
            dependencyDetail = dependencyDetail,
            roots = roots,
            dataflowMaxSlices = parsed.value("dataflow-max-slices")?.toIntOrNull() ?: defaults.dataflowMaxSlices,
            dataflowWorkers = parsed.value("dataflow-workers")?.toIntOrNull() ?: defaults.dataflowWorkers,
            dataflowMaxFunctionInstructions = parsed.value("dataflow-max-function-instructions")?.toIntOrNull()
                ?: defaults.dataflowMaxFunctionInstructions,
            dataflowMaxTraceNodes = parsed.value("dataflow-max-trace-nodes")?.toIntOrNull()
                ?: defaults.dataflowMaxTraceNodes,
            dataflowMaxTraceEdges = parsed.value("dataflow-max-trace-edges")?.toIntOrNull()
                ?: defaults.dataflowMaxTraceEdges,
            accessPathDepth = parsed.value("access-path-depth")?.toIntOrNull() ?: defaults.accessPathDepth,
            dataflowSkipGenerated = parsed.bool("dataflow-skip-generated", defaults.dataflowSkipGenerated),
            dataflowPathWidening = parsed.bool("dataflow-path-widening", defaults.dataflowPathWidening),
            callgraphTimeoutSeconds = parsed.value("callgraph-timeout")?.toIntOrNull() ?: defaults.callgraphTimeoutSeconds,
            maxPathsPerSymbol = parsed.value("max-paths-per-symbol")?.toIntOrNull() ?: defaults.maxPathsPerSymbol,
            includeStdlib = parsed.bool("include-stdlib", defaults.includeStdlib),
            endpointSources = parsed.bool("endpoint-sources", defaults.endpointSources),
            deps = parsed.bool("deps", defaults.deps),
            depsMaxClasses = parsed.value("deps-max-classes")?.toIntOrNull() ?: defaults.depsMaxClasses,
            dataflowMaxSummarySinkEffects = parsed.value("max-summary-sink-effects")?.toIntOrNull()
                ?: defaults.dataflowMaxSummarySinkEffects,
            maxAnalysisSeconds = parsed.value("max-analysis-seconds")?.toIntOrNull() ?: defaults.maxAnalysisSeconds,
            maxRssMb = parsed.value("max-rss-mb")?.toIntOrNull() ?: defaults.maxRssMb,
            unknownCall = parsed.value("unknown-call", defaults.unknownCall).let {
                if (it != "propagate" && it != "drop") {
                    throw UsageException("--unknown-call must be propagate|drop")
                }
                it
            },
            languageVersion = parsed.value("language-version") ?: defaults.languageVersion,
            apiVersion = parsed.value("api-version") ?: defaults.apiVersion,
            jvmTarget = parsed.value("jvm-target") ?: defaults.jvmTarget,
            classpath = parsed.values("classpath"),
            classpathFile = parsed.value("classpath-file"),
            classpathStrategy = parsed.value("classpath-strategy")?.let {
                io.cdxgen.kosi.schema.ClasspathStrategy.fromId(it)
                    ?: throw UsageException(
                        "unknown classpath strategy '$it' " +
                            "(auto, explicit, file, jars, cache, none)",
                    )
            } ?: defaults.classpathStrategy,
            jdkHome = parsed.value("jdk-home"),
            progressive = parsed.bool("progressive", defaults.progressive),
            optIn = parsed.values("opt-in"),
            multiplatformTarget = parsed.value("multiplatform-target") ?: defaults.multiplatformTarget,
            pretty = parsed.bool("pretty", defaults.pretty),
            format = parsed.value("format", defaults.format).let {
                if (it != "json" && it != "graphml" && it != "gexf") {
                    throw UsageException("unknown format '$it' (json, graphml, gexf)")
                }
                it
            },
        )
    }

    // ---- kir ----------------------------------------------------------------

    /**
     * `kosi kir dump` (gate): lower the resolved tier to the KIR and dump
     * it. The round-trip is enforced HERE on every dump — dump, re-read,
     * dump again must be byte-identical, or the command fails loudly instead
     * of publishing a format nothing can re-read.
     */
    private fun kir(args: List<String>): Int {
        val sub = args.firstOrNull()
        when (sub) {
            "dump" -> {}
            null, "help", "--help" -> {
                printKirUsage()
                return ExitCodes.OK
            }
            else -> {
                System.err.println("kosi: unknown kir subcommand '$sub' (try: dump)")
                return ExitCodes.USAGE
            }
        }
        val rest = args.drop(1)
        val parsed = ParsedArgs.parse(
            rest,
            known = ANALYZE_VALUE_FLAGS + ANALYZE_BOOLEAN_FLAGS,
            booleans = ANALYZE_BOOLEAN_FLAGS,
        )
        if (parsed.bool("help")) {
            printKirUsage()
            return ExitCodes.OK
        }
        parsed.requireNoPositionals("kir dump", "--dir <path>")
        val dir = parsed.value("dir") ?: throw UsageException("kir dump requires --dir <path>")
        val outPath = parsed.outPath()
        val root = Path.of(dir)
        if (!Files.isDirectory(root)) throw UsageException("--dir $dir does not exist or is not a directory")
        val options = optionsFrom(parsed).copy(backend = Backend.RESOLVED)
        val dump = KirDumper.dump(root.toAbsolutePath(), options)
        // Round-trip enforcement (gate): dump -> read -> dump byte-identical.
        val reRead = KirReader.read(dump)
        val second = KirWriter.write(reRead)
        if (second != dump) {
            // Name the FIRST line that differs: without it the gate says only
            // that something disagreed, and every investigation starts by
            // re-deriving the dump by hand.
            val a = dump.lines()
            val b = second.lines()
            val at = a.indices.firstOrNull { it >= b.size || a[it] != b[it] } ?: b.size
            throw Analyzer.AnalysisException(
                "kir dump round-trip mismatch: the dumper and reader disagree at line ${at + 1}:\n" +
                    "  dumped: ${a.getOrNull(at)?.take(300)}\n  reread: ${b.getOrNull(at)?.take(300)}",
            )
        }
        val findings = KirValidator.validate(reRead)
        if (findings.isNotEmpty()) {
            throw Analyzer.AnalysisException(
                "kir dump validation failed: " +
                    findings.take(10).joinToString("; ") { "${it.function} ${it.block}: ${it.problem}" },
            )
        }
        return when (outPath) {
            null -> {
                println(dump)
                ExitCodes.OK
            }
            else -> {
                Files.writeString(Path.of(outPath), dump)
                ExitCodes.OK
            }
        }
    }

    private fun printKirUsage() {
        println(
            """
            kosi kir dump — lower the resolved tier to the KIR and dump it

              kosi kir dump --dir <path> [--out <file>] [analyze flags]

            Applies the same discovery, classpath resolution and JDK attachment
            as `analyze --backend resolved`, then dumps the lowered module.
            Fails when the dump does not round-trip or the CFG validates dirty.
            """.trimIndent(),
        )
    }

    // ---- bench -------------------------------------------------------------

    private fun bench(args: List<String>): Int {
        val parsed = ParsedArgs.parse(
            args,
            known = BENCH_VALUE_FLAGS + BENCH_BOOLEAN_FLAGS,
            booleans = BENCH_BOOLEAN_FLAGS,
        )
        if (parsed.bool("help")) {
            printBenchUsage()
            return ExitCodes.OK
        }
        parsed.requireNoPositionals("bench", "--repo-root <path>")
        val tiers = parsed.value("tier", "fixtures")!!.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val only = parsed.value("only")
        val repoRoot = Path.of(parsed.value("repo-root", ".")).toAbsolutePath().normalize()
        val result = BenchRunner.run(
            repoRoot,
            BenchRunner.RunOptions(
                tiers = tiers,
                only = only,
                skipMissingRepos = parsed.bool("skip-missing-repos"),
            ),
            commit = commit,
        )
        // `--compare <file>` is the spelling the review protocol uses and
        // `--baseline <file>` the one the help text uses; both name the same
        // file, and a baseline that cannot be read is a runtime error rather
        // than a comparison that silently checks nothing.
        val baselineFile = parsed.value("compare") ?: parsed.value("baseline")
        val writeBaseline = parsed.bool("write-baseline")
        val baseline = baselineFile
            ?.takeUnless { writeBaseline && !Path.of(it).exists() }
            ?.let { file ->
                val path = Path.of(file)
                if (!path.exists()) {
                    throw BenchRunner.BenchException("baseline $file does not exist (write one with --write-baseline)")
                }
                Baseline.load(path)
            }
        if (writeBaseline) {
            val target = Path.of(baselineFile ?: "baseline.json")
            Baseline.save(result, target)
            System.err.println("kosi: baseline written to $target")
        }

        // The ratchet: any FAIL or XPASS fails the build, in both directions.
        val totals = result.totals()
        val regressions = mutableListOf<String>()
        for (res in result.results) {
            if (res.fail > 0) {
                regressions.add("${res.slug}/${res.slot}: ${res.fail} failed expectation(s)")
            }
            if (res.xpass > 0) {
                regressions.add("${res.slug}/${res.slot}: ${res.xpass} known-fail expectation(s) started passing (XPASS)")
            }
        }
        val compareAgainst = baseline
        if (compareAgainst != null) {
            Baseline.compare(result, compareAgainst).forEach { regressions.add(it.render()) }
        }

        val gate = Promotion.evaluate(result, compareAgainst)
        if (parsed.bool("fail-unless-promotable") && !gate.promotable) {
            regressions.add("promotion gate: ${gate.verdict}")
        }

        // In CI the multi-megabyte report goes to a FILE: the bench's JSON
        // has repeatedly coincided with the runner tearing the step down
        // (four runs, always at report time), and a file survives whatever
        // kills the log stream. Local runs print to stdout as before.
        val json = result.toJson()
        val reportDir = System.getenv("KOSI_REPORT_DIR")
        if (!reportDir.isNullOrBlank()) {
            val target = java.nio.file.Path.of(reportDir, "kosi-bench-report.json")
            java.nio.file.Files.writeString(target, json)
            println("kosi bench report: " + target.toAbsolutePath() + " (" + json.length + " chars)")
        } else if (json.length > 262144) {
            for (chunk in json.chunked(262144)) println(chunk)
        } else {
            println(json)
        }
        if (System.getenv("KOSI_TRACE") != null && System.getenv("KOSI_TRACE") != "") {
            System.err.println("TRACE: bench report written (" + json.length + " chars)")
        }
        // Asking for a comparison IS asking for the gate: rendering it only
        // under --verbose meant `bench --compare <baseline>` computed every
        // criterion and showed none of them. It goes to stderr so stdout
        // stays a parseable report.
        if (compareAgainst != null || parsed.bool("verbose")) {
            System.err.println(gate.render())
        }

        return if (regressions.isEmpty()) {
            ExitCodes.OK
        } else {
            System.err.println("kosi bench: ${regressions.size} problem(s):")
            regressions.forEach { System.err.println("  - $it") }
            ExitCodes.EXPECTATIONS_FAILED
        }
    }

    // ---- golden -------------------------------------------------------------

    private fun golden(args: List<String>): Int {
        val parsed = ParsedArgs.parse(
            args,
            known = GOLDEN_VALUE_FLAGS + GOLDEN_BOOLEAN_FLAGS,
            booleans = GOLDEN_BOOLEAN_FLAGS,
        )
        if (parsed.bool("help")) {
            printGoldenUsage()
            return ExitCodes.OK
        }
        parsed.requireNoPositionals("golden", "--repo-root <path>")
        val repoRoot = Path.of(parsed.value("repo-root", ".")).toAbsolutePath().normalize()
        val goldensDir = Path.of(parsed.value("goldens", "goldens"))
        val manifest = io.cdxgen.kosi.corpus.CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        // Every BUNDLED fixture is golden-ratcheted — derived from the
        // manifest's paths, not from a tier list somebody has to remember to
        // extend. This comment made that claim from while the line under
        // it named two tiers of the eleven; `frameworks` and `crypto` were
        // added later and silently fell outside the pin, which left every
        // ktor/spring/micronaut/quarkus/http4k/grpc fixture, every crypto
        // fixture and the bundled vulnerable service unpinned. The
        // exclusions are stated in `GOLDEN_EXCLUDED_TIERS`.
        val entries = manifest.bundled(parsed.value("only"))
        val problems = mutableListOf<String>()
        var checked = 0
        var portabilityChecked = 0
        // The gate proves its own portability instead of trusting a
        // reviewer to try it. Every fixture is analysed from TWO absolute
        // locations in this run — the checkout and a relocated copy under
        // the system temp dir — and any section digest that differs fails
        // the gate. This is the in-gate form of the report contract's
        // "two machines compare equal byte for byte": were
        // both one-environment proofs of cross-environment properties, and
        // the relocated run would have caught on the commit that
        // introduced it. The digests compared here are RAW — the golden
        // pin tolerates option values that name one machine, but a report
        // whose own bytes name their location is not portable whatever the
        // digest would tolerate.
        val portableRoot = Files.createTempDirectory("kosi-golden-portable")
        try {
            for (entry in entries) {
                val dir = repoRoot.resolve(entry.path!!)
                val relocatedDir = portableRoot.resolve(entry.path!!)
                copyTree(dir, relocatedDir)
                if (dir == relocatedDir) {
                    problems.add("${entry.slug}: portability relocation is the same directory as the checkout")
                    continue
                }
                // A pin's jar can live OUTSIDE the entry directory (the async
                // fixtures reach ../shared-libs): it is still an input the
                // analysis reads, so the relocation has to carry it or the
                // relocated run measures a DIFFERENT analysis. Only RELATIVE
                // targets inside the checkout can travel; an absolute pin or
                // one escaping the checkout names one machine and is a
                // portability defect in its own right.
                entry.classpathFile?.let { declared ->
                    for (target in classpathPinTargets(dir.resolve(declared))) {
                        // Targets INSIDE the entry directory are already in
                        // the copy; only the ones reaching out of it need
                        // mirroring.
                        if (!target.startsWith(dir.toAbsolutePath().normalize())) {
                            val rel = repoRoot.relativize(target)
                            if (rel.startsWith("..")) {
                                problems.add("${entry.slug}: classpath pin target does not travel with the checkout: $target")
                            } else {
                                copyTree(target, portableRoot.resolve(rel))
                            }
                        }
                    }
                }
                // The classpath_file a corpus entry declares is part of the
                // INPUT the report contract pins: the bench runner already
                // applies it (BenchRunner.runSlot), but this gate analysed the
                // bare slot options until — every classpath_file fixture
                // was golden-checked against the machine-cache scan instead of
                // its pinned classpath, so its digests were machine-dependent
                // exactly where the pin existed to make them not. A
                // declared file that is missing fails the entry outright: a
                // pin nobody can read is a broken pin.
                val declaredClasspath = entry.classpathFile?.let { dir.resolve(it) }
                if (declaredClasspath != null && !Files.isRegularFile(declaredClasspath)) {
                    problems.add("${entry.slug}: declares classpath_file '${entry.classpathFile}' which is not on disk")
                    continue
                }
                // A deep-tier fixture is golden-pinned in the default
                // slot only - one pair per fixture, the tier's cost rule.
                for (slot in io.cdxgen.kosi.bench.Matrix.slotsFor(entry.tier)) {
                    checked++
                    portabilityChecked++
                    // The ENTRY-RELATIVE value is what the report records: an
                    // absolute path would put this checkout's location into the
                    // `options` digest, so the gate would only ever pass in the
                    // directory the goldens were generated in (a later review).
                    // Both runs get the SAME relative options, and that is
                    // the point: each resolves the pin against its own root,
                    // so neither reads the other's jars. An absolute pin here
                    // would hand the relocated run the checkout's files and
                    // measure nothing.
                    val slotOptions = entry.classpathFile
                        ?.let { slot.options().copy(classpathFile = it) }
                        ?: slot.options()
                    val report = Analyzer.analyze(dir, slotOptions, commit)
                    val relocatedReport = Analyzer.analyze(relocatedDir, slotOptions, commit)
                    Digests.sectionDifferences(
                        io.cdxgen.kosi.bench.Digests.FixtureDigest(
                            slug = entry.slug,
                            slot = slot.label,
                            sections = Digests.compute(report.toJson(pretty = false), normalizeEnvironmentNaming = false),
                        ),
                        io.cdxgen.kosi.bench.Digests.FixtureDigest(
                            slug = entry.slug,
                            slot = slot.label,
                            sections = Digests.compute(relocatedReport.toJson(pretty = false), normalizeEnvironmentNaming = false),
                        ),
                        "at $dir",
                        "at $relocatedDir",
                    ).forEach { problems.add("${entry.slug}/${slot.label}: NOT PORTABLE: $it") }
                    val digest = Digests.FixtureDigest(
                        slug = entry.slug,
                        slot = slot.label,
                        sections = Digests.compute(report.toJson(pretty = false)),
                    )
                    val goldenFile = goldensDir.resolve("${entry.slug}-${slot.label}.json")
                    val existing = Digests.load(goldenFile)
                    if (existing == null || parsed.bool("update-goldens")) {
                        if (existing == null && !parsed.bool("update-goldens")) {
                            problems.add("${entry.slug}/${slot.label}: no golden (run kosi golden --update-goldens)")
                            continue
                        }
                        Digests.save(digest, goldenFile)
                    } else {
                        val diff = Digests.diff(digest, existing)
                        if (diff.isNotEmpty()) {
                            diff.forEach { problems.add("${entry.slug}/${slot.label}: $it") }
                        }
                    }
                }
            }
        } finally {
            portableRoot.toFile().deleteRecursively()
        }
        System.err.println(
            "kosi golden: checked $checked fixture/slot pair(s), $portabilityChecked from two locations, ${problems.size} problem(s)",
        )
        if (problems.isNotEmpty()) {
            problems.forEach { System.err.println("  - $it") }
            return ExitCodes.EXPECTATIONS_FAILED
        }
        return ExitCodes.OK
    }

    /** Recursive copy of a fixture tree, for the golden gate's relocated run. */
    private fun copyTree(from: Path, to: Path) {
        Files.walk(from).use { stream ->
            for (source in stream.sorted()) {
                val target = to.resolve(from.relativize(source).toString())
                if (Files.isDirectory(source)) {
                    Files.createDirectories(target)
                } else {
                    Files.createDirectories(target.parent)
                    // REPLACE_EXISTING: several fixtures pin the same shared
                    // jar, so a target can be mirrored more than once.
                    Files.copy(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            }
        }
    }

    /**
     * The jar files a classpath pin names, resolved the way the resolver
     * resolves them (relative entries against the file's own directory;
     * `g:a:v=path` bound entries the same). Bare `g:a:v` coordinates are
     * absent on purpose: they name the machine-local Gradle cache, which is
     * the environment axis the two-environment proof varies, not a committed
     * input the relocation must carry.
     */
    private fun classpathPinTargets(pinFile: Path): List<Path> {
        if (!Files.isRegularFile(pinFile)) return emptyList()
        val parent = pinFile.toAbsolutePath().normalize().parent ?: return emptyList()
        return pinFile.toFile().readLines().mapNotNull { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@mapNotNull null
            val raw = when {
                trimmed.endsWith(".jar") && trimmed.contains('=') && trimmed.substringBefore('=').split(':').size >= 3 ->
                    trimmed.substringAfter('=')
                trimmed.endsWith(".jar") -> trimmed
                else -> return@mapNotNull null
            }.trim().trim('"', '\'')
            val path = Path.of(raw)
            (if (path.isAbsolute) path else parent.resolve(path)).toAbsolutePath().normalize()
        }
    }

    // ---- version --------------------------------------------------------------

    private fun version(args: List<String>): Int {
        val parsed = ParsedArgs.parse(
            args,
            known = VERSION_BOOLEAN_FLAGS,
            booleans = VERSION_BOOLEAN_FLAGS,
        )
        val syntaxProbe = StandaloneSessionProbe.probeSyntax()
        val probe = StandaloneSessionProbe.probe()
        val w = io.cdxgen.kosi.schema.JsonWriter(pretty = parsed.bool("pretty"))
        w.beginObject()
        w.beginObject("components")
        // Both backends are PROBED, never asserted: since they share one
        // session substrate, so a build where the session cannot be created
        // has no working syntax tier either — and a constant "available"
        // string would report the opposite of the truth.
        w.str("backend-syntax", if (syntaxProbe.available) "available" else syntaxProbe.detail)
        w.str("backend-resolved", if (probe.available) "available" else probe.detail)
        w.str("analysis-api-standalone", if (probe.available) "available" else probe.detail)
        w.endObject()
        w.str("commit", commit)
        w.beginObject("compiler")
        val band = io.cdxgen.kosi.front.CompilerInfo.versionBand()
        w.str("firstSupported", band.first)
        w.str("firstNonDeprecated", band.firstNonDeprecated)
        w.str("latestStable", band.latestStable)
        w.str("version", io.cdxgen.kosi.front.CompilerInfo.compilerVersion())
        w.endObject()
        w.str("description", Analyzer.TOOL_DESCRIPTION)
        w.str("host", Analyzer.hostId())
        w.bool("nativeImage", Analyzer.isNativeImage())
        w.str("schemaVersion", io.cdxgen.kosi.schema.KosiReport.SCHEMA_VERSION)
        w.str("version", Analyzer.TOOL_VERSION)
        w.endObject()
        println(w.render())
        return ExitCodes.OK
    }

    // ---- usage ------------------------------------------------------------------

    private fun printUsage() {
        println(
            """
            kosi — Kotlin Source Inspector (syntax and resolved backends)

            Usage:
              kosi analyze --dir <path> [--out <file>] [options]
              kosi bench   [--tier fixtures,small,...] [--baseline <file>] [--write-baseline]
                           [--compare] [--fail-unless-promotable] [--only <slug>]
              kosi golden  [--update-goldens] [--only <slug>]
              kosi version
              kosi --version

            Exit codes: 0 success; 1 expectations failed; 2 usage error; 3 runtime error.
            """.trimIndent(),
        )
    }

    private fun printAnalyzeUsage() {
        println(
            """
            kosi analyze options (defaults live in AnalyzeOptions, not in the parser):
              --dir <path>                    project root to analyse (default: .)
              --out <file>                    write report to file (default: stdout; --output is an alias)
              --dataflow <mode>               none|security|crypto|reachable|security-deps|all
              --callgraph <mode>              none|static|cha|sealed|rta|vta|auto
              --roots <scope>                 repeatable: main, exported, handlers, tests, android, all, symbol:<regex>
              --dependency-detail <view>      collapse|drop|full
              --language-version <v>          override language version (diagnosed)
              --api-version <v>               override api version (diagnosed)
              --jvm-target <v>                override JVM target (diagnosed)
              --classpath <jar>               repeatable: explicit classpath jar for the resolved backend
              --classpath-file <file>         file of jar paths (one per line, # comments)
              --classpath-strategy <strategy> auto (default: explicit -> file -> jars -> cache), or force
                                              one: explicit (flags only), file (classpath.txt/.classpath
                                              in the analysed tree), jars (libs/ directories), cache
                                              (offline scan of ~/.gradle and ~/.m2), none; the winner is
                                              published in stats.classpath on every run
              --jdk-home <path>               JDK module for the resolved backend (default: running JVM)
              --backend <syntax|resolved|compile>
                                              analysis tier; `compile` is a DECLARED GAP: it runs the
                                              resolved tier and stamps compile-backend-gap on the report
              --include-stdlib                keep stdlib nodes in the graph view (--no-include-stdlib to drop)
              --endpoint-sources              seed handler parameters as taint sources; endpoint-rooted
                                              slices then carry the endpoint they enter through
              --deps                          analyse dependency jars from the resolved classpath: their
                                              bodies lower to the same KIR, summaries carry origin=bytecode,
                                              and cross-dependency slices are added; --dataflow
                                              security-deps implies this
              --deps-max-classes <n>          cap on dependency classes lowered per run (default 500)
              --max-summary-sink-effects <n>  summary escape-set budget; past it a summary is dropped
                                              whole and callers fall to the labelled default
                                              (default 8192); the trips are counted in
                                              stats.truncations as summary-effect-budget
              --max-analysis-seconds <n>      wall-clock budget; tripping emits a named diagnostic and the
                                              partial report still ships (0 trips at the first boundary)
              --max-rss-mb <n>                peak-RSS budget; same degradation contract
              --reachable-symbols <file>      write shortest witness paths for reached symbols (JSON)
              --format <fmt>                  json (full report), graphml or gexf (call graph)
              --pretty                        indented JSON

            Unknown flags are a usage error (exit 2); repeatable flags (--roots, --opt-in)
            accumulate, and a repeated single-value flag takes its last occurrence.
            """.trimIndent(),
        )
    }

    private fun printBenchUsage() {
        println(
            """
            kosi bench options:
              --tier <tiers>                 comma-separated tiers from corpus.toml (default: fixtures)
              --only <slug>                  restrict to one fixture
              --baseline <file>              baseline to compare against
              --compare <file>               same as --baseline (the review-protocol spelling)
              --write-baseline               write the baseline (implies --baseline <file> target)
              --fail-unless-promotable       fail the run unless the promotion gate says PROMOTE
              --skip-missing-repos           warn instead of failing when a pinned repo cannot be fetched
              --repo-root <path>             repository root holding corpus.toml (default: .)
            """.trimIndent(),
        )
    }

    private fun printGoldenUsage() {
        println(
            """
            kosi golden options:
              --update-goldens               write missing/changed goldens
              --only <slug>                  restrict to one fixture
              --goldens <dir>                golden directory (default: goldens)
              --repo-root <path>             repository root holding corpus.toml (default: .)
            """.trimIndent(),
        )
    }
}

/**
 * Entry point (also used by the Gradle bench/corpus tasks).
 *
 * kosi is a headless CLI, but the Analysis API pulls in intellij-core, which
 * initialises AWT. On macOS that registers a real application: the process
 * appears in the Dock and STEALS KEYBOARD FOCUS on startup, which turns a
 * corpus run over 35 fixtures into an unusable machine. The launcher scripts
 * and Gradle JVMs pass these already; setting them here as well covers the
 * paths that have no launcher — `java -jar kosi-all.jar` and the native
 * image. Set before anything can touch the toolkit, and never overriding a
 * value the caller chose.
 */
fun main(args: Array<String>) {
    for ((key, value) in listOf("java.awt.headless" to "true", "apple.awt.UIElement" to "true")) {
        if (System.getProperty(key) == null) System.setProperty(key, value)
    }
    // `java.awt.headless` above is the ONLY property that steers AWT on the
    // pinned toolchain. There used to be a second one here and in
    // AnalysisEnvironment: `awt.toolkit`, pointing at a hand-written no-op
    // Toolkit. JDK 25's `Toolkit.getDefaultToolkit()` never reads that
    // property — it calls `PlatformGraphicsInfo.createToolkit()`, which
    // branches on `isHeadless()` alone — so the no-op toolkit was never
    // once selected on this toolchain, on any platform (measured: with the
    // property set, `getDefaultToolkit()` still returns `LWCToolkit`). It
    // is removed rather than left as a comfort: the real linux fix is the
    // build-time headless bake plus the JNI registrations in the Makefile,
    // and the inert property was what made that fix look unnecessary for
    // eleven phases.
    // An UNCAUGHT exception must never end main: the IntelliJ substrate
    // leaves a NON-daemon pooled thread behind, and a JVM whose main died
    // naturally then waits for it FOREVER (the http4k corpus run hung two
    // hours past a finished analysis, silent, exit never reached). Every
    // failure exits here, with kosi's own message and code.
    val code = try {
        Main.run(args)
    } catch (t: Throwable) {
        System.err.println(
            "kosi: " + (t.message?.take(400)?.ifBlank { null } ?: t::class.simpleName + " (no message)"),
        )
        // a heap-exhaustion death used to print its class name
        // and nothing else. dagger (1,950 files) at -Xmx8g died with
        // `kosi: io/cdxgen/kosi/flow/Summarizer$compute$4` — a
        // NoClassDefFoundError, because a JVM too starved to load one more
        // class reports the class it could not load, not the reason. That
        // reads as a kosi bug, or as a corrupt jar; it is neither, and the
        // one thing that would have fixed it (a bigger heap) was the one
        // thing the message did not mention. the disease, one layer in:
        // a failure whose entire message is a class name.
        memoryAdvice(t)?.let { System.err.println(it) }
        if (System.getenv("KOSI_TRACE") != null) t.printStackTrace()
        io.cdxgen.kosi.cli.ExitCodes.RUNTIME
    }
    kotlin.system.exitProcess(code)
}

/**
 * The advice a memory-shaped death owes the operator.
 *
 * `OutOfMemoryError` says so itself. The one that does not is
 * `NoClassDefFoundError`: a JVM with no room to define one more class fails
 * at whichever class it happened to need, so the message is a class name and
 * the cause is invisible. Dagger (1,950 files) at `-Xmx8g` printed
 * `io/cdxgen/kosi/flow/Summarizer$compute$4` and exited 3; the same run at
 * `-Xmx16g` produces a complete 1,950-file report. Nothing about the first
 * message pointed at the heap.
 *
 * The advice names the heap that was actually in effect, because "raise
 * -Xmx" is useless without knowing what it is now, and reports the machine's
 * physical memory so the suggestion is one the operator can actually take.
 * Returns null for failures that are not memory-shaped — a wrong guess here
 * would send someone tuning the JVM over a real defect.
 */
internal fun memoryAdvice(t: Throwable): String? {
    val chain = generateSequence(t) { it.cause }.take(8).toList()
    // A StackOverflowError is NOT a heap problem, and advising `-Xmx` for one
    // sends the operator to the wrong knob entirely. It is the CALL STACK,
    // and in kosi it means one thing in practice: a source file nested deeper
    // than the recursive walkers can descend. Measured — a single expression
    // of 2,000 `+` terms (one 8 KB file) kills the run at any heap size,
    // while 1,000 terms analyses fine. Generated code, long `when` chains and
    // large Compose trees all reach that shape, so the advice names the
    // source, not the machine.
    if (chain.any { it is StackOverflowError }) {
        return "kosi: this is a CALL STACK overflow, not a heap problem — raising -Xmx will not help.\n" +
            "kosi: kosi walks source syntax recursively and bounds every walk (per-file `psi-depth-cap` " +
            "and `stack-overflow-skipped` diagnostics), so an overflow reaching here came from outside " +
            "those boundaries.\n" +
            "kosi: the analysis already runs on a 512 MB stack; retry with a larger one only if the report " +
            "itself says which file was skipped, e.g. `java -Xss512m -jar kosi-all.jar ...`. " +
            "See docs/KOSI.md, \"How much stack\"."
    }
    val memoryShaped = chain.any { it is OutOfMemoryError || it is NoClassDefFoundError }
    if (!memoryShaped) return null
    val maxHeapBytes = Runtime.getRuntime().maxMemory()
    // Taxonomy: "-Xmx256m" divided to "0 GiB" — an integer floor that
    // misstates the very heap the advice is about. Sub-gigabyte heaps are
    // named in MiB.
    val heap = when {
        maxHeapBytes == Long.MAX_VALUE -> "unbounded"
        maxHeapBytes >= (1L shl 30) -> "${maxHeapBytes / (1L shl 30)} GiB"
        else -> "${maxHeapBytes / (1L shl 20)} MiB"
    }
    val physical = try {
        (java.lang.management.ManagementFactory.getOperatingSystemMXBean()
            as? com.sun.management.OperatingSystemMXBean)
            ?.totalMemorySize?.let { "${it / (1L shl 30)} GiB" }
    } catch (_: Throwable) {
        null
    }
    return buildString {
        append("kosi: this looks like memory exhaustion, not a defect in the analysed code. ")
        append("The heap was $heap")
        physical?.let { append("; this machine has $it physical") }
        append(".\n")
        append("kosi: a NoClassDefFoundError naming a kosi class is what a starved JVM reports — ")
        append("it fails at whatever class it needed next, so the message is never the reason.\n")
        append("kosi: retry with a larger heap, e.g. `java -Xmx16g -jar kosi-all.jar ...`. ")
        append("Repositories of a few thousand source files with a resolved classpath need 16 GiB or more; ")
        append("see docs/KOSI.md, \"How much memory\".")
    }
}
