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
                null, "help", "--help" -> {
                    printUsage()
                    ExitCodes.OK
                }
                "analyze" -> analyze(args.drop(1))
                "kir" -> kir(args.drop(1))
                "bench" -> bench(args.drop(1))
                "golden" -> golden(args.drop(1))
                "version" -> version(args.drop(1))
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
        "dir", "out", "backend", "dataflow", "callgraph", "roots", "root", "dependency-detail",
        "dataflow-max-slices", "dataflow-workers", "dataflow-max-function-instructions",
        "dataflow-max-trace-nodes", "dataflow-max-trace-edges", "access-path-depth",
        "callgraph-timeout", "max-paths-per-symbol", "unknown-call", "language-version",
        "api-version", "jvm-target", "opt-in", "multiplatform-target", "format",
        "classpath", "classpath-file", "jdk-home",
    )
    private val ANALYZE_BOOLEAN_FLAGS = setOf(
        "help", "pretty", "include-stdlib", "dataflow-skip-generated", "progressive",
    )
    private val BENCH_VALUE_FLAGS = setOf("tier", "only", "repo-root", "baseline", "compare")
    private val BENCH_BOOLEAN_FLAGS =
        setOf("help", "write-baseline", "fail-unless-promotable", "skip-missing-repos", "verbose")
    private val GOLDEN_VALUE_FLAGS = setOf("only", "goldens", "repo-root")
    private val GOLDEN_BOOLEAN_FLAGS = setOf("help", "update-goldens")
    private val VERSION_BOOLEAN_FLAGS = setOf("help", "pretty")

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
        val dir = Path.of(parsed.value("dir", "."))
        if (!dir.exists()) throw UsageException("--dir ${dir} does not exist")
        val options = optionsFrom(parsed)
        val out = parsed.value("out")
        val report = Analyzer.analyze(dir.toAbsolutePath(), options, commit)
        val json = report.toJson(options.pretty)
        if (out != null) {
            val outPath = Path.of(out)
            outPath.toAbsolutePath().parent?.let { Files.createDirectories(it) }
            Files.writeString(outPath, json)
        } else {
            println(json)
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
            Backend.fromId(it) ?: throw UsageException("unknown backend '$it' (syntax, resolved)")
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
            callgraphTimeoutSeconds = parsed.value("callgraph-timeout")?.toIntOrNull() ?: defaults.callgraphTimeoutSeconds,
            maxPathsPerSymbol = parsed.value("max-paths-per-symbol")?.toIntOrNull() ?: defaults.maxPathsPerSymbol,
            includeStdlib = parsed.bool("include-stdlib", defaults.includeStdlib),
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
            jdkHome = parsed.value("jdk-home"),
            progressive = parsed.bool("progressive", defaults.progressive),
            optIn = parsed.values("opt-in"),
            multiplatformTarget = parsed.value("multiplatform-target") ?: defaults.multiplatformTarget,
            pretty = parsed.bool("pretty", defaults.pretty),
            format = parsed.value("format", defaults.format).let {
                if (it != "json") throw UsageException("only --format json is supported in phase 0")
                it
            },
        )
    }

    // ---- kir ----------------------------------------------------------------

    /**
     * `kosi kir dump` (P2 gate): lower the resolved tier to the KIR and dump
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
        val dir = parsed.value("dir") ?: throw UsageException("kir dump requires --dir <path>")
        val outPath = parsed.value("out")
        val root = Path.of(dir)
        if (!Files.isDirectory(root)) throw UsageException("--dir $dir does not exist or is not a directory")
        val options = optionsFrom(parsed).copy(backend = Backend.RESOLVED)
        val dump = KirDumper.dump(root.toAbsolutePath(), options)
        // Round-trip enforcement (P2 gate): dump -> read -> dump byte-identical.
        val reRead = KirReader.read(dump)
        val second = KirWriter.write(reRead)
        if (second != dump) {
            throw Analyzer.AnalysisException("kir dump round-trip mismatch: the dumper and reader disagree")
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

        println(result.toJson())
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
        val repoRoot = Path.of(parsed.value("repo-root", ".")).toAbsolutePath().normalize()
        val goldensDir = Path.of(parsed.value("goldens", "goldens"))
        val manifest = io.cdxgen.kosi.corpus.CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        val entries = manifest.select(setOf("fixtures"), parsed.value("only"))
        val problems = mutableListOf<String>()
        var checked = 0
        for (entry in entries) {
            val dir = repoRoot.resolve(entry.path!!)
            for (slot in io.cdxgen.kosi.bench.Matrix.defaultMatrix()) {
                checked++
                val report = Analyzer.analyze(dir, slot.options(), commit)
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
        System.err.println("kosi golden: checked $checked fixture/slot pair(s), ${problems.size} problem(s)")
        if (problems.isNotEmpty()) {
            problems.forEach { System.err.println("  - $it") }
            return ExitCodes.EXPECTATIONS_FAILED
        }
        return ExitCodes.OK
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
        // Both backends are PROBED, never asserted: since P1 they share one
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

            Exit codes: 0 success; 1 expectations failed; 2 usage error; 3 runtime error.
            """.trimIndent(),
        )
    }

    private fun printAnalyzeUsage() {
        println(
            """
            kosi analyze options (defaults live in AnalyzeOptions, not in the parser):
              --dir <path>                    project root to analyse (default: .)
              --out <file>                    write report to file (default: stdout)
              --dataflow <mode>               none|security|crypto|reachable|security-deps|all
              --callgraph <mode>              none|static|cha|sealed|rta|vta|auto
              --roots <scope>                 repeatable: main, exported, handlers, tests, android, all, symbol:<regex>
              --dependency-detail <view>      collapse|drop|full
              --language-version <v>          override language version (diagnosed)
              --api-version <v>               override api version (diagnosed)
              --jvm-target <v>                override JVM target (diagnosed)
              --classpath <jar>               repeatable: explicit classpath jar for the resolved backend
              --classpath-file <file>         file of jar paths (one per line, # comments)
              --jdk-home <path>               JDK module for the resolved backend (default: running JVM)
              --backend <syntax|resolved>     analysis tier (resolved needs no build execution)
              --include-stdlib                keep stdlib nodes in the graph view (--no-include-stdlib to drop)
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

/** Entry point (also used by the Gradle bench/corpus tasks). */
fun main(args: Array<String>) {
    kotlin.system.exitProcess(Main.run(args))
}
