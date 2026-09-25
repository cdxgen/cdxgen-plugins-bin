package io.cdxgen.kosi.front

import io.cdxgen.kosi.project.ClasspathResolver
import io.cdxgen.kosi.project.DiscoveredModule
import io.cdxgen.kosi.project.ProjectDiscovery
import io.cdxgen.kosi.project.SourceCollector
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.CryptoEvidence
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.AnnotationEvidence
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.Declaration
import io.cdxgen.kosi.schema.FileEvidence
import io.cdxgen.kosi.schema.ImportUsage
import io.cdxgen.kosi.schema.KosiReport
import io.cdxgen.kosi.schema.LanguageVersionRange
import io.cdxgen.kosi.schema.LibraryUsage
import io.cdxgen.kosi.schema.ModuleRef
import io.cdxgen.kosi.schema.PackageEvidence
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.RuntimeInfo
import io.cdxgen.kosi.schema.Severity
import io.cdxgen.kosi.schema.Stats
import io.cdxgen.kosi.schema.ToolInfo
import io.cdxgen.kosi.schema.degradations
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.Path
import java.io.File
import java.util.Locale

/**
 * The analysis pipeline: project discovery (read-only), the chosen backend,
 * and report assembly with deterministic ordering and stable ids. The syntax
 * backend parses PSI without a classpath; the resolved backend runs the
 * standalone Analysis API session over the discovered modules, the
 * offline-resolved classpath and the JDK module. Nothing downstream of
 * kosi-front sees compiler types.
 */
object Analyzer {

    const val TOOL_NAME = "kosi"

    const val TOOL_DESCRIPTION = "kosi — Kotlin Source Inspector (static analysis for cdxgen)"

    /**
     * The cdxgen-plugins-bin release this kosi ships in, injected into a
     * resource at build time from the repository's package.json.
     */
    val TOOL_VERSION: String by lazy {
        try {
            Analyzer::class.java.getResourceAsStream("/kosi-version.txt")
                ?.bufferedReader()?.use { it.readText().trim() }
                ?.takeIf { it.isNotEmpty() && !it.startsWith("\${'$'}") }
                ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    class AnalysisException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

    /**
     * A failure rendered as its CAUSE CHAIN, not just its outermost frame.
     * A wrapper carries no message of its own — `ExceptionInInitializerError`
     * is the one that matters here, because that is how a native image
     * reports a class whose initializer it could not run, and the class it
     * could not initialise is the entire content of the report. Rendering
     * only the wrapper printed "ExceptionInInitializerError: no message",
     * which named nothing and sent the reader to `kosi version`, where the
     * answer was never going to be.
     */
    internal fun describeFailure(t: Throwable, limit: Int = 200): String {
        val parts = mutableListOf<String>()
        var current: Throwable? = t
        val seen = java.util.IdentityHashMap<Throwable, Boolean>()
        while (current != null && seen.put(current, true) == null && parts.size < 4) {
            val name = current::class.qualifiedName ?: current::class.simpleName ?: "error"
            val message = current.message?.take(limit)
            parts.add(if (message.isNullOrBlank()) name else "$name: $message")
            current = current.cause
        }
        return parts.joinToString(" <- ")
    }

    /**
     * The endpoint-detection inputs, captured mid-pipeline: the
     * lowered module, the source texts, the resolved declaration-annotation
     * values and the resolved dependency coordinates. The pack-entry
     * liveness gate re-runs [io.cdxgen.kosi.endpoints.Endpoints.analyze]
     * over one capture per fixture with each pack entry removed, so the
     * question "does any fixture's report change if this entry goes" is
     * answered mechanically instead of by anecdote.
     */
    data class EndpointCapture(
        val module: io.cdxgen.kosi.kir.KirModule,
        val sourceTexts: Map<String, String>,
        val annotationValues: Map<String, List<io.cdxgen.kosi.endpoints.EndpointDetector.DeclAnnotation>>,
        val dependencyCoordinates: Set<String>,
        /** The types the run read with their supertypes, for repository resources. */
        val typeDeclarations: List<io.cdxgen.kosi.endpoints.Endpoints.TypeDeclaration> = emptyList(),
        /** File -> two-segment roots of the packages it imports. */
        val importRootsByFile: Map<String, Set<String>> = emptyMap(),
        /**
         * The endpoint pass's OWN result — including the value
         * folder's fold statistics, the config-resolution counts and the
         * source-handler map — captured so the depth report and the
         * liveness gates can measure the consumers without re-running the
         * front end. Null for runs that disable endpoint detection.
         */
        val endpoints: io.cdxgen.kosi.endpoints.Endpoints.Result? = null,
        /** The value folder's fold counters for this run's consumers. */
        val foldStats: io.cdxgen.kosi.kir.KirValueFolder.FoldStats = io.cdxgen.kosi.kir.KirValueFolder.FoldStats(),
        /**
         * The taint engine's depth scoreboard for this run —
         * sources seeded, sink hits dropped unprovable, cap-affected hits,
         * summary-missing call sites, sanitizers that actually fired. Null
         * when the run asked for no dataflow.
         */
        val flowDepth: io.cdxgen.kosi.flow.TaintEngine.DepthStats? = null,
        /**
         * The flow module's verdicts on "can taint reach this
         * function's return value" — the second answer to the question the
         * const folder answers with its workspace walk. The depth report's
         * agreement gate compares the two; null when no dataflow ran.
         */
        val flowReturnOpinions: io.cdxgen.kosi.flow.TaintEngine.ReturnOpinions? = null,
    )

    fun analyze(root: Path, options: AnalyzeOptions, commit: String): KosiReport =
        analyze(root, options, commit, endpointCapture = null)

    fun analyze(
        root: Path,
        options: AnalyzeOptions,
        commit: String,
        endpointCapture: ((EndpointCapture) -> Unit)?,
    ): KosiReport = runOnAnalysisStack {
        when (options.backend) {
            Backend.SYNTAX -> analyzeSyntax(root, options, commit)
            Backend.RESOLVED, Backend.COMPILE -> analyzeResolved(root, options, commit, endpointCapture)
        }
    }

    // ---- syntax tier ---------------------------------------------------------

    private fun analyzeSyntax(root: Path, options: AnalyzeOptions, commit: String): KosiReport {
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, versionDiagnostics, overrideDiagnostics) =
            discoverVersionPolicy(root, discovery.modules, options)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })
        val syntax = runSyntaxBackend(root, collected)
        val (coverage, coverageDiagnostic) = sourceCoverageOf(root, collected)

        return assemble(
            root = root,
            options = options,
            commit = commit,
            modules = versionedModules,
            buildSystem = discovery.buildSystem,
            collected = collected,
            declarations = syntax.declarations.map { (raw, source) ->
                DeclarationDraft(
                    name = raw.name,
                    qualifiedName = raw.qualifiedName,
                    canonicalName = raw.canonicalName,
                    kind = raw.kind,
                    signature = raw.signature,
                    returnType = raw.returnType,
                    extensionReceiverType = raw.extensionReceiverType,
                    visibility = raw.visibility,
                    modifiers = raw.modifiers,
                    annotations = raw.annotations,
                    overrides = emptyList(),
                    supertypes = emptyList(),
                    jvmOwner = null,
                    jvmDescriptor = null,
                    position = raw.position,
                    source = source,
                    parameterAnnotations = raw.parameterAnnotations,
                )
            },
            usages = syntax.usages,
            imports = syntax.imports,
            diagnostics = versionDiagnostics + overrideDiagnostics + syntax.diagnostics + listOfNotNull(coverageDiagnostic),
            stats = Stats(
                fileCount = syntax.fileCount,
                declarationCount = syntax.declarations.size,
                usageCount = syntax.usages.size,
                importCount = syntax.imports.size,
                resolvedCallRatio = 0.0,
                // The syntax tier counts no calls at all: the zeros say the
                // 0.0 above is by construction, not a resolution failure.
                callsTotal = 0,
                callsResolved = 0,
                unknownCallPropagations = 0,
                loweringFailures = emptyMap(),
                functionsLowered = 0,
                fixpointCapHits = 0,
                functionsAnalysed = 0,
                sourceCount = 0,
                sinkCount = 0,
                sliceCount = 0,
                crossDependencySliceCount = 0,
                reachableSliceCount = 0,
                truncations = emptyMap(),
                degraded = null,
                sourceCoverage = coverage,
            ),
        )
    }

    /**
     * Files discovered against files present, under the
     * collector's own exclusion policy, plus the loud diagnostic when the
     * gap is large. Kotlinx.coroutines analysed 1 of 1 039 files and the
     * report read as clean — `no-sources` could not fire because one file
     * WAS found; the ratio is what makes that shape visible. Threshold:
     * less than half of at least 20 present NON-TEST files — a
     * dropped-module failure leaves under 10% (1/1039), while a normal repo
     * whose modules all have conventional roots sits near 1.0.
     *
     * The denominator excludes test sources because a source ROOT is a main
     * source root: counting `src/test` against discovery makes a repository
     * with a large test suite indistinguishable from one whose modules were
     * dropped. kotlinx.coroutines is the measured case — 651 of its 1 061
     * files are tests, so the raw ratio reads 0.54 where discovery of the
     * files a root could hold is 0.97.
     */
    private fun sourceCoverageOf(
        root: Path,
        collected: List<SourceCollector.CollectedFile>,
    ): Pair<io.cdxgen.kosi.schema.SourceCoverage, Diagnostic?> {
        val (present, testPresent) = SourceCollector.presentCounts(root)
        val coverage = io.cdxgen.kosi.schema.SourceCoverage(
            discovered = collected.size,
            present = present,
            testPresent = testPresent,
        )
        val diagnostic = if (present - testPresent >= 20 && coverage.nonTestRatio < 0.5) {
            Diagnostic(
                code = DiagnosticCodes.SOURCE_COVERAGE_GAP,
                severity = Severity.WARNING,
                message = "source discovery collected ${collected.size} of ${present - testPresent} non-test " +
                    "Kotlin/Java file(s) present under the analysed root " +
                    "(${(coverage.nonTestRatio * 100).toInt()}%; $testPresent further test file(s) are not " +
                    "counted); modules outside the Maven/Gradle source-root convention may be missing from " +
                    "every downstream result",
                position = Position(".", 1, 1),
                count = present - testPresent - collected.size,
            )
        } else {
            null
        }
        return coverage to diagnostic
    }

    private fun runSyntaxBackend(
        root: Path,
        collected: List<SourceCollector.CollectedFile>,
    ): SyntaxRun {
        val imports = mutableListOf<ImportUsage>()
        val declarations = mutableListOf<RawDeclarationHolder>()
        val usages = mutableListOf<LibraryUsage>()
        val diagnostics = mutableListOf<Diagnostic>()
        var fileCount = 0
        var javaFileCount = 0
        // Same treatment as the resolved tier: since both tiers share one
        // session substrate, a substrate that cannot be created must produce
        // kosi's own RUNTIME error naming the cause, not a platform stack
        // trace and exit 1.
        val environment = try {
            AnalysisEnvironment.createForSyntax()
        } catch (t: Throwable) {
            throw AnalysisException(
                "syntax backend: the analysis session could not be created " +
                    "(${describeFailure(t)}); " +
                    "run `kosi version` to see which components are available on this build",
                t,
            )
        }
        environment.use { env ->
            for (source in collected) {
                val text = try {
                    Files.readString(source.absolutePath)
                } catch (e: Exception) {
                    diagnostics.add(
                        Diagnostic(
                            code = DiagnosticCodes.UNREADABLE_SOURCE,
                            severity = Severity.ERROR,
                            message = "could not read ${source.relativePath}: ${e.message ?: "error"}",
                            position = Position(source.relativePath, 1, 1),
                        ),
                    )
                    continue
                }
                if (source.language == FileEvidence.LANGUAGE_JAVA) {
                    // Java sources are evidence in files[] at the syntax tier;
                    // parsing Java PSI is part of the resolved tier. Counted in
                    // a diagnostic below so the gap is measurable rather than
                    // implied by a smaller declarations[].
                    fileCount++
                    javaFileCount++
                    continue
                }
                val analyzer = SyntaxAnalyzer(env, source.relativePath, source.modulePath)
                // The per-file boundary. A pathological file (nesting
                // past the walk budget's headroom, or a shape the parser
                // itself descends on) must degrade to a diagnostic NAMING
                // the file, never take the whole report down — the
                // no-sources/coverage lesson: a partial answer that says so
                // beats no answer. AnalysisException here is parseFile's
                // plain-text misclassification, never a downstream failure.
                val result = try {
                    analyzer.analyze(text)
                } catch (e: StackOverflowError) {
                    diagnostics.add(
                        Diagnostic(
                            code = DiagnosticCodes.STACK_OVERFLOW_SKIPPED,
                            severity = Severity.ERROR,
                            message = "analysing ${source.relativePath} exhausted the stack and the file was " +
                                "skipped; every other file was analysed. The analysis runs on a " +
                                "${WalkBudgets.ANALYSIS_STACK_BYTES / (1L shl 20)} MB stack, so a file that " +
                                "still overflows it is far past the ${WalkBudgets.PSI_DEPTH_CAP}-level walk budget",
                            position = Position(source.relativePath, 1, 1),
                            count = 1,
                        ),
                    )
                    fileCount++
                    continue
                } catch (e: Analyzer.AnalysisException) {
                    diagnostics.add(
                        Diagnostic(
                            code = DiagnosticCodes.UNREADABLE_SOURCE,
                            severity = Severity.ERROR,
                            message = "${source.relativePath}: ${e.message}",
                            position = Position(source.relativePath, 1, 1),
                            count = 1,
                        ),
                    )
                    fileCount++
                    continue
                }
                fileCount++
                imports.addAll(result.imports)
                diagnostics.addAll(result.diagnostics)
                for (raw in result.declarations) {
                    declarations.add(RawDeclarationHolder(raw, source))
                }
                for (raw in result.usages) {
                    usages.add(
                        LibraryUsage(
                            id = "",
                            name = raw.name,
                            simpleName = raw.name.substringAfterLast('.').substringAfterLast("::"),
                            usageKind = raw.usageKind,
                            modulePath = source.modulePath,
                            purl = source.modulePurl,
                            filePath = source.relativePath,
                            position = raw.position,
                        ),
                    )
                }
            }
        }
        if (javaFileCount > 0) {
            diagnostics.add(
                Diagnostic(
                    code = DiagnosticCodes.JAVA_SOURCE_NOT_PARSED,
                    severity = Severity.WARNING,
                    message = "$javaFileCount Java source file(s) are listed in files[] but not parsed at the " +
                        "syntax tier; their declarations and usages are absent from this report",
                    count = javaFileCount,
                ),
            )
        }
        diagnostics.add(
            Diagnostic(
                code = DiagnosticCodes.SYNTAX_BACKEND_NO_RESOLUTION,
                severity = Severity.INFO,
                message = "syntax backend parses without a classpath; no symbol resolution is " +
                    "performed and resolvedCallRatio is 0.0 by construction",
                count = 1,
            ),
        )
        return SyntaxRun(imports, declarations, usages, diagnostics, fileCount)
    }

    data class RawDeclarationHolder(
        val raw: SyntaxAnalyzer.RawDeclaration,
        val source: SourceCollector.CollectedFile,
    )

    private data class SyntaxRun(
        val imports: List<ImportUsage>,
        val declarations: List<RawDeclarationHolder>,
        val usages: List<LibraryUsage>,
        val diagnostics: List<Diagnostic>,
        val fileCount: Int,
    )

    // ---- resolved tier -------------------------------------------------

    private fun analyzeResolved(root: Path, options: AnalyzeOptions, commit: String, endpointCapture: ((EndpointCapture) -> Unit)? = null): KosiReport {
        // The budgets (time, RSS) live across the whole resolved run and
        // degrade it — never panic, never discard computed evidence. Off by
        // default; when both budgets are unset no sampler thread exists and
        // shouldStop() is a constant null.
        val budgets = Budgets.of(options)
        try {
            return analyzeResolvedInner(root, options, commit, budgets, endpointCapture)
        } finally {
            budgets.close()
        }
    }

    private fun analyzeResolvedInner(
        root: Path,
        options: AnalyzeOptions,
        commit: String,
        budgets: Budgets,
        endpointCapture: ((EndpointCapture) -> Unit)? = null,
    ): KosiReport {
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, versionDiagnostics, overrideDiagnostics) =
            discoverVersionPolicy(root, discovery.modules, options)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })
        val (sourceCoverage, coverageDiagnostic) = sourceCoverageOf(root, collected)

        // Classpath acquisition (02-ARCHITECTURE.md §3): explicit flags first,
        // then offline resolution from the local caches. Every coordinate the
        // resolver cannot find becomes a `classpath-partial` diagnostic naming
        // it — a partial classpath is never silent (07-REVIEW-PROTOCOL.md #9).
        val moduleDirs = versionedModules.map { vm ->
            root.resolve(vm.module.modulePath).toAbsolutePath().normalize()
        }
        // A named classpath file that does not exist is an error, not a
        // silently empty classpath: a later review `--compare` defect was
        // exactly this shape — a flag the run echoed but never applied.
        // A RELATIVE --classpath-file resolves against the analysed directory,
        // not the process's working directory. The recorded option is part of
        // the report, and an absolute path records the checkout's LOCATION —
        // which is not an analysis input, and which made the golden gate's
        // `options` digest differ between two machines analysing the same tree
        // (a later review). Absolute paths are unchanged: resolve() returns them
        // as given.
        val classpathFile = options.classpathFile?.let { root.resolve(it) }
        classpathFile?.let { file ->
            if (!Files.isRegularFile(file)) {
                throw AnalysisException(
                    "--classpath-file ${options.classpathFile} does not exist or is not a regular file",
                )
            }
        }
        val resolution = ClasspathResolver.resolve(
            root = root,
            explicitJars = options.classpath.map { Path.of(it) },
            explicitFile = classpathFile,
            moduleDirs = moduleDirs,
            strategy = options.classpathStrategy,
        )
        // The acquisition record — which strategy produced the
        // classpath, how many entries it attached, and what each tried
        // strategy found — is REPORT DATA, not a log line: a classpath-less
        // run and a run that found nothing publish the same sparse graph,
        // and `strategy: none` with the attempts is what tells them apart.
        val classpathStats = io.cdxgen.kosi.schema.ClasspathStats(
            strategy = resolution.strategy,
            entries = resolution.jars.size,
            missing = resolution.missing.size,
            attempts = resolution.attempts.map {
                io.cdxgen.kosi.schema.ClasspathAttempt(it.strategy, it.jars, it.note)
            },
        )
        val classpathDiagnostics = buildList {
            if (resolution.missing.isNotEmpty()) {
                add(
                    Diagnostic(
                        code = DiagnosticCodes.CLASSPATH_PARTIAL,
                        severity = Severity.WARNING,
                        message = "offline resolution could not locate ${resolution.missing.size} " +
                            "coordinate(s): ${resolution.missing.joinToString(", ")}; " +
                            "calls into them resolve as unresolved",
                        position = Position(".", 1, 1),
                        count = resolution.missing.size,
                    ),
                )
            }
        }

        // The JDK module: explicit --jdk-home, else the running JVM's home,
        // else JAVA_HOME (which is how an image finds one, java.home being
        // unset there). A home that names no modular JDK is a usage error —
        // a flag that cannot work is rejected with the reason, never
        // silently downgraded to a partial classpath. When no source names a
        // JDK at all the run continues with the gap diagnosed below.
        val jdkResolution = JdkModules.resolve(options.jdkHome?.let { Path.of(it) })
        val jdkHome = when (val resolution = jdkResolution) {
            is JdkModules.Resolution.Found -> resolution.home
            is JdkModules.Resolution.Invalid -> throw AnalysisException(resolution.message)
            is JdkModules.Resolution.NotFound -> null
        }
        val jdkDiagnostic = if (jdkHome == null) {
            Diagnostic(
                code = DiagnosticCodes.CLASSPATH_PARTIAL,
                severity = Severity.WARNING,
                message = (jdkResolution as JdkModules.Resolution.NotFound).tried +
                    "; java.* symbols resolve as unresolved",
                position = Position(".", 1, 1),
                count = 1,
            )
        } else {
            null
        }

        // The workspace's own kotlin-stdlib rides the classpath so stdlib
        // symbols resolve for projects that do not declare it explicitly.
        val stdlibJar = stdlibJar
        val packageIndex = ClasspathResolver.packageIndex(resolution.jars)

        // The offline resolver is project-global; the merged workspace module
        // sees the whole resolved classpath, plus the bundled stdlib so
        // implicit stdlib references resolve.
        val libraries = resolution.jars.map { ResolvedPlan.ResolvedLibrary(it.jar, it.purl) } +
            listOfNotNull(stdlibJar?.let { ResolvedPlan.ResolvedLibrary(it, STDLIB_PURL) })
        // The workspace module analyses at the highest effective version among
        // the discovered modules (each module's own effective version is still
        // published in modules[] and clamped there).
        val effectiveVersion = versionedModules.maxOfOrNull { CompilerInfo.bandRank(it.effective) }
        val effectiveApi = versionedModules
            .mapNotNull { vm -> vm.module.declaredApiVersion?.let { effectiveApiVersion(it, vm.effective) } }
            .maxOrNull()
        val plan = ResolvedPlan(
            sourceFiles = collected.map { it.absolutePath },
            languageVersion = effectiveVersion?.let { CompilerInfo.versionAtRank(it) },
            apiVersion = effectiveApi,
            libraries = libraries,
            jdkHome = jdkHome?.takeIf { Files.isDirectory(it) },
        )

        val fileRelPathByAbsolute = collected.associate {
            it.absolutePath.toAbsolutePath().normalize().toString() to
                (it.relativePath to it.modulePath)
        }

        // Session construction can fail with a Throwable rather than an
        // Exception (the platform reports extension-registration problems
        // through an assertion). Turned into kosi's own error so the CLI
        // exits with RUNTIME and a message that names the cause, instead of
        // printing a platform stack trace and exiting 1.
        val env = try {
            AnalysisEnvironment.createForResolved(plan)
        } catch (t: Throwable) {
            throw AnalysisException(
                "resolved backend: the analysis session could not be created " +
                    "(${describeFailure(t)}); " +
                    "run `kosi version` to see which components are available on this build",
                t,
            )
        }
        // (arrow): this used to be `env.use { ... }`. The `use` epilogue
        // runs `AutoCloseable.closeFinally`, and on a run whose session
        // classpath carried kotlin-stdlib-jdk7 (arrow's own resolution) the
        // close itself failed with NoClassDefFoundError: kotlin/ExceptionsKt
        // — which REPLACED the real exception and reported six characters of
        // a class name. An explicit guarded close means the analysis's own
        // failure (or success) is what the caller sees; a close failure is
        // recorded and can never mask it.
        try {
            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: session built, modules=" + env.session.modulesWithFiles.size)
            val workspace = env.session.modulesWithFiles.keys
                .filterIsInstance<org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule>()
                .firstOrNull() ?: throw AnalysisException("resolved backend: session built no workspace module")

            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: running resolved analyzer")
            val facts = ResolvedAnalyzer.run(env, workspace, fileRelPathByAbsolute)
            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: facts=" + facts.size)

            // Lower the same session to the KIR. The failures map is the
            // itemised breakdown; the function count is what it was computed
            // over — neither travels without the other.
            val kir = KirLowering.lower(env, workspace)
            val kirDiagnostic = if (kir.failures.isNotEmpty()) {
                val breakdown = kir.failures.entries.sortedWith(compareBy({ it.key }, { it.value })).joinToString(", ") { "${it.key}=${it.value}" }
                Diagnostic(
                    code = DiagnosticCodes.LOWERING_FAILED,
                    severity = Severity.WARNING,
                    message = "lowering could not perform $breakdown " +
                        "(${kir.failures.values.sum()} of ${kir.functionCount} functions)",
                    position = Position(".", 1, 1),
                    count = kir.failures.values.sum(),
                )
            } else {
                null
            }
            // Files whose lowering was skipped whole (walk budget or
            // stack overflow), each named, with the relative path the report
            // contract requires.
            val kirSkippedDiagnostics = kir.skippedFiles.map { skip ->
                val rel = fileRelPathByAbsolute[skip.file]?.first ?: skip.file
                if (skip.reason == "psi-depth") {
                    Diagnostic(
                        code = DiagnosticCodes.PSI_DEPTH_CAP,
                        severity = Severity.WARNING,
                        message = "$rel nests ${skip.depth} syntax level(s), past the " +
                            "${WalkBudgets.PSI_DEPTH_CAP}-level walk budget; its functions were not lowered " +
                            "and their bodies are absent from the graph and the dataflow engine",
                        position = Position(rel, 1, 1),
                        count = 1,
                    )
                } else {
                    Diagnostic(
                        code = DiagnosticCodes.STACK_OVERFLOW_SKIPPED,
                        severity = Severity.ERROR,
                        message = "lowering $rel exhausted the stack; the file's functions are absent from the " +
                            "KIR and every downstream result, while the rest of the run completed",
                        position = Position(rel, 1, 1),
                        count = 1,
                    )
                }
            }
            // Dispatch facts (visibility/modality/overrides/supertypes) that
            // could not be read join the resolution-failure count: the graph
            // treats them as open and non-exported, and the report says why.
            val kirSymbolFailures = kir.symbolFactFailures


            val imports = mutableListOf<ImportUsage>()
            val usages = mutableListOf<LibraryUsage>()
            val diagnostics = mutableListOf<Diagnostic>()
            val drafts = mutableListOf<DeclarationDraft>()
            var fileCount = 0
            var callsTotal = 0
            var callsResolved = 0
            var symbolFailures = 0
            // Indexed once: a scan per declaration and per usage is quadratic
            // in file count, which is invisible on fixtures and dominates the
            // wall clock on a real repo's thousands of files.
            val sourceByRelPath = collected.associateBy { it.relativePath }
            val purlByModulePath = versionedModules.associate { it.module.modulePath to it.module.purl }

            // The call graph and reachability, built from the KIR in
            // kosi-graph (compiler types stop at this module's boundary).
            // `--callgraph none` publishes no graph at all — `options`
            // already records that nothing was requested.
            //
            // Golem's guardAlgorithm lesson: a call-graph crash must
            // not discard the already-computed evidence report. The failure
            // becomes a NAMED diagnostic and the report ships without the
            // graph; it is never swallowed into a green result.
            var callgraphFailure: String? = null
            val graphResult = if (options.callgraph != io.cdxgen.kosi.schema.CallGraphMode.NONE) {
                if (budgets.shouldStop() != null) {
                    callgraphFailure = "the analysis budget tripped before the call graph could be built"
                    null
                } else {
                    try {
                        io.cdxgen.kosi.graph.CallGraphBuilder.build(
                            io.cdxgen.kosi.kir.KirModule(kir.functions),
                            io.cdxgen.kosi.graph.GraphOptions(
                                mode = options.callgraph,
                                roots = io.cdxgen.kosi.graph.GraphOptions.rootsOf(options.roots),
                                includeStdlib = options.includeStdlib,
                                dependencyDetail = options.dependencyDetail,
                                maxPathsPerSymbol = options.maxPathsPerSymbol,
                                timeoutSeconds = options.callgraphTimeoutSeconds,
                            ),
                            io.cdxgen.kosi.graph.CallGraphBuilder.Attribution(
                                byAbsoluteFilePath = fileRelPathByAbsolute,
                                purlByModulePath = purlByModulePath,
                            ),
                        )
                    } catch (t: Throwable) {
                        callgraphFailure = (t.message ?: t::class.simpleName ?: "error").take(300)
                        if (System.getenv("KOSI_TRACE") != null) t.printStackTrace()
                        null
                    }
                }
            } else {
                null
            }

            for (fact in facts) {
                fileCount++
                callsTotal += fact.callsTotal
                callsResolved += fact.callsResolved
                symbolFailures += fact.symbolFailures
                diagnostics.addAll(fact.diagnostics)
                for (import in fact.imports) {
                    imports.add(import.copy(purl = ClasspathResolver.purlForImport(import.name, packageIndex)))
                }
                for (raw in fact.usages) {
                    usages.add(
                        LibraryUsage(
                            id = "",
                            name = raw.name,
                            simpleName = raw.name.substringAfterLast('.').substringAfterLast("::"),
                            usageKind = raw.usageKind,
                            modulePath = fact.modulePath,
                            purl = purlByModulePath[fact.modulePath] ?: "",
                            filePath = fact.relativePath,
                            position = raw.position,
                        ),
                    )
                }
                for (decl in fact.declarations) {
                    val source = sourceByRelPath[fact.relativePath]
                    drafts.add(
                        DeclarationDraft(
                            name = decl.name,
                            qualifiedName = decl.qualifiedName,
                            canonicalName = decl.canonicalName,
                            kind = decl.kind,
                            signature = decl.signature,
                            returnType = decl.returnType,
                            extensionReceiverType = decl.extensionReceiverType,
                            visibility = decl.visibility,
                            modifiers = decl.modifiers,
                            annotations = decl.annotations,
                            overrides = decl.overrides,
                            supertypes = decl.supertypes,
                            jvmOwner = decl.jvmOwner,
                            jvmDescriptor = decl.jvmDescriptor,
                            position = decl.position,
                            source = source,
                            parameterAnnotations = decl.parameterAnnotations,
                            unresolvedSupertypes = decl.unresolvedSupertypes,
                        ),
                    )
                }
            }

            // Framework endpoints, outbound services and URL evidence,
            // resolved from the lowered module plus the declaration
            // annotations' values; and the crypto/CBOM evidence. Both live
            // in their own modules; the pipeline only wires them.
            val kirModule = io.cdxgen.kosi.kir.KirModule(kir.functions)
            val sourceTexts = collected.associate { source ->
                source.relativePath to (try {
                    Files.readString(source.absolutePath)
                } catch (_: Exception) {
                    ""
                })
            }
            val importResolvedAnnotations = java.util.concurrent.atomic.AtomicInteger()
            val declarationAnnotationValues = declarationAnnotations(
                drafts,
                kirModule,
                // Resolution's own short-name -> FQN map. Scanning KIR
                // FUNCTION annotations cannot reach a class with no
                // functions, and framework matching is on the FQN.
                facts.fold(mutableMapOf<String, MutableSet<String>>()) { acc, f ->
                    for ((short, fqns) in f.annotationFqnsByShortName) {
                        acc.getOrPut(short) { mutableSetOf() }.addAll(fqns)
                    }
                    acc
                },
                // Explicit imports per file: the compiler's own rule for a
                // short annotation name when the classpath lacks its jar.
                importsByFile = facts.associate { f ->
                    f.relativePath to f.imports.filter { !it.star }.associate { (it.alias ?: it.name.substringAfterLast('.')) to it.name }
                },
                starImportsByFile = facts.associate { f ->
                    f.relativePath to (f.packageName to f.imports.filter { it.star }.map { it.name.removeSuffix(".*") })
                },
                importResolved = importResolvedAnnotations,
            )
            val resolvedDependencyCoordinates = buildSet {
                for (jar in resolution.jars) {
                    // The real coordinate, interpolated: this arm read
                    // `"${'$'}{it.group}:${'$'}{it.artifact}"`,
                    // which renders the LITERAL `${it.group}:...` — a
                    // dead arm nobody noticed because the FILE-NAME arm
                    // below matched every Gradle-cache jar anyway
                    // (R111b). A bound pin with a custom jar name has no
                    // filename to fall back on; implicit-routes-
                    // unresolved pins exactly that shape.
                    jar.coordinate?.let { add(it.group + ":" + it.artifact) }
                    // With its version when the pin names one: a route set
                    // can depend on the generation (spring-data-commons 3
                    // split PagingAndSortingRepository off CrudRepository).
                    jar.coordinate?.takeIf { it.version != null }?.let { add(it.group + ":" + it.artifact + ":" + it.version) }
                    add(jar.jar.fileName.toString())
                }
            }
            // The pack-entry liveness gate re-runs endpoint
            // DETECTION once per removed pack entry over exactly these
            // captured products, so the front-end analysis runs once per
            // fixture regardless of how many entries the pack carries.
            // The capture carries the endpoint pass's own Result
            // (fold statistics included), computed in the same run.
            val capture = EndpointCapture(
                module = kirModule,
                sourceTexts = sourceTexts,
                annotationValues = declarationAnnotationValues,
                dependencyCoordinates = resolvedDependencyCoordinates,
                importRootsByFile = facts.associate { f ->
                    f.relativePath to f.imports.mapNotNull { imp -> imp.name.split('.').take(2).takeIf { it.size == 2 }?.joinToString(".") }.toSet()
                },
                typeDeclarations = typeDeclarationsOf(
                    drafts,
                    facts.associate { f -> f.relativePath to f.imports.filter { !it.star }.associate { (it.alias ?: it.name.substringAfterLast('.')) to it.name } },
                    facts.associate { f -> f.relativePath to (f.packageName to f.imports.filter { it.star }.map { it.name.removeSuffix(".*") }) },
                ),
            )
            val endpoints = io.cdxgen.kosi.endpoints.Endpoints.analyze(
                module = kirModule,
                root = root,
                sourceTexts = sourceTexts,
                annotationValues = declarationAnnotationValues,
                attribution = io.cdxgen.kosi.endpoints.Endpoints.Attribution(fileRelPathByAbsolute, purlByModulePath),
                includeManifests = true,
                // The resolved classpath, as coordinates: some routes exist
                // because a dependency is present and for no other reason.
                // PRESENT means the resolver located the artifact — the
                // missing[] list is deliberately NOT fed here: a marker
                // coordinate that failed to resolve is an ABSENT dependency,
                // and treating it as present published the implicit trees on
                // machines whose cache was cold, the exact
                // wrong-reason pass implicit-routes-unresolved pins.
                dependencyCoordinates = resolvedDependencyCoordinates,
                // Every declaration this run READ, both languages.
                // A manifest component's substantiation is decided against
                // this set, and the KIR cannot stand in for it — Java
                // declarations never enter the KIR, so a Java-only Android
                // module answered "did not look" about classes it had read.
                analysedDeclarations = drafts.mapTo(HashSet()) { it.canonicalName },
                foldStats = capture.foldStats,
                typeDeclarations = capture.typeDeclarations,
                importRootsByFile = capture.importRootsByFile,
            )
            val crypto = io.cdxgen.kosi.crypto.CryptoCollector.collect(
                io.cdxgen.kosi.crypto.CryptoCollector.Input(
                    module = kirModule,
                    sourceTexts = sourceTexts,
                    configValues = configValuesForCrypto(root),
                    configKeys = io.cdxgen.kosi.endpoints.ConfigResolver.load(root).keys(),
                ),
            ).let { result ->
                // Evidence carries RELATIVE paths, like every other array.
                result.copy(
                    operations = result.operations.map { op ->
                        val rel = fileRelPathByAbsolute[op.filePath]?.first ?: op.filePath
                        op.copy(filePath = rel, position = Position(rel, op.position.line, op.position.column))
                    },
                    materials = result.materials.map { m ->
                        val rel = fileRelPathByAbsolute[m.filePath]?.first ?: m.filePath
                        m.copy(filePath = rel, position = Position(rel, m.position.line, m.position.column))
                    },
                    findings = result.findings.map { f ->
                        val rel = fileRelPathByAbsolute[f.filePath]?.first ?: f.filePath
                        f.copy(filePath = rel, position = Position(rel, f.position.line, f.position.column))
                    },
                )
            }

            // The intraprocedural taint engine (kosi-flow, compiler-free).
            // Sources, sinks, passthroughs, sanitizers and effects are DATA
            // (the shipped model pack); the engine walks each lowered
            // function's CFG to a worklist fixpoint. `--dataflow reachable`
            // intersects the slices with the call graph's reachability from
            // the roots — a slice whose function no root reaches is not
            // published, and the surviving ones carry the flag.
            //
            // `--deps`: when the run asks for it, the resolved classpath
            // jars are lowered to the SAME KIR by kosi-bytecode and handed to
            // the SAME engine, whose summaries then carry `origin=bytecode`.
            val depsEnabled = options.deps || options.dataflow == io.cdxgen.kosi.schema.DataflowMode.SECURITY_DEPS
            val depTier = if (depsEnabled) {
                buildDependencyTier(kirModule, resolution, options)
            } else {
                null
            }
            val flowResult = if (options.dataflow != io.cdxgen.kosi.schema.DataflowMode.NONE) {
                io.cdxgen.kosi.flow.TaintEngine.analyze(
                    kirModule,
                    io.cdxgen.kosi.models.ModelPacks.loadBuiltin(),
                    io.cdxgen.kosi.flow.TaintEngine.Attribution(fileRelPathByAbsolute, purlByModulePath),
                    io.cdxgen.kosi.flow.TaintEngine.Options(
                        mode = options.dataflow.id,
                        accessPathDepth = options.accessPathDepth,
                        maxSlices = options.dataflowMaxSlices,
                        maxTraceNodes = options.dataflowMaxTraceNodes,
                        maxFunctionInstructions = options.dataflowMaxFunctionInstructions,
                        maxSummarySinkEffects = options.dataflowMaxSummarySinkEffects,
                        unknownCallPropagate = options.unknownCall == "propagate",
                        skipGenerated = options.dataflowSkipGenerated,
                        pathWidening = options.dataflowPathWidening,
                        dispatchMode = options.callgraph.id,
                        endpointSources = if (options.endpointSources) endpoints.sourceHandlers else emptyMap(),
                        // The framework's own statement about which handler
                        // parameters carry attacker input, WHAT KIND of
                        // input each annotation names, and the category it
                        // carries (the source is a parameter, not
                        // a function).
                        endpointParameterAnnotations = if (options.endpointSources) {
                            io.cdxgen.kosi.models.EndpointModels.loadBuiltin().frameworks
                                .flatMap { it.parameterAnnotations }
                                .associate { it.pattern to it }
                        } else {
                            emptyMap()
                        },
                        endpointHandlerFrameworks = if (options.endpointSources) {
                            endpoints.apiEndpoints
                                .filter { it.handlerCanonicalName.isNotEmpty() }
                                .associate { it.handlerCanonicalName to it.framework }
                        } else {
                            emptyMap()
                        },
                        endpointHandlerInput = if (options.endpointSources) {
                            io.cdxgen.kosi.models.EndpointModels.loadBuiltin().frameworks
                                .associate { it.id to it.handlerInput }
                        } else {
                            emptyMap()
                        },
                        endpointContextParameterTypes = if (options.endpointSources) {
                            io.cdxgen.kosi.models.EndpointModels.loadBuiltin().frameworks
                                .associate { it.id to it.contextParameterTypes }
                        } else {
                            emptyMap()
                        },
                        endpointNonInputAnnotations = if (options.endpointSources) {
                            io.cdxgen.kosi.models.EndpointModels.loadBuiltin().frameworks
                                .associate { it.id to it.nonInputAnnotations }
                        } else {
                            emptyMap()
                        },
                        endpointSimpleParameterTypes = if (options.endpointSources) {
                            io.cdxgen.kosi.models.EndpointModels.loadBuiltin().frameworks
                                .associate { it.id to it.simpleParameterTypes }
                        } else {
                            emptyMap()
                        },
                        depsModule = depTier?.module,
                        depsPurls = depTier?.purlsUsed ?: emptySet(),
                        depsAliases = depTier?.aliases ?: emptyMap(),
                        depsClassCount = depTier?.classCount ?: 0,
                        depsBodylessRecords = depTier?.bodylessRecords ?: 0,
                        shouldStop = budgets::shouldStop,
                        dataflowWorkers = options.dataflowWorkers,
                    ),
                )
            } else {
                null
            }
            endpointCapture?.invoke(
                capture.copy(
                    endpoints = endpoints,
                    flowDepth = flowResult?.depth,
                    flowReturnOpinions = flowResult?.returnOpinions,
                ),
            )
            val dataFlow = if (flowResult != null) {
                // `--dataflow crypto` is a FILTER, and until
                // this change it filtered nothing — `security`, `crypto`,
                // `all` and `security-deps` published byte-identical slice
                // sets, so a run that asked for crypto flows was handed
                // log-injection findings under `"mode": "crypto"`. The
                // predicate is the one the bench has counted
                // `cryptoFlowSlices`, now shared rather than
                // duplicated. The other modes keep their meanings exactly:
                // `security` is every pack flow, `all` is its declared alias
                // (the pack has nothing `security` leaves out), `reachable`
                // is the intersection below, `security-deps` is `security`
                // plus the dependency tier.
                val evidence = if (options.dataflow == io.cdxgen.kosi.schema.DataflowMode.CRYPTO) {
                    flowResult.evidence.restrictTo(
                        flowResult.evidence.slices.filter { io.cdxgen.kosi.schema.CryptoFlow.isCryptoFlow(it) },
                    )
                } else {
                    flowResult.evidence
                }
                if (options.dataflow == io.cdxgen.kosi.schema.DataflowMode.REACHABLE && graphResult != null) {
                    val reachedFunctions = graphResult.callGraph.reachability
                        .filter { it.reached }
                        .mapNotNull { entry -> graphResult.callGraph.nodes.firstOrNull { it.id == entry.nodeId }?.canonicalName }
                        .toSet()
                    val kept = evidence.slices.filter { it.sinkFunction in reachedFunctions }
                    // The intersection IS the reachability fact — the
                    // per-slice flag that used to be stamped true here said
                    // only "this run was the reachable one", which
                    // `dataFlow.mode` already says. It narrows the
                    // whole document (nodes, edges and every derived counter)
                    // through the one function that does that, instead of
                    // recomputing four counters and leaving five plus the
                    // node and edge arrays describing dropped traces.
                    val narrowed = evidence.restrictTo(kept)
                    narrowed.copy(stats = narrowed.stats.copy(reachableSlices = kept.size))
                } else {
                    evidence
                }
            } else {
                null
            }

            // `--endpoint-sources` links endpoint-rooted slices to the
            // endpoint they enter through, and names the source categories
            // each endpoint introduces.
            val apiEndpoints = if (options.endpointSources && dataFlow != null) {
                val handlers = endpoints.apiEndpoints.associate { ep -> ep.handlerCanonicalName to ep.id }
                val bySlice = HashMap<String, MutableList<String>>()
                endpoints.apiEndpoints.forEach { ep -> bySlice[ep.handlerCanonicalName] = mutableListOf() }
                dataFlow.slices.forEach { slice ->
                    bySlice[slice.sourceFunction]?.add(slice.id)
                }
                endpoints.apiEndpoints.map { ep ->
                    ep.copy(
                        sliceIds = (bySlice[ep.handlerCanonicalName] ?: emptyList()).sorted(),
                        reachableSources = if (ep.handlerCanonicalName in handlers &&
                            (bySlice[ep.handlerCanonicalName] ?: emptyList()).isNotEmpty()
                        ) {
                            listOf(io.cdxgen.kosi.endpoints.Endpoints.SOURCE_CATEGORY)
                        } else {
                            emptyList()
                        },
                    )
                }
            } else {
                endpoints.apiEndpoints
            }

            // A manifest endpoint whose handler class matches no
            // analysed declaration is a claim kosi READ NOTHING of — dagger
            // published 53 of them beside `no-sources`, every one carrying
            // an EMPTY handlerCanonicalName (the lifecycle matcher found no
            // class to name). Marked, never silently asserted: the endpoint
            // stays (the manifest IS real), `substantiated=false` and the
            // diagnostic carry the "did not look" (the rule).
            //
            // moved the DECISION to the detector, which is the only
            // place that still knows the component's class name: the old
            // rule here read `handlerCanonicalName`, so a component whose
            // class kosi had read but which overrides no lifecycle method
            // (every nested `TestActivity` in dagger) was reported as
            // unread. What survives here is the counting and the
            // diagnostic; the verdict arrives on the endpoint.
            fun unsubstantiated(ep: io.cdxgen.kosi.schema.ApiEndpoint): Boolean = !ep.substantiated
            val unsubstantiatedEndpoints = apiEndpoints.count(::unsubstantiated)
            val unsubstantiatedDiagnostic = if (unsubstantiatedEndpoints > 0) {
                Diagnostic(
                    code = DiagnosticCodes.ENDPOINT_UNSUBSTANTIATED,
                    severity = Severity.WARNING,
                    message = "$unsubstantiatedEndpoints manifest endpoint(s) name a component class that is not " +
                        "among the analysed declarations (library components, or a run that discovered none of " +
                        "the sources); their behaviour was not read and they carry substantiated=false",
                    position = Position(".", 1, 1),
                    count = unsubstantiatedEndpoints,
                )
            } else {
                null
            }

            val pathUnresolvedEndpoints = apiEndpoints.count { it.pathUnresolved != null }
            val pathUnresolvedDiagnostic = if (pathUnresolvedEndpoints > 0) {
                Diagnostic(
                    code = DiagnosticCodes.ENDPOINT_PATH_UNRESOLVED,
                    severity = Severity.WARNING,
                    message = "$pathUnresolvedEndpoints endpoint(s) have a path kosi could not prove (a base path the deployment sets, " +
                        "or a path computed at run time); their pathTemplate is partial or empty and each names why in pathUnresolved",
                    position = Position(".", 1, 1),
                    count = pathUnresolvedEndpoints,
                )
            } else {
                null
            }
            val crudUnknown = endpoints.repositoriesCrudUnknown
            val crudUnknownDiagnostic = if (crudUnknown.isNotEmpty()) {
                Diagnostic(
                    code = DiagnosticCodes.REPOSITORY_CRUD_UNKNOWN,
                    severity = Severity.WARNING,
                    message = "${crudUnknown.size} repository resource(s) extend PagingAndSortingRepository alone and the " +
                        "resolved classpath names no spring-data-commons version; its CRUD methods exist only before 3.x, " +
                        "so only the collection's findAll routes were published: ${crudUnknown.take(5).joinToString()}",
                    position = Position(".", 1, 1),
                    count = crudUnknown.size,
                )
            } else {
                null
            }

            val importResolvedCount = importResolvedAnnotations.get()
            val importResolvedDiagnostic = if (importResolvedCount > 0) {
                Diagnostic(
                    code = DiagnosticCodes.ANNOTATION_IMPORT_RESOLVED,
                    severity = Severity.WARNING,
                    message = "$importResolvedCount annotation use(s) did not resolve against the classpath and were read at " +
                        "the FQN their file explicitly imports; the classpath lacks the framework's jars — pass the " +
                        "project's resolved classpath for full resolution",
                    position = Position(".", 1, 1),
                    count = importResolvedCount,
                )
            } else {
                null
            }

            val totalCalls = callsTotal
            val ratio = if (totalCalls == 0) 0.0 else callsResolved.toDouble() / totalCalls

            // Dependency-tier diagnostics: every miss is a counted,
            // named row, never a silent gap in the tier.
            val depsDiagnostics = if (depTier != null) {
                buildList {
                    if (depTier.bodylessRecords > 0) {
                        add(
                            Diagnostic(
                                code = DiagnosticCodes.DEPS_BODYLESS,
                                severity = Severity.INFO,
                                message = "${depTier.bodylessRecords} dependency record(s) carry no body " +
                                    "(abstract, interface, native or stripped) and were EXCLUDED from the " +
                                    "dependency tier — an empty body is indistinguishable from a no-op, so " +
                                    "none was summarised",
                                count = depTier.bodylessRecords,
                            ),
                        )
                    }
                    if (depTier.classesNotFound.isNotEmpty()) {
                        add(
                            Diagnostic(
                                code = DiagnosticCodes.DEPS_CLASS_NOT_FOUND,
                                severity = Severity.INFO,
                                message = "${depTier.classesNotFound.size} workspace call(s) name classes absent " +
                                    "from every classpath jar; their summaries cannot be computed: " +
                                    depTier.classesNotFound.take(10).joinToString(", "),
                                count = depTier.classesNotFound.size,
                            ),
                        )
                    }
                    if (depTier.classLimitHit) {
                        add(
                            Diagnostic(
                                code = DiagnosticCodes.DEPS_CLASS_LIMIT,
                                severity = Severity.WARNING,
                                message = "the --deps-max-classes budget capped the lowered dependency set at " +
                                    "${depTier.classCount} classes; ${depTier.classesNotLowered.size} selected class(es) " +
                                    "were not lowered (first: " + depTier.classesNotLowered.take(5).joinToString(", ") + "); " +
                                    "summaries through unlowered classes are absent",
                                count = depTier.classesNotLowered.size,
                            ),
                        )
                    }
                    if (depTier.unlowered.isNotEmpty()) {
                        val breakdown = depTier.unlowered.entries.sortedWith(compareBy({ it.key }, { it.value }))
                            .joinToString(", ") { "${it.key}=${it.value}" }
                        add(
                            Diagnostic(
                                code = DiagnosticCodes.BYTECODE_UNLOWERED,
                                severity = Severity.WARNING,
                                message = "the bytecode lowering declined $breakdown record(s); each is treated " +
                                    "as body-less and excluded, never summarised from a partial body",
                                count = depTier.unlowered.values.sum(),
                            ),
                        )
                    }
                }
            } else {
                emptyList()
            }
            val compileGapDiagnostic = if (options.backend == Backend.COMPILE) {
                Diagnostic(
                    code = DiagnosticCodes.COMPILE_BACKEND_GAP,
                    severity = Severity.WARNING,
                    message = "--backend compile is a DECLARED GAP in this release: kosi cannot execute the " +
                        "analysed build offline to obtain generated sources (KSP/Compose/Room), so this " +
                        "report is the RESOLVED tier's; generated sources were NOT analysed and no generated " +
                        "declaration appears in it",
                    position = Position(".", 1, 1),
                    count = 1,
                )
            } else {
                null
            }
            val callgraphDiagnostic = callgraphFailure?.let {
                Diagnostic(
                    code = DiagnosticCodes.CALLGRAPH_FAILED,
                    severity = Severity.ERROR,
                    message = "the call graph crashed and is ABSENT from this report; the already-computed " +
                        "evidence still ships: $it",
                    position = Position(".", 1, 1),
                    count = 1,
                )
            }
            val budgetDiagnostic = budgets.tripCode()?.let { code ->
                Diagnostic(
                    code = code,
                    severity = Severity.WARNING,
                    message = "the ${if (code == DiagnosticCodes.ANALYSIS_TIME_BUDGET) "--max-analysis-seconds" else "--max-rss-mb"} " +
                        "budget tripped during the run; the report degraded without discarding computed evidence",
                    position = Position(".", 1, 1),
                    count = 1,
                )
            }

            // Symbol operations that threw are counted, never swallowed: a
            // report whose declarations lost their JVM evidence because the
            // Analysis API failed underneath must say so, otherwise a
            // wholesale resolution breakage looks like a clean text-tier
            // report (07-REVIEW-PROTOCOL.md failure mode 9).
            val symbolFailureDiagnostic = if (symbolFailures > 0) {
                Diagnostic(
                    code = DiagnosticCodes.SYMBOL_RESOLUTION_FAILED,
                    severity = Severity.WARNING,
                    message = "${symbolFailures + kirSymbolFailures} symbol operation(s) failed during resolution " +
                        "($symbolFailures declarations, $kirSymbolFailures dispatch facts); the affected " +
                        "declarations carry text-derived evidence only (no jvmOwner/jvmDescriptor, " +
                        "supertypes or overrides) and the graph treats the affected functions as open",
                    position = Position(".", 1, 1),
                    count = symbolFailures + kirSymbolFailures,
                )
            } else {
                null
            }
            // Files the session's VFS refused are dropped from resolution
            // while staying in files[]; the count travels so the gap is not
            // silent.
            val droppedFiles = env.droppedSourceFiles
            val droppedDiagnostic = if (droppedFiles > 0) {
                Diagnostic(
                    code = DiagnosticCodes.UNREADABLE_SOURCE,
                    severity = Severity.ERROR,
                    message = "$droppedFiles collected source file(s) could not be opened by the analysis " +
                        "session and are absent from resolution although files[] lists them",
                    position = Position(".", 1, 1),
                    count = droppedFiles,
                )
            } else {
                null
            }

            return assemble(
                root = root,
                options = options,
                commit = commit,
                modules = versionedModules,
                buildSystem = discovery.buildSystem,
                collected = collected,
                declarations = drafts,
                usages = usages,
                imports = imports,
                diagnostics = versionDiagnostics + overrideDiagnostics + classpathDiagnostics +
                    listOfNotNull(
                        coverageDiagnostic,
                        unsubstantiatedDiagnostic,
                        pathUnresolvedDiagnostic, crudUnknownDiagnostic, importResolvedDiagnostic,
                        jdkDiagnostic, symbolFailureDiagnostic, droppedDiagnostic, kirDiagnostic, compileGapDiagnostic, callgraphDiagnostic, budgetDiagnostic,
                    ) + kirSkippedDiagnostics +
                    diagnostics + depsDiagnostics + (flowResult?.diagnostics ?: emptyList()),
                stats = Stats(
                    fileCount = fileCount,
                    declarationCount = drafts.size,
                    usageCount = usages.size,
                    importCount = imports.size,
                    resolvedCallRatio = ratio,
                    callsTotal = callsTotal,
                    callsResolved = callsResolved,
                    // The unresolved call sites the graph walked past; once the
                    // flow engine runs it counts the unknown calls through
                    // which taint ACTUALLY propagated — the honest measure of
                    // the conservative default's precision cost.
                    unknownCallPropagations = flowResult?.unknownCallPropagations
                        ?: graphResult?.unresolvedCalls ?: 0,
                    // Workspace lowering only. The dependency tier's misses
                    // are NOT folded in here: `loweringFailures` is the
                    // gate's numerator over `functionsLowered`, which counts
                    // workspace functions alone — adding jar records to the
                    // numerator and none to the denominator is the shape,
                    // and it would silently change what the gate means
                    // (empty on every fixture slot). The tier's misses are
                    // carried by the BYTECODE_UNLOWERED diagnostic, with
                    // their own breakdown and their own count.
                    loweringFailures = kir.failures,
                    functionsLowered = kir.functionCount,
                    fixpointCapHits = flowResult?.fixpointCapHits ?: 0,
                    functionsAnalysed = flowResult?.functionsAnalysed ?: 0,
                    unnameableInvokes = flowResult?.unnameableInvokes ?: 0,
                    sourceCount = flowResult?.sourceSites ?: 0,
                    sinkCount = flowResult?.sinkSites ?: 0,
                    sliceCount = dataFlow?.slices?.size ?: 0,
                    crossDependencySliceCount = dataFlow?.stats?.crossDependencySlices ?: 0,
                    crossModuleSliceCount = dataFlow?.stats?.crossModuleSlices ?: 0,
                    // READ, never re-derived: the intersection above is the
                    // only place that can answer this, and it has already
                    // written its answer into `dataFlow.stats`. A later
                    // review is what the second derivation cost — this line
                    // asked the MODE ("was reachability wanted?") where the
                    // intersection asks whether a graph existed, so
                    // `--dataflow reachable --callgraph none` published
                    // every slice as reachable with nothing computed. The
                    // phase's own rule: when two pieces of code answer the
                    // same question, the answers are a gate — so there is
                    // now one piece of code.
                    reachableSliceCount = dataFlow?.stats?.reachableSlices ?: 0,
                    sccsProcessed = flowResult?.sccsProcessed ?: 0,
                    sccIterationCapHits = flowResult?.sccIterationCapHits ?: 0,
                    suspendCrossingSliceCount = dataFlow?.stats?.suspendCrossingSlices ?: 0,
                    bodylessRecords = flowResult?.bodylessRecords ?: 0,
                    dependencyClasses = flowResult?.dependencyClasses ?: 0,
                    dependencyFunctions = flowResult?.dependencyFunctions ?: 0,
                    truncations = flowResult?.truncations ?: emptyMap(),
                    policySkips = flowResult?.skips ?: emptyMap(),
                    degraded = degradedTag(versionDiagnostics, resolution, ratio, noJdk = jdkHome == null),
                    classpath = classpathStats,
                    sourceCoverage = sourceCoverage,
                ),
                callGraph = graphResult?.callGraph,
                dataFlow = dataFlow,
                securitySignals = io.cdxgen.kosi.evidence.NativeInterop.collect(
                    root,
                    kirModule,
                    io.cdxgen.kosi.evidence.NativeInterop.Attribution(fileRelPathByAbsolute, purlByModulePath),
                ),
                apiEndpoints = apiEndpoints,
                services = endpoints.services,
                urls = endpoints.urls,
                crypto = io.cdxgen.kosi.schema.CryptoEvidence(
                    libraries = crypto.libraries,
                    assets = crypto.assets,
                    operations = crypto.operations,
                    materials = crypto.materials,
                    protocols = crypto.protocols,
                    findings = crypto.findings,
                ),
            )
        } finally {
            try {
                env.close()
            } catch (closeFailure: Throwable) {
                System.err.println(
                    "kosi: warning: the analysis session failed to close cleanly " +
                        "(${closeFailure::class.simpleName}: ${closeFailure.message?.take(200)}); " +
                        "the analysis result is unaffected",
                )
            }
        }
    }

    /**
     * The declaration annotations WITH VALUES, keyed by canonical name and
     * carrying the RESOLVED fqn the KIR holds: the detector matches on type
     * identity, so a PSI short name alone never stands for the framework's
     * annotation. A short name the KIR resolves to several fqns yields one
     * entry per fqn — only the framework's own matches, which is the
     * homonym rule doing the disambiguation.
     */
    private fun declarationAnnotations(
        drafts: List<DeclarationDraft>,
        kirModule: io.cdxgen.kosi.kir.KirModule,
        resolvedFqnsByShort: Map<String, Set<String>> = emptyMap(),
        importsByFile: Map<String, Map<String, String>> = emptyMap(),
        importResolved: java.util.concurrent.atomic.AtomicInteger? = null,
        /** File -> (its package, its star-imported packages). */
        starImportsByFile: Map<String, Pair<String, List<String>>> = emptyMap(),
    ): Map<String, List<io.cdxgen.kosi.endpoints.EndpointDetector.DeclAnnotation>> {
        val fqnsByShort = HashMap<String, MutableSet<String>>()
        for ((short, fqns) in resolvedFqnsByShort) {
            fqnsByShort.getOrPut(short) { mutableSetOf() }.addAll(fqns)
        }
        for (fn in kirModule.functions) {
            for (annotation in fn.annotations + fn.ownerAnnotations + fn.params.flatMap { it.annotations }) {
                fqnsByShort.getOrPut(annotation.substringAfterLast('.')) { mutableSetOf() }.add(annotation)
            }
        }
        // A short name NOTHING resolved: the declaring file's explicit
        // import names its FQN — Kotlin resolves an explicitly imported
        // name before any other scope, so this is the compiler's rule, not
        // a name-only guess. Without it, a run whose classpath lacked
        // spring-web (the offline cache scan brings no transitive jars)
        // found ZERO endpoints on every Spring, Quarkus and Micronaut repo
        // of the corpus. Counted, and published as a diagnostic.
        //
        // A STAR import (`import org.springframework.web.bind.annotation.*`)
        // is weaker evidence — Kotlin gives it lower priority, and several
        // star packages could each hold the name — so it resolves only when
        // (1) the file's own package declares no such name, (2) the FQN is
        // one the endpoints pack MODELS (a symbol known to exist there, and
        // pinned by the symbol-evidence gate), and (3) exactly ONE of the
        // file's star packages yields such an FQN.
        val declaredCanonicals = drafts.mapTo(HashSet()) { it.canonicalName }
        fun fqnsOf(short: String, file: String): Set<String> {
            // The file's explicit import FIRST: it is what the name means in
            // THIS file. The short-name map is repo-wide, so a same-named
            // annotation resolved in another package claimed every file's
            // unresolved use of the name.
            importsByFile[file]?.get(short)?.let { fqn ->
                if (fqnsByShort[short]?.contains(fqn) != true) importResolved?.incrementAndGet()
                return setOf(fqn)
            }
            fqnsByShort[short]?.takeIf { it.isNotEmpty() }?.let { return it }
            starImportsByFile[file]?.let { (pkg, stars) ->
                val local = if (pkg.isEmpty()) short else "$pkg.$short"
                if (local !in declaredCanonicals) {
                    val candidates = stars.map { "$it.$short" }.filter { it in PACK_SYMBOLS }
                    if (candidates.size == 1) {
                        importResolved?.incrementAndGet()
                        return setOf(candidates.single())
                    }
                }
            }
            return setOf(short)
        }
        val out = LinkedHashMap<String, MutableList<io.cdxgen.kosi.endpoints.EndpointDetector.DeclAnnotation>>()
        // A parameter's annotations under `<function>#<parameter>`: the
        // value of `@PathVariable("idProduct")` is the URL variable's name.
        for (draft in drafts) {
            for ((parameter, annotations) in draft.parameterAnnotations) {
                val entries = out.getOrPut(draft.canonicalName + "#" + parameter) { mutableListOf() }
                for (annotation in annotations) {
                    for (fqn in fqnsOf(annotation.name, draft.position.filename).sorted()) {
                        entries.add(
                            io.cdxgen.kosi.endpoints.EndpointDetector.DeclAnnotation(
                                fqn = fqn,
                                value = annotation.value,
                                line = draft.position.line,
                                namedValues = annotation.namedValues,
                                file = draft.position.filename,
                            ),
                        )
                    }
                }
            }
        }
        for (draft in drafts) {
            if (draft.annotations.isEmpty()) continue
            val entries = out.getOrPut(draft.canonicalName) { mutableListOf() }
            for (annotation in draft.annotations) {
                val fqns = fqnsOf(annotation.name, draft.position.filename)
                for (fqn in fqns.sorted()) {
                    entries.add(
                        io.cdxgen.kosi.endpoints.EndpointDetector.DeclAnnotation(
                            fqn = fqn,
                            value = annotation.value?.removeSurrounding("\"")?.removeSurrounding("'"),
                            line = annotation.position.line,
                            namedValues = annotation.namedValues,
                            file = draft.position.filename,
                            references = annotation.references,
                        ),
                    )
                }
            }
        }
        return out
    }

    /**
     * Every class FQN the endpoints pack names, the only symbols a star
     * import may resolve an unresolved annotation to (see
     * `declarationAnnotations`).
     */
    private val PACK_SYMBOLS: Set<String> by lazy {
        val text = io.cdxgen.kosi.models.EndpointModels::class.java
            .getResourceAsStream(io.cdxgen.kosi.models.EndpointModels.ENDPOINTS_PACK_RESOURCE)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        Regex(""""((?:[a-z_][A-Za-z0-9_]*\.)+[A-Z][A-Za-z0-9_]*)"""").findAll(text).mapTo(HashSet()) { it.groupValues[1] }
    }

    private val TYPE_KINDS = setOf("class", "interface", "data-class", "sealed-class", "object")

    /** The types a run read, with supertypes: a member-less repository interface is visible only here. */
    private fun typeDeclarationsOf(
        drafts: List<DeclarationDraft>,
        imports: Map<String, Map<String, String>> = emptyMap(),
        stars: Map<String, Pair<String, List<String>>> = emptyMap(),
    ): List<io.cdxgen.kosi.endpoints.Endpoints.TypeDeclaration> {
        val declared = drafts.mapTo(HashSet()) { it.canonicalName }
        return drafts.mapNotNull { draft ->
            val file = draft.position.filename
            // An UNRESOLVED supertype through the file's imports, by the
            // rule the annotations use: explicit import first; a star import
            // only to a pack-modelled FQN from exactly one star package. A
            // repository whose Spring Data jar is not on the classpath is
            // otherwise invisible.
            val recovered = draft.unresolvedSupertypes.mapNotNull { short ->
                imports[file]?.get(short) ?: stars[file]?.let { (pkg, starPkgs) ->
                    if ((if (pkg.isEmpty()) short else "$pkg.$short") in declared) null
                    else starPkgs.map { "$it.$short" }.filter { it in PACK_SYMBOLS }.singleOrNull()
                }
            }
            val supertypes = (draft.supertypes + recovered).distinct()
            // A supertype-less CLASS is kept too: a hierarchy search needs
            // its kind (interface or class) and whether it is abstract.
            if (supertypes.isEmpty() && draft.kind !in TYPE_KINDS) null
            else io.cdxgen.kosi.endpoints.Endpoints.TypeDeclaration(
                draft.canonicalName, file, supertypes, draft.kind, draft.modifiers.toSet(),
            )
        }
    }

    /** The config table's key -> value view the crypto collector folds against. */
    private fun configValuesForCrypto(root: java.nio.file.Path): Map<String, String> {
        val table = io.cdxgen.kosi.endpoints.ConfigResolver.load(root)
        return table.keys().mapNotNull { key -> table[key]?.value?.let { key to it } }.toMap()
    }

    /**
     * 08-VERSION-POLICY.md policy 4: a run with a version mismatch AND heavy
     * resolution fallout is marked degraded so no consumer reads the fallout
     * as facts about the code.
     */
    private fun degradedTag(
        versionDiagnostics: List<Diagnostic>,
        resolution: ClasspathResolver.Result,
        ratio: Double,
        noJdk: Boolean,
    ): String? {
        // A resolved run with no JDK resolves every `java.*` symbol to
        // nothing. That is not a partial classpath, it is a missing floor:
        // `fixtures/java-interop` drops from 2 of 2 resolved calls to 1, and
        // `fixtures/kosi-vulnerable-service` from 2 sinks and 1 slice to
        // none at all — with exit 0 and a warning nobody reads. The tag is
        // what a consumer checks instead.
        if (noJdk) return "no-jdk"
        val versionMismatch = versionDiagnostics.any {
            it.code == DiagnosticCodes.KOTLIN_LANGUAGE_VERSION || it.code == DiagnosticCodes.KOTLIN_VERSION
        }
        if (!versionMismatch) return null
        val fallout = resolution.missing.isNotEmpty() || ratio < 0.5
        return if (fallout) "kotlin-version" else null
    }

    private fun effectiveApiVersion(declared: String, language: String): String {
        val clamped = CompilerInfo.clampApiVersion(declared, language)
        return clamped.effective
    }

    /**
     * The kotlin-stdlib this kosi runs with: on the JVM it is a classpath
     * entry; in a native image the fat jar ships it as a resource, which is
     * materialized to a temp jar so the session can read it. Materialized
     * ONCE per process and deleted on exit — a per-run copy of a 1.8 MB jar
     * leaks a temp file for every analysed project (60 of them in one
     * corpusQuick).
     */
    private val stdlibJar: Path? by lazy { stdlibJarPath() }

    /** The bundled stdlib jar, shared with the kir dump pipeline. */
    internal fun stdlibJarForDump(): Path? = stdlibJar

    private fun stdlibJarPath(): Path? {
        for (entry in System.getProperty("java.class.path")?.split(File.pathSeparator) ?: emptyList()) {
            if (entry.isEmpty()) continue
            val p = Path.of(entry)
            val name = p.fileName.toString()
            if (name.startsWith("kotlin-stdlib-") && name.endsWith(".jar")) return p
        }
        val stream = Analyzer::class.java.classLoader.getResourceAsStream("kosi-libs/kotlin-stdlib.jar")
            ?: return null
        val target = Files.createTempFile("kosi-stdlib", ".jar")
        target.toFile().deleteOnExit()
        stream.use { input -> Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING) }
        return target
    }

    private val STDLIB_PURL: String
        get() = "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@" + CompilerInfo.compilerVersion()

    // ---- shared assembly -----------------------------------------------------

    class DeclarationDraft(
        val name: String,
        val qualifiedName: String,
        val canonicalName: String,
        val kind: String,
        val signature: String?,
        val returnType: String?,
        val extensionReceiverType: String?,
        val visibility: String,
        val modifiers: List<String>,
        val annotations: List<AnnotationEvidence>,
        val overrides: List<String>,
        val supertypes: List<String>,
        val jvmOwner: String?,
        val jvmDescriptor: String?,
        val position: Position,
        val source: SourceCollector.CollectedFile?,
        val parameterAnnotations: Map<String, List<AnnotationEvidence>> = emptyMap(),
        val unresolvedSupertypes: List<String> = emptyList(),
    )

    /**
     * Version policy (08-VERSION-POLICY.md §3/§4): clamp declared versions
     * into the bundled compiler's band, loudly, before any other diagnostics;
     * record explicit CLI overrides.
     */
    data class VersionedModule(val module: DiscoveredModule, val effective: String)

    internal fun discoverVersionPolicy(
        root: Path,
        modules: List<DiscoveredModule>,
        options: AnalyzeOptions,
    ): Triple<List<VersionedModule>, List<Diagnostic>, List<Diagnostic>> {
        val out = mutableListOf<VersionedModule>()
        val diagnostics = mutableListOf<Diagnostic>()
        val overrides = mutableListOf<Diagnostic>()
        val band = CompilerInfo.versionBand()
        for (module in modules.sortedWith(compareBy({ it.modulePath }, { it.name }))) {
            val clamped = CompilerInfo.clampLanguageVersion(module.declaredLanguageVersion)
            if (clamped.clamped) {
                val direction = if (CompilerInfo.isBelowBand(module.declaredLanguageVersion)) {
                    "below"
                } else {
                    "above"
                }
                diagnostics.add(
                    Diagnostic(
                        code = if (direction == "below") DiagnosticCodes.KOTLIN_LANGUAGE_VERSION else DiagnosticCodes.KOTLIN_VERSION,
                        severity = Severity.WARNING,
                        message = "module ${module.name} declares languageVersion=${module.declaredLanguageVersion} " +
                            "($direction the supported band ${band.first}..${band.latestStable}); " +
                            "analysis uses ${clamped.effective}",
                        position = Position(filename = module.modulePath, line = 1, column = 1),
                    ),
                )
            }
            val apiClamped = CompilerInfo.clampApiVersion(module.declaredApiVersion, clamped.effective)
            if (apiClamped.clamped) {
                diagnostics.add(
                    Diagnostic(
                        code = DiagnosticCodes.KOTLIN_API_VERSION,
                        severity = Severity.WARNING,
                        message = "module ${module.name} declares apiVersion=${module.declaredApiVersion} " +
                            "above its language version; clamped to ${apiClamped.effective}",
                        position = Position(filename = module.modulePath, line = 1, column = 1),
                    ),
                )
            }
            // CLI passthrough is a recorded override, not a silent one
            // (08-VERSION-POLICY.md policy 5).
            if (options.languageVersion != null &&
                module.declaredLanguageVersion != null &&
                options.languageVersion != module.declaredLanguageVersion
            ) {
                overrides.add(
                    Diagnostic(
                        code = DiagnosticCodes.VERSION_OVERRIDE,
                        severity = Severity.INFO,
                        message = "--language-version=${options.languageVersion} overrides module " +
                            "${module.name}'s declared ${module.declaredLanguageVersion}",
                        position = Position(filename = module.modulePath, line = 1, column = 1),
                    ),
                )
            }
            if (options.jvmTarget != null && module.jvmTarget != null && options.jvmTarget != module.jvmTarget) {
                overrides.add(
                    Diagnostic(
                        code = DiagnosticCodes.VERSION_OVERRIDE,
                        severity = Severity.INFO,
                        message = "--jvm-target=${options.jvmTarget} overrides module " +
                            "${module.name}'s declared ${module.jvmTarget}",
                        position = Position(filename = module.modulePath, line = 1, column = 1),
                    ),
                )
            }
            out.add(VersionedModule(module, clamped.effective))
        }
        return Triple(out, diagnostics, overrides)
    }

    private fun assemble(
        root: Path,
        options: AnalyzeOptions,
        commit: String,
        modules: List<VersionedModule>,
        buildSystem: String,
        collected: List<SourceCollector.CollectedFile>,
        declarations: List<DeclarationDraft>,
        usages: List<LibraryUsage>,
        imports: List<ImportUsage>,
        diagnostics: List<Diagnostic>,
        stats: Stats,
        callGraph: io.cdxgen.kosi.schema.CallGraph? = null,
        dataFlow: io.cdxgen.kosi.schema.DataFlowEvidence? = null,
        securitySignals: List<io.cdxgen.kosi.schema.SecuritySignal> = emptyList(),
        apiEndpoints: List<io.cdxgen.kosi.schema.ApiEndpoint> = emptyList(),
        services: List<io.cdxgen.kosi.schema.ServiceRef> = emptyList(),
        urls: List<io.cdxgen.kosi.schema.UrlEvidence> = emptyList(),
        crypto: io.cdxgen.kosi.schema.CryptoEvidence = io.cdxgen.kosi.schema.CryptoEvidence(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
    ): KosiReport {
        val moduleRefs = modules.map { vm ->
            val m = vm.module
            ModuleRef(
                name = m.name,
                modulePath = m.modulePath,
                platform = m.platform,
                workspaceMember = m.workspaceMember,
                purl = m.purl,
                sourceRoots = m.sourceRoots,
                declaredLanguageVersion = m.declaredLanguageVersion,
                declaredApiVersion = m.declaredApiVersion,
                effectiveLanguageVersion = vm.effective,
                jvmTarget = m.jvmTarget,
            )
        }

        val files = collected.map { source ->
            FileEvidence(
                path = source.relativePath,
                modulePath = source.modulePath,
                purl = source.modulePurl,
                language = source.language,
                generated = false,
            )
        }

        // Deterministic ids: sort canonically, then number.
        val sortedDeclarations = declarations
            .sortedWith(
                compareBy(
                    { it.position.filename },
                    { it.position.line },
                    { it.position.column },
                    { it.name },
                ),
            )
        val declarationsOut = sortedDeclarations.mapIndexed { index, draft ->
            Declaration(
                id = "dec-${(index + 1).toString().padStart(6, '0')}",
                name = draft.name,
                qualifiedName = draft.qualifiedName,
                canonicalName = draft.canonicalName,
                jvmOwner = draft.jvmOwner,
                jvmDescriptor = draft.jvmDescriptor,
                kind = draft.kind,
                modulePath = draft.source?.modulePath ?: "",
                purl = draft.source?.modulePurl ?: "",
                filePath = draft.source?.relativePath ?: draft.position.filename,
                signature = draft.signature,
                returnType = draft.returnType,
                extensionReceiverType = draft.extensionReceiverType,
                visibility = draft.visibility,
                modifiers = draft.modifiers,
                annotations = draft.annotations,
                overrides = draft.overrides,
                supertypes = draft.supertypes,
                position = draft.position,
                generated = null,
            )
        }

        val sortedUsages = usages.sortedWith(LibraryUsage.COMPARATOR)
        val usagesOut = sortedUsages.mapIndexed { index, usage ->
            usage.copy(id = "use-${(index + 1).toString().padStart(6, '0')}")
        }

        val packages = moduleRefs.map { module ->
            PackageEvidence(
                purl = module.purl,
                name = module.name,
                modulePath = module.modulePath,
                files = files.filter { it.modulePath == module.modulePath }.map { it.path },
            )
        }

        val diagnosticsOut = buildList {
            addAll(diagnostics)
            // Every accepted option pairing that cannot deliver what
            // it names, from the ONE predicate the CLI's refusals also read.
            // Stamped here, in `assemble`, because both tiers end up here and
            // a degradation that depended on which tier stamped it would be
            // the shape again. The Analyzer is a library — the bench,
            // the corpus and evinse call it directly and never see a usage
            // message — so it names all of them, including the ones the CLI
            // refuses outright.
            for (degradation in options.degradations()) {
                add(
                    Diagnostic(
                        code = degradation.code,
                        severity = if (degradation.usageError) Severity.WARNING else Severity.INFO,
                        message = degradation.message,
                        position = Position(".", 1, 1),
                        count = 1,
                    ),
                )
            }
            if (buildSystem == "none") {
                add(
                    Diagnostic(
                        code = DiagnosticCodes.NO_BUILD_FILES,
                        severity = Severity.INFO,
                        message = "no Gradle/Maven build files found; analysed as a plain source tree " +
                            "with inferred source roots",
                        position = Position(".", 1, 1),
                    ),
                )
            }
            if (stats.fileCount == 0) {
                add(
                    Diagnostic(
                        code = DiagnosticCodes.NO_SOURCES,
                        severity = Severity.WARNING,
                        message = "no Kotlin or Java source files were found under the discovered source roots",
                        position = Position(".", 1, 1),
                    ),
                )
            }
        }.sortedWith(Diagnostic.COMPARATOR)

        return KosiReport(
            schemaVersion = KosiReport.SCHEMA_VERSION,
            tool = ToolInfo(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, commit),
            runtime = RuntimeInfo(
                kotlinVersion = CompilerInfo.compilerVersion(),
                languageVersionRange = run {
                    val band = CompilerInfo.versionBand()
                    LanguageVersionRange(band.first, band.firstNonDeprecated, band.latestStable)
                },
                jvmVersion = System.getProperty("java.version") ?: "unknown",
                host = hostId(),
                workingDirectory = root.toAbsolutePath().normalize().toString(),
                nativeImage = isNativeImage(),
            ),
            options = options,
            modules = moduleRefs,
            packages = packages,
            files = files,
            imports = imports.sortedWith(ImportUsage.COMPARATOR),
            declarations = declarationsOut,
            usages = usagesOut,
            securitySignals = securitySignals,
            crypto = crypto,
            callGraph = callGraph,
            dataFlow = dataFlow,
            apiEndpoints = apiEndpoints,
            services = services,
            urls = urls,
            diagnostics = diagnosticsOut,
            stats = stats,
        )
    }

    fun hostId(): String {
        val os = System.getProperty("os.name")?.lowercase(Locale.ROOT) ?: "unknown"
        val arch = System.getProperty("os.arch")?.lowercase(Locale.ROOT) ?: "unknown"
        val family = when {
            os.contains("mac") || os.contains("darwin") -> "darwin"
            os.contains("win") -> "windows"
            os.contains("linux") -> "linux"
            os.contains("musl") -> "linuxmusl"
            else -> os
        }
        return "$family-$arch"
    }

    fun isNativeImage(): Boolean =
        System.getProperty("org.graalvm.nativeimage.enabled") != null ||
            System.getProperty("org.graalvm.nativeimage.imagecode") != null

    // ---- the --deps dependency tier ---------------------------------------

    private class DepTierBuild(
        val module: io.cdxgen.kosi.kir.KirModule,
        val classCount: Int,
        val purlsUsed: Set<String>,
        val aliases: Map<String, List<String>>,
        val bodylessRecords: Int,
        val unlowered: Map<String, Int>,
        val classesNotFound: List<String>,
        val classLimitHit: Boolean,
        val classesNotLowered: List<String>,
    )

    /**
     * Platform APIs live in the JDK image (or the Android platform jar), not
     * in the resolved classpath jars, and the shipped pack models their
     * shapes already — the tier excludes them BY PREFIX and the exclusion is
     * published (docs/KOSI.md names the shapes this population misses).
     */
    private val PLATFORM_PREFIXES = listOf(
        "java.", "javax.", "jdk.", "sun.", "com.sun.", "kotlin.", "kotlinx.", "android.",
    )

    /**
     * Selects and lowers the dependency classes the workspace actually calls
     * into. The wanted set is the workspace's resolved callees that are NOT
     * workspace functions and NOT platform APIs; the jars come from the same
     * offline classpath resolution the resolved tier already used, so the
     * tier never widens what the run can see.
     */
    private fun buildDependencyTier(
        kirModule: io.cdxgen.kosi.kir.KirModule,
        resolution: ClasspathResolver.Result,
        options: AnalyzeOptions,
    ): DepTierBuild? {
        if (resolution.jars.isEmpty()) return null
        val workspaceCanonicals = kirModule.functions.mapTo(HashSet()) { it.canonicalName }
        val workspaceClasses = kirModule.functions.mapNotNullTo(HashSet()) { it.enclosingClass }
        val wanted = sortedSetOf<String>()
        for (function in kirModule.functions) {
            val body = function.body ?: continue
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    if (ins !is io.cdxgen.kosi.kir.KirCall) continue
                    // CONSTRUCTOR callees ARE wanted: the constructor itself
                    // has no summary to apply, but lowering the class makes
                    // its methods available as dispatch targets (a planted
                    // DebugTree is how Timber's chain reaches a Log sink).
                    val fqn = ins.callee.fqn
                    if (fqn.isEmpty() || fqn.startsWith("<")) continue
                    if (fqn in workspaceCanonicals) continue
                    // Property-callable shapes name the owner class rather
                    // than the accessor's JVM method: skip anything whose
                    // class prefix is a workspace class.
                    if (fqn.substringBeforeLast('.') in workspaceClasses) continue
                    if (PLATFORM_PREFIXES.any { fqn.startsWith(it) }) continue
                    wanted.add(fqn)
                }
            }
        }
        if (wanted.isEmpty()) return null
        val jars = resolution.jars.map {
            io.cdxgen.kosi.bytecode.BytecodeLowerer.JarSpec(it.jar, it.purl)
        }
        val result = io.cdxgen.kosi.bytecode.BytecodeLowerer.lower(jars, wanted, options.depsMaxClasses)
        if (result.classCount == 0) return null
        return DepTierBuild(
            module = result.module,
            classCount = result.classCount,
            purlsUsed = result.purlsUsed,
            aliases = result.aliases,
            bodylessRecords = result.bodylessRecords,
            unlowered = result.unlowered,
            classesNotFound = result.classesNotFound,
            classLimitHit = result.classLimitHit,
            classesNotLowered = result.classesNotLowered,
        )
    }
}

/** True when a declared version is below FIRST_SUPPORTED (vs above the ceiling). */
private fun CompilerInfo.isBelowBand(declared: String?): Boolean {
    if (declared == null) return true
    val band = CompilerInfo.versionBand()
    val declaredParts = declared.split('.').mapNotNull { it.toIntOrNull() }
    val firstParts = band.first.split('.').mapNotNull { it.toIntOrNull() }
    if (declaredParts.size < 2 || firstParts.size < 2) return true
    return declaredParts[0] < firstParts[0] ||
        (declaredParts[0] == firstParts[0] && declaredParts[1] < firstParts[1])
}
