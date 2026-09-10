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
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.Path
import java.io.File
import java.util.Locale

/**
 * The analysis pipeline: project discovery (read-only), the chosen backend,
 * and report assembly with deterministic ordering and stable ids. The syntax
 * backend parses PSI without a classpath; the resolved backend (P1) runs the
 * standalone Analysis API session over the discovered modules, the
 * offline-resolved classpath and the JDK module. Nothing downstream of
 * kosi-front sees compiler types.
 */
object Analyzer {

    const val TOOL_NAME = "kosi"

    const val TOOL_DESCRIPTION = "kosi — Kotlin Source Inspector (static analysis for cdxgen)"

    const val TOOL_VERSION = "0.2.0"

    class AnalysisException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

    fun analyze(root: Path, options: AnalyzeOptions, commit: String): KosiReport = when (options.backend) {
        Backend.SYNTAX -> analyzeSyntax(root, options, commit)
        Backend.RESOLVED -> analyzeResolved(root, options, commit)
    }

    // ---- syntax tier (phase 0 behaviour, unchanged) -------------------------

    private fun analyzeSyntax(root: Path, options: AnalyzeOptions, commit: String): KosiReport {
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, versionDiagnostics, overrideDiagnostics) =
            discoverVersionPolicy(root, discovery.modules, options)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })
        val syntax = runSyntaxBackend(root, collected)

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
                )
            },
            usages = syntax.usages,
            imports = syntax.imports,
            diagnostics = versionDiagnostics + overrideDiagnostics + syntax.diagnostics,
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
            ),
        )
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
                    "(${t::class.simpleName}: ${t.message?.take(200) ?: "no message"}); " +
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
                val result = analyzer.analyze(text)
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

    // ---- resolved tier (P1) -------------------------------------------------

    private fun analyzeResolved(root: Path, options: AnalyzeOptions, commit: String): KosiReport {
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, versionDiagnostics, overrideDiagnostics) =
            discoverVersionPolicy(root, discovery.modules, options)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })

        // Classpath acquisition (02-ARCHITECTURE.md §3): explicit flags first,
        // then offline resolution from the local caches. Every coordinate the
        // resolver cannot find becomes a `classpath-partial` diagnostic naming
        // it — a partial classpath is never silent (07-REVIEW-PROTOCOL.md #9).
        val moduleDirs = versionedModules.map { vm ->
            root.resolve(vm.module.modulePath).toAbsolutePath().normalize()
        }
        // A named classpath file that does not exist is an error, not a
        // silently empty classpath: the P0 review's `--compare` defect was
        // exactly this shape — a flag the run echoed but never applied.
        options.classpathFile?.let { file ->
            if (!Files.isRegularFile(Path.of(file))) {
                throw AnalysisException("--classpath-file $file does not exist or is not a regular file")
            }
        }
        val resolution = ClasspathResolver.resolve(
            root = root,
            explicitJars = options.classpath.map { Path.of(it) },
            explicitFile = options.classpathFile?.let { Path.of(it) },
            moduleDirs = moduleDirs,
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
                    "(${t::class.simpleName}: ${t.message?.take(200) ?: "no message"}); " +
                    "run `kosi version` to see which components are available on this build",
                t,
            )
        }
        env.use { env ->
            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: session built, modules=" + env.session.modulesWithFiles.size)
            val workspace = env.session.modulesWithFiles.keys
                .filterIsInstance<org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule>()
                .firstOrNull() ?: throw AnalysisException("resolved backend: session built no workspace module")

            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: running resolved analyzer")
            val facts = ResolvedAnalyzer.run(env, workspace, fileRelPathByAbsolute)
            if (System.getenv("KOSI_TRACE") != null) System.err.println("TRACE: facts=" + facts.size)

            // P2: lower the same session to the KIR. The failures map is the
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

            // P3: the call graph and reachability, built from the KIR in
            // kosi-graph (compiler types stop at this module's boundary).
            // `--callgraph none` publishes no graph at all — `options`
            // already records that nothing was requested.
            val graphResult = if (options.callgraph != io.cdxgen.kosi.schema.CallGraphMode.NONE) {
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
                        ),
                    )
                }
            }

            // P4: the intraprocedural taint engine (kosi-flow, compiler-free).
            // Sources, sinks, passthroughs, sanitizers and effects are DATA
            // (the shipped model pack); the engine walks each lowered
            // function's CFG to a worklist fixpoint. `--dataflow reachable`
            // intersects the slices with the call graph's reachability from
            // the roots — a slice whose function no root reaches is not
            // published, and the surviving ones carry the flag.
            val flowResult = if (options.dataflow != io.cdxgen.kosi.schema.DataflowMode.NONE) {
                io.cdxgen.kosi.flow.TaintEngine.analyze(
                    io.cdxgen.kosi.kir.KirModule(kir.functions),
                    io.cdxgen.kosi.models.ModelPacks.loadBuiltin(),
                    io.cdxgen.kosi.flow.TaintEngine.Attribution(fileRelPathByAbsolute, purlByModulePath),
                    io.cdxgen.kosi.flow.TaintEngine.Options(
                        mode = options.dataflow.id,
                        accessPathDepth = options.accessPathDepth,
                        maxSlices = options.dataflowMaxSlices,
                        maxTraceNodes = options.dataflowMaxTraceNodes,
                        maxFunctionInstructions = options.dataflowMaxFunctionInstructions,
                        unknownCallPropagate = options.unknownCall == "propagate",
                        skipGenerated = options.dataflowSkipGenerated,
                        dispatchMode = options.callgraph.id,
                    ),
                )
            } else {
                null
            }
            val dataFlow = if (flowResult != null) {
                val evidence = flowResult.evidence
                if (options.dataflow == io.cdxgen.kosi.schema.DataflowMode.REACHABLE && graphResult != null) {
                    val reachedFunctions = graphResult.callGraph.reachability
                        .filter { it.reached }
                        .mapNotNull { entry -> graphResult.callGraph.nodes.firstOrNull { it.id == entry.nodeId }?.canonicalName }
                        .toSet()
                    val kept = evidence.slices.filter { it.sinkFunction in reachedFunctions }
                    evidence.copy(
                        slices = kept.map { it.copy(reachableFromRoots = true) },
                        stats = evidence.stats.copy(
                            sliceCount = kept.size,
                            uniqueFlows = kept.map { it.flowKey }.toSortedSet().size,
                            reachableSlices = kept.size,
                        ),
                    )
                } else {
                    evidence
                }
            } else {
                null
            }

            val totalCalls = callsTotal
            val ratio = if (totalCalls == 0) 0.0 else callsResolved.toDouble() / totalCalls

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
                    listOfNotNull(jdkDiagnostic, symbolFailureDiagnostic, droppedDiagnostic, kirDiagnostic) +
                    diagnostics + (flowResult?.diagnostics ?: emptyList()),
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
                    loweringFailures = kir.failures,
                    functionsLowered = kir.functionCount,
                    fixpointCapHits = flowResult?.fixpointCapHits ?: 0,
                    functionsAnalysed = flowResult?.functionsAnalysed ?: 0,
                    sourceCount = flowResult?.sourceSites ?: 0,
                    sinkCount = flowResult?.sinkSites ?: 0,
                    sliceCount = dataFlow?.slices?.size ?: 0,
                    crossDependencySliceCount = dataFlow?.stats?.crossDependencySlices ?: 0,
                    crossModuleSliceCount = dataFlow?.stats?.crossModuleSlices ?: 0,
                    reachableSliceCount = dataFlow?.slices?.count { it.reachableFromRoots } ?: 0,
                    sccsProcessed = flowResult?.sccsProcessed ?: 0,
                    sccIterationCapHits = flowResult?.sccIterationCapHits ?: 0,
                    suspendCrossingSliceCount = dataFlow?.stats?.suspendCrossingSlices ?: 0,
                    truncations = flowResult?.truncations ?: emptyMap(),
                    degraded = degradedTag(versionDiagnostics, resolution, ratio),
                ),
                callGraph = graphResult?.callGraph,
                dataFlow = dataFlow,
            )
        }
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
    ): String? {
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
            securitySignals = emptyList(),
            crypto = CryptoEvidence(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
            callGraph = callGraph,
            dataFlow = dataFlow,
            apiEndpoints = emptyList(),
            services = emptyList(),
            urls = emptyList(),
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
