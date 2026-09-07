package io.cdxgen.kosi.front

import io.cdxgen.kosi.project.DiscoveredModule
import io.cdxgen.kosi.project.GradleDiscovery
import io.cdxgen.kosi.project.ProjectDiscovery
import io.cdxgen.kosi.project.SourceCollector
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.CallGraph
import io.cdxgen.kosi.schema.CryptoEvidence
import io.cdxgen.kosi.schema.DataFlowEvidence
import io.cdxgen.kosi.schema.Diagnostic
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
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

/**
 * The phase-0 analysis pipeline: project discovery (read-only), the syntax
 * backend (PSI-only), and report assembly with deterministic ordering and
 * stable ids. Later phases plug the resolved/bytecode tiers in between
 * discovery and assembly; nothing downstream of kosi-front sees compiler
 * types.
 */
object Analyzer {

    const val TOOL_NAME = "kosi"

    const val TOOL_DESCRIPTION = "kosi — Kotlin Source Inspector (static analysis for cdxgen)"

    const val TOOL_VERSION = "0.1.0"

    class AnalysisException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

    fun analyze(root: Path, options: AnalyzeOptions, commit: String, pretty: Boolean): KosiReport {
        require(options.backend == Backend.SYNTAX) {
            "backend ${options.backend.id} is not available in phase 0; use --backend syntax"
        }
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, versionDiagnostics) = discoverVersionPolicy(root, discovery.modules)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })
        val syntax = runSyntaxBackend(root, collected)

        return assemble(
            root = root,
            options = options,
            commit = commit,
            modules = versionedModules,
            buildSystem = discovery.buildSystem,
            collected = collected,
            syntax = syntax,
            extraDiagnostics = versionDiagnostics,
        )
    }

    /**
     * Version policy (08-VERSION-POLICY.md §3/§4): clamp declared versions
     * into the bundled compiler's band, loudly, before any other diagnostics.
     */
    private data class VersionedModule(val module: DiscoveredModule, val effective: String)

    private fun discoverVersionPolicy(root: Path, modules: List<DiscoveredModule>): Pair<List<VersionedModule>, List<Diagnostic>> {
        val out = mutableListOf<VersionedModule>()
        val diagnostics = mutableListOf<Diagnostic>()
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
                        code = if (direction == "below") "kotlin-language-version" else "kotlin-version",
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
                        code = "kotlin-api-version",
                        severity = Severity.WARNING,
                        message = "module ${module.name} declares apiVersion=${module.declaredApiVersion} " +
                            "above its language version; clamped to ${apiClamped.effective}",
                        position = Position(filename = module.modulePath, line = 1, column = 1),
                    ),
                )
            }
            out.add(VersionedModule(module, clamped.effective))
        }
        return out to diagnostics
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
        PsiEnvironment.create().use { env ->
            for (source in collected) {
                val text = try {
                    Files.readString(source.absolutePath)
                } catch (e: Exception) {
                    diagnostics.add(
                        Diagnostic(
                            code = "unreadable-source",
                            severity = Severity.ERROR,
                            message = "could not read ${source.relativePath}: ${e.message ?: "error"}",
                            position = Position(source.relativePath, 1, 1),
                        ),
                    )
                    continue
                }
                if (source.language == FileEvidence.LANGUAGE_JAVA) {
                    // Java sources are evidence in files[] at the syntax tier;
                    // parsing Java PSI is part of the resolved tier.
                    fileCount++
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
        diagnostics.add(
            Diagnostic(
                code = "syntax-backend-no-resolution",
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

    private fun assemble(
        root: Path,
        options: AnalyzeOptions,
        commit: String,
        modules: List<VersionedModule>,
        buildSystem: String,
        collected: List<SourceCollector.CollectedFile>,
        syntax: SyntaxRun,
        extraDiagnostics: List<Diagnostic>,
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
        val sortedDeclarations = syntax.declarations
            .sortedWith(
                compareBy(
                    { it.raw.position.filename },
                    { it.raw.position.line },
                    { it.raw.position.column },
                    { it.raw.name },
                ),
            )
        val declarations = sortedDeclarations.mapIndexed { index, holder ->
            val raw = holder.raw
            Declaration(
                id = "dec-${(index + 1).toString().padStart(6, '0')}",
                name = raw.name,
                qualifiedName = raw.qualifiedName,
                canonicalName = raw.canonicalName,
                jvmOwner = null,
                jvmDescriptor = null,
                kind = raw.kind,
                modulePath = holder.source.modulePath,
                purl = holder.source.modulePurl,
                filePath = holder.source.relativePath,
                signature = raw.signature,
                receiverType = raw.receiverType,
                extensionReceiverType = raw.extensionReceiverType,
                visibility = raw.visibility,
                modifiers = raw.modifiers,
                annotations = raw.annotations,
                overrides = emptyList(),
                position = raw.position,
                generated = null,
            )
        }

        val sortedUsages = syntax.usages.sortedWith(LibraryUsage.COMPARATOR)
        val usages = sortedUsages.mapIndexed { index, usage ->
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

        val diagnostics = buildList {
            addAll(extraDiagnostics)
            addAll(syntax.diagnostics)
            if (buildSystem == "none") {
                add(
                    Diagnostic(
                        code = "no-build-files",
                        severity = Severity.INFO,
                        message = "no Gradle/Maven build files found; analysed as a plain source tree " +
                            "with inferred source roots",
                        position = Position(".", 1, 1),
                    ),
                )
            }
            if (syntax.fileCount == 0) {
                add(
                    Diagnostic(
                        code = "no-sources",
                        severity = Severity.WARNING,
                        message = "no Kotlin or Java source files were found under the discovered source roots",
                        position = Position(".", 1, 1),
                    ),
                )
            }
        }.sortedWith(Diagnostic.COMPARATOR)

        val stats = Stats(
            fileCount = syntax.fileCount,
            declarationCount = declarations.size,
            usageCount = usages.size,
            importCount = syntax.imports.size,
            resolvedCallRatio = 0.0,
            unknownCallPropagations = 0,
            loweringFailures = emptyMap(),
            fixpointCapHits = 0,
            sourceCount = 0,
            sinkCount = 0,
            sliceCount = 0,
            crossDependencySliceCount = 0,
            reachableSliceCount = 0,
            truncations = emptyMap(),
            degraded = null,
        )

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
            imports = syntax.imports.sortedWith(ImportUsage.COMPARATOR),
            declarations = declarations,
            usages = usages,
            securitySignals = emptyList(),
            crypto = CryptoEvidence(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
            callGraph = null,
            dataFlow = null,
            apiEndpoints = emptyList(),
            services = emptyList(),
            urls = emptyList(),
            diagnostics = diagnostics,
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

    /**
     * Peak RSS via the OS where available (linux VmHWM, darwin ps), else the
     * JVM heap ceiling as a documented lower bound with a diagnostic from the
     * caller. Volatile by nature; excluded from digest goldens.
     */
    fun peakRssBytes(): Long {
        try {
            val proc = Path.of("/proc/self/status")
            if (Files.exists(proc)) {
                for (line in Files.readAllLines(proc)) {
                    if (line.startsWith("VmHWM:")) {
                        val kb = line.substringAfter("VmHWM:").trim().substringBefore(" ").toLongOrNull()
                        if (kb != null) return kb * 1024
                    }
                }
            }
            if (hostId().startsWith("darwin")) {
                val pid = ProcessHandle.current().pid()
                val p = ProcessBuilder("ps", "-o", "rss=", "-p", pid.toString())
                    .redirectErrorStream(true)
                    .start()
                val out = p.inputStream.bufferedReader().readText().trim()
                p.waitFor()
                val kb = out.lines().firstOrNull()?.toLongOrNull()
                if (kb != null) return kb * 1024
            }
        } catch (_: Exception) {
            // fall through to the JVM lower bound
        }
        val heap = ManagementFactory.getMemoryMXBean().heapMemoryUsage
        val nonHeap = ManagementFactory.getMemoryMXBean().nonHeapMemoryUsage
        return heap.used + nonHeap.used
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
