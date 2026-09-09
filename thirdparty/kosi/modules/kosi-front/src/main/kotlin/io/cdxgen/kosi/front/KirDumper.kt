package io.cdxgen.kosi.front

import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.project.ClasspathResolver
import io.cdxgen.kosi.project.ProjectDiscovery
import io.cdxgen.kosi.project.SourceCollector
import io.cdxgen.kosi.kir.KirValidator
import io.cdxgen.kosi.kir.KirWriter
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Files
import java.nio.file.Path

/**
 * The `kir dump` pipeline (P2 gate): the resolved tier's discovery,
 * classpath resolution and JDK attachment feeding [KirLowering], validated
 * and written by [KirWriter]. A dump whose CFG validates dirty is an error,
 * not a best-effort text file.
 */
object KirDumper {

    fun dump(root: Path, options: AnalyzeOptions): String {
        val (text, warnings) = dumpWithWarnings(root, options)
        for (message in warnings) {
            System.err.println("kosi: kir dump: $message")
        }
        return text
    }

    fun dumpWithWarnings(root: Path, options: AnalyzeOptions): Pair<String, List<String>> {
        require(options.backend == Backend.RESOLVED) { "kir dump lowers the resolved tier only" }
        val discovery = ProjectDiscovery.discover(root)
        val (versionedModules, _, _) = Analyzer.discoverVersionPolicy(root, discovery.modules, options)
        val collected = SourceCollector.collect(root, versionedModules.map { it.module })
        val moduleDirs = versionedModules.map { vm ->
            root.resolve(vm.module.modulePath).toAbsolutePath().normalize()
        }
        val resolution = ClasspathResolver.resolve(
            root = root,
            explicitJars = options.classpath.map { Path.of(it) },
            explicitFile = options.classpathFile?.let { Path.of(it) },
            moduleDirs = moduleDirs,
        )
        val jdkResolution = JdkModules.resolve(options.jdkHome?.let { Path.of(it) })
        val jdkHome = when (val resolution = jdkResolution) {
            is JdkModules.Resolution.Found -> resolution.home
            is JdkModules.Resolution.Invalid -> throw Analyzer.AnalysisException(resolution.message)
            is JdkModules.Resolution.NotFound -> null
        }
        val stdlibJar = Analyzer.stdlibJarForDump()
        val libraries = resolution.jars.map { ResolvedPlan.ResolvedLibrary(it.jar, it.purl) } +
            listOfNotNull(stdlibJar?.let { ResolvedPlan.ResolvedLibrary(it, "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib") })
        val effectiveVersion = versionedModules.maxOfOrNull { CompilerInfo.bandRank(it.effective) }
        val plan = ResolvedPlan(
            sourceFiles = collected.map { it.absolutePath },
            languageVersion = effectiveVersion?.let { CompilerInfo.versionAtRank(it) },
            apiVersion = null,
            libraries = libraries,
            jdkHome = jdkHome?.takeIf { Files.isDirectory(it) },
        )
        val env = try {
            AnalysisEnvironment.createForResolved(plan)
        } catch (t: Throwable) {
            throw Analyzer.AnalysisException(
                "kir dump: the analysis session could not be created " +
                    "(${t::class.simpleName}: ${t.message?.take(200) ?: "no message"})",
                t,
            )
        }
        env.use { env ->
            val workspace = env.session.modulesWithFiles.keys
                .filterIsInstance<org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule>()
                .firstOrNull() ?: throw Analyzer.AnalysisException("kir dump: session built no workspace module")
            val lowered = KirLowering.lower(env, workspace)
            val module = KirModule(lowered.functions.sortedBy { it.canonicalName })
            val findings = KirValidator.validate(module)
            if (findings.isNotEmpty()) {
                throw Analyzer.AnalysisException(
                    "kir dump: CFG validation failed: " +
                        findings.take(10).joinToString("; ") { "${it.function} ${it.block}: ${it.problem}" },
                )
            }
            val warnings = buildList {
                if (jdkResolution is JdkModules.Resolution.NotFound) {
                    add(jdkResolution.tried)
                }
                if (lowered.failures.isNotEmpty()) {
                    add(
                        "lowering failures: " + lowered.failures.entries.sortedWith(compareBy({ it.key }, { it.value }))
                            .joinToString(", ") { "${it.key}=${it.value}" },
                    )
                }
            }
            return KirWriter.write(module) to warnings
        }
    }
}
