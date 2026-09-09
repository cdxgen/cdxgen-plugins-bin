package io.cdxgen.kosi.front

import com.intellij.openapi.Disposable
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.psi.PsiErrorElement
import com.intellij.psi.PsiRecursiveElementWalkingVisitor
import org.jetbrains.kotlin.analysis.api.standalone.StandaloneAnalysisAPISession
import org.jetbrains.kotlin.analysis.api.standalone.buildStandaloneAnalysisAPISession
import org.jetbrains.kotlin.analysis.project.structure.builder.KtModuleProviderBuilder
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtLibraryModule
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtSdkModule
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtSourceModule
import com.intellij.psi.PsiFile
import org.jetbrains.kotlin.K1Deprecation
import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys
import org.jetbrains.kotlin.cli.common.messages.MessageCollector
import org.jetbrains.kotlin.config.ApiVersion
import org.jetbrains.kotlin.config.CommonConfigurationKeys
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.config.LanguageVersion
import org.jetbrains.kotlin.config.LanguageVersionSettings
import org.jetbrains.kotlin.config.LanguageVersionSettingsImpl
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtPsiFactory
import java.nio.file.Files
import java.nio.file.Path

/**
 * The analysis environment: one standalone Analysis API session per analysis
 * run (02-ARCHITECTURE.md §3). The session owns the unrelocated IntelliJ
 * platform application, the PSI factory used by both tiers, and — for the
 * resolved tier — the module provider built over the discovered project.
 *
 * The syntax tier uses only [parseFile]: parsing needs no classpath and no
 * JDK. The resolved tier additionally lays out KaSourceModules over the
 * discovered modules, their offline-resolved library jars and the JDK module
 * (see [ModuleProviderFactory]).
 *
 * The session registers application-level services and spawns worker threads,
 * so it must be disposed before the process analyses the next project —
 * `close()` disposes the whole tree under the run's Disposable.
 */
class AnalysisEnvironment private constructor(
    val session: StandaloneAnalysisAPISession,
    private val disposable: Disposable,
    /**
     * Collected source files the session's VFS would not open, so the caller
     * can diagnose the gap instead of quietly analysing fewer files than
     * `files[]` advertises.
     */
    val droppedSourceFiles: Int = 0,
) : AutoCloseable {

    val project = session.project

    private val psiFactory = KtPsiFactory(project, markGenerated = false)

    fun parseFile(text: String): KtFile = psiFactory.createFile(text)

    fun collectParseErrors(file: KtFile): List<PsiErrorElement> {
        val errors = mutableListOf<PsiErrorElement>()
        file.accept(object : PsiRecursiveElementWalkingVisitor() {
            override fun visitElement(element: com.intellij.psi.PsiElement) {
                if (element is PsiErrorElement) {
                    errors.add(element)
                }
                super.visitElement(element)
            }
        })
        return errors
    }

    override fun close() {
        Disposer.dispose(disposable)
    }

    companion object {
        /** A parse-only environment: the provider registers no modules. */
        fun createForSyntax(): AnalysisEnvironment =
            create { builder ->
                builder.platform = JvmPlatforms.defaultJvmPlatform
                0
            }

        /**
         * Builds the environment with the resolved tier's module provider over
         * the plan the caller derived from project discovery and offline
         * classpath resolution.
         */
        fun createForResolved(plan: ResolvedPlan): AnalysisEnvironment =
            create { builder -> ModuleProviderFactory.populate(builder, plan) }

        /**
         * The K1 application environment is created ONCE per process, with a
         * configuration WE control. This matters in a native image: the stock
         * session builder creates a fresh CompilerConfiguration, and the K1
         * bootstrap (registerApplicationExtensionPointsAndExtensionsFrom)
         * then resolves extension points through a jar-location lookup of
         * `CompilerSystemProperties.class` — `PathManager.urlToFile` cannot
         * extract a file path from an image `resource:` URL, so the builder
         * can never construct. `getOrCreateApplicationEnvironment` caches its
         * result in a static: seeding it here with INTELLIJ_PLUGIN_ROOT
         * pointing at the materialized `kosi-ext/META-INF/extensions`
         * descriptors (the configuration key the 2.4.0 code checks first)
         * means every later session builder reuses the warmed environment and
         * never reaches the lookup. On the JVM the same seeding is harmless —
         * the lookup works there and would find the real jar.
         */
        @OptIn(K1Deprecation::class)
        private val applicationEnvironmentSeed: Any by lazy {
            @OptIn(CompilerConfiguration.Internals::class, K1Deprecation::class)
            val configuration = CompilerConfiguration()
            configuration.put(CommonConfigurationKeys.MESSAGE_COLLECTOR_KEY, MessageCollector.NONE)
            // Always set: the seeded environment never falls back to the
            // jar-location lookup, on any substrate.
            configuration.put(CLIConfigurationKeys.INTELLIJ_PLUGIN_ROOT, materializedExtensionRoot())
            KotlinCoreEnvironment.getOrCreateApplicationEnvironmentForProduction(
                Disposer.newDisposable("kosi application environment seed"),
                configuration,
            )
        }

        private fun create(configure: (KtModuleProviderBuilder) -> Int): AnalysisEnvironment {
            applicationEnvironmentSeed // warm/cached K1 application environment
            val disposable = Disposer.newDisposable()
            var dropped = 0
            val session = buildStandaloneAnalysisAPISession(disposable) {
                // Serialized builtins must resolve against the materialized
                // stdlib jar, not classloader URLs (unusable in images). The
                // platform registers its CLI provider during the builder's
                // construction, so swap the component before anything asks
                // for it (re-registering would be a duplicate-key error).
                val applicationPico = (application as com.intellij.mock.MockComponentManager).picoContainer
                val providerKey = org.jetbrains.kotlin.analysis.decompiler.psi.BuiltinsVirtualFileProvider::class.java.name
                applicationPico.unregisterComponent(providerKey)
                applicationPico.registerComponentInstance(
                    providerKey,
                    KosiBuiltinsVirtualFileProvider(materializedStdlibJar),
                )
                buildKtModuleProvider { dropped = configure(this) }
            }
            return AnalysisEnvironment(session, disposable, dropped)
        }

        /**
         * The shipped kotlin-stdlib jar (kosi-libs resource), materialized
         * ONCE per process and deleted on exit: one copy per session leaks a
         * temp jar for every analysed project.
         */
        private val materializedStdlibJar: java.nio.file.Path by lazy {
            val stream = AnalysisEnvironment::class.java.classLoader.getResourceAsStream("kosi-libs/kotlin-stdlib.jar")
                ?: error("kosi-libs/kotlin-stdlib.jar missing from the distribution")
            val target = Files.createTempFile("kosi-stdlib", ".jar")
            target.toFile().deleteOnExit()
            stream.use { input -> Files.copy(input, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING) }
            target
        }

        /**
         * The compiler's extension descriptors ship as resources (checked in
         * under `kosi-ext/`); they are materialized into a temp directory and
         * the directory CONTAINING META-INF is returned, so the extension
         * points register from real files — no jar-location lookup, which is
         * what breaks inside a native image (`PathManager.urlToFile` cannot
         * extract a path from an image `resource:` URL). Also seeds
         * `idea.home.path` for the platform's PathManager, whose own
         * installation-home derivation fails for a single fat jar or an
         * image.
         */
        private fun materializedExtensionRoot(): String {
            // The mock application schedules one runnable through Swing; in
            // an image the macOS AWT natives are absent, so point the JDK at
            // the no-op toolkit BEFORE anything touches AWT. Set on every
            // substrate (also lets the tracing agent record the reflective
            // instantiation for the image); kosi never renders anything.
            if (System.getProperty(KosiNoopToolkit.Companion.PROPERTY) == null) {
                System.setProperty(KosiNoopToolkit.Companion.PROPERTY, KosiNoopToolkit.Companion.CLASS_NAME)
            }
            val descriptors = listOf(
                "META-INF/extensions/compiler-cli-root.xml",
                "META-INF/extensions/compiler.xml",
            )
            for (name in descriptors) {
                if (javaClass.classLoader.getResourceAsStream("kosi-ext/$name") == null) {
                    error("kosi-ext/$name missing from the distribution")
                }
            }
            val root = Files.createTempDirectory("kosi-extensions")
            for (name in descriptors) {
                val target = root.resolve("kosi-ext/$name")
                Files.createDirectories(target.parent)
                javaClass.classLoader.getResourceAsStream("kosi-ext/$name")!!.use { input ->
                    Files.copy(input, target)
                }
            }
            val extensionRoot = root.resolve("kosi-ext").toString()
            if (System.getProperty("idea.home.path") == null) {
                System.setProperty("idea.home.path", extensionRoot)
            }
            return extensionRoot
        }
    }
}

internal object JvmPlatforms {
    val defaultJvmPlatform: org.jetbrains.kotlin.platform.TargetPlatform by lazy {
        org.jetbrains.kotlin.platform.jvm.JvmPlatforms.defaultJvmPlatform
    }
}

/**
 * Everything the resolved tier needs to lay out the module provider, decided
 * by the caller (Analyzer) in plain paths and strings so no Analysis API type
 * leaks past kosi-front's boundary into report assembly.
 */
data class ResolvedPlan(
    /**
     * Absolute source files — exactly the files SourceCollector produced, so
     * the session's view matches the report's files[] (build/generated trees
     * are excluded by the collector, not re-excluded here).
     */
    val sourceFiles: List<Path>,
    /** The effective language version for the merged workspace module. */
    val languageVersion: String?,
    val apiVersion: String?,
    /** Offline-resolved classpath jars. */
    val libraries: List<ResolvedLibrary>,
    val jdkHome: Path?,
) {
    data class ResolvedLibrary(val jar: Path, val purl: String)
}

/**
 * Lays out the standalone session's module provider from a [ResolvedPlan]:
 * a shared SDK module from the JDK home, one library module per classpath
 * jar (named by purl, so resolution failures are attributable), and ONE
 * source module carrying every workspace source file.
 *
 * Why one merged workspace module: the builder registers dependencies at
 * build time only, so mutually-visible source modules cannot be expressed
 * (a Gradle app depending on a library sibling would not resolve into it).
 * A single module gives every workspace file visibility into every other —
 * the conservative superset the resolved tier wants — while per-module
 * attribution (modulePath, purl, declared versions) remains report-level
 * data carried by fileRelPathByAbsolute, not by the session's module split.
 */
internal object ModuleProviderFactory {

    const val WORKSPACE_MODULE_NAME = "workspace"

    /** Returns the number of source files the VFS would not open. */
    fun populate(builder: KtModuleProviderBuilder, plan: ResolvedPlan): Int {
        builder.platform = JvmPlatforms.defaultJvmPlatform

        val sdk = plan.jdkHome?.let { jdkHome ->
            builder.buildKtSdkModule {
                platform = JvmPlatforms.defaultJvmPlatform
                libraryName = "jdk:$jdkHome"
                addBinaryRootsFromJdkHome(jdkHome, isJre = false)
            }
        }

        val libraries = plan.libraries
            .distinctBy { it.purl }
            .sortedBy { it.purl }
            .map { lib ->
                builder.buildKtLibraryModule {
                    platform = JvmPlatforms.defaultJvmPlatform
                    libraryName = lib.purl
                    addBinaryRoots(listOf(lib.jar))
                }
            }

        var dropped = 0
        val sourceModule = builder.buildKtSourceModule {
            platform = JvmPlatforms.defaultJvmPlatform
            moduleName = WORKSPACE_MODULE_NAME
            for (file in plan.sourceFiles.sorted()) {
                val virtual = VirtualFileManager.getInstance().refreshAndFindFileByNioPath(file)
                if (virtual == null) {
                    // Counted, not skipped silently: files[] would still list
                    // this file while resolution never saw it.
                    dropped++
                } else {
                    addSourceVirtualFile(virtual)
                }
            }
            languageVersionSettings = languageVersionSettings(plan.languageVersion, plan.apiVersion)
            for (library in libraries) addRegularDependency(library)
            sdk?.let { addRegularDependency(it) }
        }
        builder.addModule(sourceModule)
        return dropped
    }

    private fun languageVersionSettings(language: String?, api: String?): LanguageVersionSettings {
        val lang = language?.let {
            LanguageVersion.fromVersionString(it) ?: LanguageVersion.fromFullVersionString(it)
        } ?: LanguageVersion.LATEST_STABLE
        val apiVersion = api?.let { ApiVersion.parse(it) } ?: ApiVersion.parse(lang.versionString) ?: ApiVersion.LATEST
        return LanguageVersionSettingsImpl(lang, apiVersion)
    }
}
