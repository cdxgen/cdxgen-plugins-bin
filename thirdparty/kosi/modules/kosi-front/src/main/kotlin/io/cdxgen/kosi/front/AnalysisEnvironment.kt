package io.cdxgen.kosi.front

import com.intellij.openapi.Disposable
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.psi.PsiErrorElement
import com.intellij.psi.PsiRecursiveElementWalkingVisitor
import org.jetbrains.kotlin.analysis.api.projectStructure.KaModule
import org.jetbrains.kotlin.analysis.api.standalone.StandaloneAnalysisAPISession
import org.jetbrains.kotlin.analysis.api.standalone.buildStandaloneAnalysisAPISession
import org.jetbrains.kotlin.analysis.project.structure.builder.KtModuleProviderBuilder
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtLibraryModule
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtSdkModule
import org.jetbrains.kotlin.analysis.project.structure.builder.buildKtSourceModule
import org.jetbrains.kotlin.config.ApiVersion
import org.jetbrains.kotlin.config.LanguageVersion
import org.jetbrains.kotlin.config.LanguageVersionSettings
import org.jetbrains.kotlin.config.LanguageVersionSettingsImpl
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtPsiFactory
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
            create { builder -> builder.platform = JvmPlatforms.defaultJvmPlatform }

        /**
         * Builds the environment with the resolved tier's module provider over
         * the plan the caller derived from project discovery and offline
         * classpath resolution.
         */
        fun createForResolved(plan: ResolvedPlan): AnalysisEnvironment =
            create { builder -> ModuleProviderFactory.populate(builder, plan) }

        private fun create(configure: (KtModuleProviderBuilder) -> Unit): AnalysisEnvironment {
            val disposable = Disposer.newDisposable()
            val session = buildStandaloneAnalysisAPISession(disposable) {
                buildKtModuleProvider(configure)
            }
            return AnalysisEnvironment(session, disposable)
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

    fun populate(builder: KtModuleProviderBuilder, plan: ResolvedPlan) {
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

        val sourceModule = builder.buildKtSourceModule {
            platform = JvmPlatforms.defaultJvmPlatform
            moduleName = WORKSPACE_MODULE_NAME
            for (file in plan.sourceFiles.sorted()) {
                VirtualFileManager.getInstance().refreshAndFindFileByNioPath(file)
                    ?.let { addSourceVirtualFile(it) }
            }
            languageVersionSettings = languageVersionSettings(plan.languageVersion, plan.apiVersion)
            for (library in libraries) addRegularDependency(library)
            sdk?.let { addRegularDependency(it) }
        }
        builder.addModule(sourceModule)
    }

    private fun languageVersionSettings(language: String?, api: String?): LanguageVersionSettings {
        val lang = language?.let {
            LanguageVersion.fromVersionString(it) ?: LanguageVersion.fromFullVersionString(it)
        } ?: LanguageVersion.LATEST_STABLE
        val apiVersion = api?.let { ApiVersion.parse(it) } ?: ApiVersion.parse(lang.versionString) ?: ApiVersion.LATEST
        return LanguageVersionSettingsImpl(lang, apiVersion)
    }
}
