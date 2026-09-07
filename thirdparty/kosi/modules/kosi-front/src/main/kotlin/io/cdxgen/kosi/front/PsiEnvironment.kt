package io.cdxgen.kosi.front

import org.jetbrains.kotlin.K1Deprecation
import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys
import org.jetbrains.kotlin.config.CommonConfigurationKeys
import org.jetbrains.kotlin.cli.common.messages.MessageCollector
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.com.intellij.openapi.Disposable
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.PsiErrorElement
import org.jetbrains.kotlin.com.intellij.psi.PsiRecursiveElementWalkingVisitor
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtPsiFactory

/**
 * The PSI environment for the syntax backend, built on
 * kotlin-compiler-embeddable's shaded IntelliJ platform (all platform classes
 * live under org.jetbrains.kotlin.com.intellij). One environment per analysis
 * run; parsing needs no classpath and no JDK (02-ARCHITECTURE.md §3, syntax
 * tier).
 *
 * KotlinCoreEnvironment is K1-era API (K1Deprecation) and CompilerConfiguration
 * mutation is marked internal by JetBrains; both opt-ins are deliberate and
 * confined to this file. The K2/FIR path via the Analysis API arrives with the
 * resolved tier.
 */
@OptIn(K1Deprecation::class)
class PsiEnvironment private constructor(
    val environment: KotlinCoreEnvironment,
    private val parentDisposable: Disposable,
) : AutoCloseable {

    val project = environment.project

    private val psiFactory = KtPsiFactory(project, markGenerated = false)

    fun parseFile(text: String): KtFile = psiFactory.createFile(text)

    fun collectParseErrors(file: KtFile): List<PsiErrorElement> {
        val errors = mutableListOf<PsiErrorElement>()
        file.accept(object : PsiRecursiveElementWalkingVisitor() {
            override fun visitElement(element: PsiElement) {
                if (element is PsiErrorElement) {
                    errors.add(element)
                }
                super.visitElement(element)
            }
        })
        return errors
    }

    override fun close() {
        Disposer.dispose(parentDisposable)
    }

    companion object {
        /**
         * In a native image there is no compiler jar on disk, so the
         * environment's extension-point registration (which locates the jar
         * via classloader URLs) cannot work. We ship the compiler's extension
         * descriptors as image resources, materialize them into a temp
         * directory, and point INTELLIJ_PLUGIN_ROOT at it — the documented
         * programmatic-registration path for 05-BUILD-DIST.md's "intellij-core
         * registers extension points via ServiceLoader + XML" pitfall.
         */
        private fun nativeExtensionRoot(): String? {
            if (System.getProperty("org.graalvm.nativeimage.imagecode") == null &&
                System.getProperty("org.graalvm.nativeimage.enabled") == null
            ) {
                return null
            }
            val descriptors = listOf("META-INF/extensions/compiler-cli-root.xml", "META-INF/extensions/compiler.xml")
            for (name in descriptors) {
                if (javaClass.classLoader.getResourceAsStream("kosi-ext/$name") == null) return null
            }
            val root = java.nio.file.Files.createTempDirectory("kosi-extensions")
            for (name in descriptors) {
                val target = root.resolve("kosi-ext/$name")
                java.nio.file.Files.createDirectories(target.parent)
                javaClass.classLoader.getResourceAsStream("kosi-ext/$name")!!.use { input ->
                    java.nio.file.Files.copy(input, target)
                }
            }
            // INTELLIJ_PLUGIN_ROOT expects the directory that CONTAINS META-INF.
            return root.resolve("kosi-ext").toString()
        }

        @OptIn(CompilerConfiguration.Internals::class)
        fun create(): PsiEnvironment {
            val configuration = CompilerConfiguration()
            configuration.put(CommonConfigurationKeys.MESSAGE_COLLECTOR_KEY, MessageCollector.NONE)
            nativeExtensionRoot()?.let {
                configuration.put(CLIConfigurationKeys.INTELLIJ_PLUGIN_ROOT, it)
            }
            val parentDisposable = Disposer.newDisposable()
            val environment = KotlinCoreEnvironment.createForProduction(
                parentDisposable,
                configuration,
                EnvironmentConfigFiles.JVM_CONFIG_FILES,
            )
            return PsiEnvironment(environment, parentDisposable)
        }
    }
}
