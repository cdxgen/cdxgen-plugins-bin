package io.cdxgen.kosi.front

import org.jetbrains.kotlin.K1Deprecation
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
        @OptIn(CompilerConfiguration.Internals::class)
        fun create(): PsiEnvironment {
            val configuration = CompilerConfiguration()
            configuration.put(CommonConfigurationKeys.MESSAGE_COLLECTOR_KEY, MessageCollector.NONE)
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
