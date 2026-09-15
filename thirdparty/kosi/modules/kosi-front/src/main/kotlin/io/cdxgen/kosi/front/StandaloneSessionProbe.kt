package io.cdxgen.kosi.front

import org.jetbrains.kotlin.analysis.api.analyze
import org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule
import java.nio.file.Files

/**
 * Reports whether the resolved front end can actually run in this
 * distribution: a real one-module standalone Analysis API session is built
 * over a temporary source root and one declaration is resolved through it.
 * Since P1 amended the dependency allowlist (02-ARCHITECTURE.md §1) to the
 * KSP2 working set — the unrelocated `-for-ide` artifacts, the unrelocated
 * IntelliJ platform and their third-party libraries — this is the substrate
 * both tiers run on, and the probe doubles as the self-check the version
 * command publishes.
 */
object StandaloneSessionProbe {

    data class ProbeResult(val available: Boolean, val detail: String)

    /**
     * Whether the SYNTAX backend can run here. Since P1 both tiers share one
     * session substrate, so "syntax works" is no longer free: it is a claim
     * that has to be checked. `kosi version` used to print the constant
     * string "available" for this backend, which in a native image where the
     * session cannot be created at all was simply false.
     */
    fun probeSyntax(): ProbeResult =
        try {
            AnalysisEnvironment.createForSyntax().use { env ->
                val file = env.parseFile("package kosi.probe\n\nclass Probe\n")
                val parsed = file.declarations.firstOrNull()?.name == "Probe"
                ProbeResult(
                    available = parsed,
                    detail = if (parsed) {
                        "parsed a declaration through the shared session"
                    } else {
                        "unavailable: session created but parsing produced no declaration"
                    },
                )
            }
        } catch (t: Throwable) {
            if (System.getenv("KOSI_PROBE_TRACE") != null) t.printStackTrace()
            ProbeResult(false, "unavailable: ${t::class.simpleName}: ${t.message?.take(160)}")
        }

    fun probe(): ProbeResult {
        return try {
            val dir = Files.createTempDirectory("kosi-probe")
            Files.writeString(
                dir.resolve("Probe.kt"),
                "package kosi.probe\n\nclass Probe : Runnable {\n    override fun run() {}\n}\n",
            )
            // The probe claims the resolved backend works HERE, and the
            // java.* half of that claim needs a JDK: resolved from the same
            // sources the analyzer uses (flag, java.home, JAVA_HOME). When
            // none names a JDK the session itself is still probed, but the
            // detail says the JDK half was not exercised rather than
            // claiming coverage the binary does not have.
            val jdkResolution = JdkModules.resolve(null)
            val plan = ResolvedPlan(
                sourceFiles = listOf(dir.resolve("Probe.kt")),
                languageVersion = null,
                apiVersion = null,
                libraries = emptyList(),
                jdkHome = (jdkResolution as? JdkModules.Resolution.Found)?.home,
            )
            AnalysisEnvironment.createForResolved(plan).use { env ->
                val module = env.session.modulesWithFiles.keys
                    .filterIsInstance<KaSourceModule>()
                    .firstOrNull() ?: return ProbeResult(false, "unavailable: session built no module")
                var resolved = false
                var runnableResolved = false
                analyze(module) {
                    val file = env.session.modulesWithFiles[module]
                        ?.filterIsInstance<org.jetbrains.kotlin.psi.KtFile>()
                        ?.firstOrNull() ?: return@analyze
                    val declaration = file.declarations.firstOrNull()
                    resolved = declaration != null && declaration.symbol != null
                    if (jdkResolution is JdkModules.Resolution.Found) {
                        // A JDK is attached: "resolved backend available"
                        // includes java.* symbols, so resolve the Probe's
                        // supertype through the SDK module — the same
                        // KaClassType shape ResolvedAnalyzer publishes in
                        // supertypes[]. An error type (no JDK visible)
                        // yields no classId and must not report available:
                        // the R40 shape, a status that is not measured.
                        val ktClass = declaration as? org.jetbrains.kotlin.psi.KtClass
                        val symbol = ktClass?.symbol
                        runnableResolved =
                            symbol is org.jetbrains.kotlin.analysis.api.symbols.KaClassSymbol &&
                            symbol.superTypes.any {
                                (it as? org.jetbrains.kotlin.analysis.api.types.KaClassType)
                                    ?.classId?.asSingleFqName()?.asString() == "java.lang.Runnable"
                            }
                    }
                }
                return when {
                    !resolved ->
                        ProbeResult(false, "unavailable: session built but resolution returned no symbol")
                    jdkResolution is JdkModules.Resolution.Found && !runnableResolved -> ProbeResult(
                        false,
                        "unavailable: JDK ${jdkResolution.home} is attached but java.lang.Runnable " +
                            "does not resolve through the SDK module",
                    )
                    jdkResolution is JdkModules.Resolution.NotFound -> ProbeResult(
                        true,
                        "standalone session built and resolved a declaration; " +
                            jdkResolution.tried + " — java.* symbols will resolve as unresolved",
                    )
                    else ->
                        ProbeResult(true, "standalone session built and resolved a declaration and a JDK supertype")
                }
            }
        } catch (t: Throwable) {
            if (System.getenv("KOSI_PROBE_TRACE") != null) t.printStackTrace()
            val cause = generateSequence(t as Throwable?) { it.cause }
                .firstOrNull { it is NoClassDefFoundError || it is ClassNotFoundException }
            ProbeResult(
                available = false,
                detail = cause?.let { "unavailable: ${it.message}" } ?: "unavailable: ${t.message}",
            )
        }
    }
}
