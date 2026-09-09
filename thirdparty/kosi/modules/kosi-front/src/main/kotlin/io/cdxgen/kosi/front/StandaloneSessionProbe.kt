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
                "package kosi.probe\n\nclass Probe\n",
            )
            val plan = ResolvedPlan(
                sourceFiles = listOf(dir.resolve("Probe.kt")),
                languageVersion = null,
                apiVersion = null,
                libraries = emptyList(),
                jdkHome = null,
            )
            AnalysisEnvironment.createForResolved(plan).use { env ->
                val module = env.session.modulesWithFiles.keys
                    .filterIsInstance<KaSourceModule>()
                    .firstOrNull() ?: return ProbeResult(false, "unavailable: session built no module")
                var resolved = false
                analyze(module) {
                    val file = env.session.modulesWithFiles[module]
                        ?.filterIsInstance<org.jetbrains.kotlin.psi.KtFile>()
                        ?.firstOrNull() ?: return@analyze
                    val declaration = file.declarations.firstOrNull()
                    resolved = declaration != null && declaration.symbol != null
                }
                ProbeResult(
                    available = resolved,
                    detail = if (resolved) {
                        "standalone session built and resolved a declaration"
                    } else {
                        "unavailable: session built but resolution returned no symbol"
                    },
                )
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
