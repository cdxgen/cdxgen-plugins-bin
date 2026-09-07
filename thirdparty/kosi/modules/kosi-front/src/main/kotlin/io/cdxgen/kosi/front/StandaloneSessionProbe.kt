package io.cdxgen.kosi.front

import org.jetbrains.kotlin.analysis.api.standalone.buildStandaloneAnalysisAPISession

/**
 * Reports whether the Analysis API standalone session can actually be built
 * in this distribution. The declared `analysis-api-*-for-ide` artifacts
 * carry the Analysis API classes, but building a session also needs the
 * IntelliJ platform core classes (com.intellij.core/mock/...), which the
 * dependency allowlist does not provide in unrelocated form —
 * kotlin-compiler-embeddable shades them under
 * org.jetbrains.kotlin.com.intellij. KSP2 solves this by fat-jarring 6000+
 * platform classes; kosi records the gap as a `resolve-capability` diagnostic
 * instead of pretending resolution works. Closing the gap is a resolved-tier
 * (P2) decision recorded in docs/KOSI.md.
 */
object StandaloneSessionProbe {

    data class ProbeResult(val available: Boolean, val detail: String)

    fun probe(): ProbeResult {
        return try {
            buildStandaloneAnalysisAPISession {
                buildKtModuleProvider {
                    // No modules: the probe only measures whether the session
                    // infrastructure can be constructed in this distribution.
                }
            }
            ProbeResult(true, "standalone session built")
        } catch (t: Throwable) {
            val cause = generateSequence(t as Throwable?) { it.cause }
                .firstOrNull { it is NoClassDefFoundError || it is ClassNotFoundException }
            ProbeResult(
                available = false,
                detail = cause?.let { "unavailable: ${it.message}" } ?: "unavailable: ${t.message}",
            )
        }
    }
}
