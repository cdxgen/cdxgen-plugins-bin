package io.cdxgen.kosi.front

import org.jetbrains.kotlin.config.ApiVersion
import org.jetbrains.kotlin.config.KotlinCompilerVersion
import org.jetbrains.kotlin.config.LanguageVersion

/**
 * Reads the analysable language-version band from the bundled compiler's own
 * constants at runtime — never hard-coded (08-VERSION-POLICY.md). The
 * built-with compiler version is the ceiling; FIRST_SUPPORTED is the floor;
 * versions below it are clamped with a `kotlin-language-version` diagnostic.
 */
object CompilerInfo {

    data class VersionBand(
        val first: String,
        val firstNonDeprecated: String,
        val latestStable: String,
        val allAccepted: List<String>,
    )

    fun compilerVersion(): String = KotlinCompilerVersion.VERSION

    /**
     * Enumerates the accepted band from the bundled LanguageVersion constants.
     * The test suite analyses a fixture at every value in [allAccepted], so
     * the test grows itself when the pin bumps (08-VERSION-POLICY.md §4).
     */
    fun versionBand(): VersionBand {
        val first = LanguageVersion.FIRST_SUPPORTED
        val firstNonDeprecated = LanguageVersion.FIRST_NON_DEPRECATED
        val latest = LanguageVersion.LATEST_STABLE
        val all = LanguageVersion.entries
            .filter { it >= first && it <= latest }
            .map { it.versionString }
        return VersionBand(
            first = first.versionString,
            firstNonDeprecated = firstNonDeprecated.versionString,
            latestStable = latest.versionString,
            allAccepted = all,
        )
    }

    data class EffectiveVersion(
        val effective: String,
        val clamped: Boolean,
    )

    /**
     * Clamps a module's declared language version into the accepted band.
     * Unknown/absent versions resolve to the latest stable (what the parser
     * actually uses).
     */
    fun clampLanguageVersion(declared: String?): EffectiveVersion {
        val latest = LanguageVersion.LATEST_STABLE
        if (declared == null) return EffectiveVersion(latest.versionString, clamped = false)
        val parsed = LanguageVersion.fromVersionString(declared)
            ?: LanguageVersion.fromFullVersionString(declared)
            ?: return EffectiveVersion(latest.versionString, clamped = false)
        val clamped = when {
            parsed < LanguageVersion.FIRST_SUPPORTED -> LanguageVersion.FIRST_SUPPORTED
            parsed > latest -> latest
            else -> parsed
        }
        return EffectiveVersion(clamped.versionString, clamped = clamped != parsed)
    }

    /**
     * The API version may never exceed the language version; clamp and let
     * the caller diagnose when that happened.
     */
    fun clampApiVersion(declared: String?, language: String): EffectiveVersion {
        val langParsed = LanguageVersion.fromVersionString(language) ?: LanguageVersion.LATEST_STABLE
        if (declared == null) return EffectiveVersion(langParsed.versionString, clamped = false)
        val parsed = ApiVersion.parse(declared) ?: return EffectiveVersion(langParsed.versionString, clamped = false)
        val aboveLanguage = versionAbove(declared, langParsed.versionString)
        val clamped = if (aboveLanguage) langParsed else parsed
        return EffectiveVersion(clamped.versionString, clamped = clamped != parsed)
    }

    /** Dotted-numeric comparison: is [candidate] strictly above [reference]? */
    private fun versionAbove(candidate: String, reference: String): Boolean {
        val c = candidate.split('.').map { it.trim().toIntOrNull() ?: 0 }
        val r = reference.split('.').map { it.trim().toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(c.size, r.size)) {
            val cv = c.getOrElse(i) { 0 }
            val rv = r.getOrElse(i) { 0 }
            if (cv != rv) return cv > rv
        }
        return false
    }

    fun latestStable(): String = LanguageVersion.LATEST_STABLE.versionString

    fun firstSupported(): String = LanguageVersion.FIRST_SUPPORTED.versionString

    /** Ordinal of a version string within the accepted band, for max/min picks. */
    fun bandRank(version: String): Int {
        val parsed = LanguageVersion.fromVersionString(version)
            ?: LanguageVersion.fromFullVersionString(version)
            ?: return -1
        return parsed.ordinal
    }

    /** Inverse of [bandRank] for versions the bundled compiler knows. */
    fun versionAtRank(rank: Int): String? =
        LanguageVersion.entries.firstOrNull { it.ordinal == rank }?.versionString
}
