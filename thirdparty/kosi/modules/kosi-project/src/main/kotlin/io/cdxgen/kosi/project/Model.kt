package io.cdxgen.kosi.project

/**
 * A discovered module: a Gradle/Maven project, a Kotlin source set (KMP or
 * Android variant), or a plain source tree. All paths are relative to the
 * analysis root with POSIX separators; build files are parsed as text and
 * never executed (02-ARCHITECTURE.md §3).
 */
data class DiscoveredModule(
    val name: String,
    val modulePath: String,
    val platform: String,
    val workspaceMember: String,
    val sourceRoots: List<String>,
    val declaredLanguageVersion: String?,
    val declaredApiVersion: String?,
    val jvmTarget: String?,
    val purl: String,
) {
    companion object {
        const val PLATFORM_JVM = "jvm"
        const val PLATFORM_ANDROID = "android"
        const val PLATFORM_JS = "js"
        const val PLATFORM_NATIVE = "native"
        const val PLATFORM_COMMON = "common"
    }
}

data class DiscoveryResult(
    val modules: List<DiscoveredModule>,
    val buildSystem: String,
)
