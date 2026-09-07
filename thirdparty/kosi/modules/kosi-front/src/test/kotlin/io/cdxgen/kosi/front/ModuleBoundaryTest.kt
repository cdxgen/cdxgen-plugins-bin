package io.cdxgen.kosi.front

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Hard rule from 02-ARCHITECTURE.md §2: only kosi-front may reference the
 * Analysis API, PSI/FIR or the (relocated) IntelliJ platform types. This test
 * scans every other module's sources and fails the build on a violation, so
 * an Analysis API breaking change stays a one-module repair.
 */
class ModuleBoundaryTest {

    private val modulesDir = Path.of(System.getProperty("user.dir")).parent!!

    private val forbidden = listOf(
        "org.jetbrains.kotlin.analysis.api.",
        "org.jetbrains.kotlin.psi.",
        "org.jetbrains.kotlin.fir.",
        "org.jetbrains.kotlin.com.intellij.",
        "com.intellij.",
        "org.jetbrains.kotlin.cli.",
        "org.jetbrains.kotlin.config.",
        "org.jetbrains.kotlin.K1Deprecation",
    )

    @Test
    fun onlyKosiFrontTouchesCompilerTypes() {
        val violations = mutableListOf<String>()
        Files.walk(modulesDir).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { p -> p.fileName.toString().endsWith(".kt") }
                .filter { p -> !p.toString().contains("/kosi-front/") }
                .forEach { p ->
                    for (line in Files.readString(p).lines()) {
                        val trimmed = line.trim()
                        val isImport = trimmed.startsWith("import ")
                        val isFullyQualified = forbidden.any { trimmed.contains(it) }
                        if (isImport && forbidden.any { trimmed.contains(it) } || isFullyQualified && trimmed.startsWith("//").not() && isImport) {
                            violations.add("${p.fileName}: $trimmed")
                        }
                    }
                }
        }
        assertTrue(violations.isEmpty(), "compiler-type imports outside kosi-front:\n" + violations.joinToString("\n"))
    }
}
