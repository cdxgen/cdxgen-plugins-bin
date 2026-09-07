package io.cdxgen.kosi.front

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Hard rule from 02-ARCHITECTURE.md §2: only kosi-front may reference the
 * Analysis API, PSI/FIR or the (relocated) IntelliJ platform types. This test
 * scans every other module's sources — imports AND fully-qualified references
 * in code bodies, since an inline `org.jetbrains.kotlin.psi.KtFile` escapes an
 * import-only check — and fails the build on a violation, so an Analysis API
 * breaking change stays a one-module repair.
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
                    for ((index, raw) in Files.readString(p).lines().withIndex()) {
                        val line = raw.trim()
                        // Comment lines may name the forbidden types (this
                        // file's own KDoc does); code may not.
                        if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) continue
                        val hit = forbidden.firstOrNull { line.contains(it) }
                        if (hit != null) {
                            violations.add("${p.fileName}:${index + 1}: $hit -> $line")
                        }
                    }
                }
        }
        assertTrue(violations.isEmpty(), "compiler-type references outside kosi-front:\n" + violations.joinToString("\n"))
    }

    /**
     * The scanner itself must be able to fail: a synthetic violation —
     * including the fully-qualified form the previous import-only check
     * missed — is detected.
     */
    @Test
    fun theScannerDetectsFullyQualifiedReferences() {
        val offenders = listOf(
            "val f: org.jetbrains.kotlin.psi.KtFile = make()",
            "import org.jetbrains.kotlin.psi.KtFile",
            "val env = com.intellij.openapi.Disposer.newDisposable()",
        )
        val clean = listOf(
            "// talks about org.jetbrains.kotlin.psi freely",
            "val psi = frontEnd.parseFile(text)",
        )
        for (line in offenders) {
            assertTrue(forbidden.any { line.contains(it) }, "expected a hit for: $line")
        }
        for (line in clean) {
            val code = line.trim()
            if (code.startsWith("//")) continue
            assertTrue(forbidden.none { code.contains(it) }, "unexpected hit for: $line")
        }
    }
}
