package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DiagnosticCodes
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P29's gate: what used to kill the run now degrades with a name.
 *
 * Three defects are pinned here, each with its restore-proof (rule 8):
 *
 *  - **The walk budget.** A file whose syntax nests past
 *    [WalkBudgets.PSI_DEPTH_CAP] is not walked recursively; the report
 *    carries `psi-depth-cap` naming the file and its depth, and the run
 *    completes. Delete the guard and the `psi-depth-cap` assertion below
 *    fails (the big stack would quietly absorb the file, which is exactly
 *    the silent-truncation shape the budget exists to prevent).
 *  - **The big analysis stack.** A file just UNDER the budget — 1,900
 *    nesting levels, measured to overflow a default thread stack at
 *    ~1,250 (P28/P29 measurement) — analyses fully. Remove
 *    `runOnAnalysisStack` and this test dies with the StackOverflowError
 *    that was P28's exit-3.
 *  - **The per-file boundary.** The pathological file and a healthy
 *    sibling in one directory: the sibling's declarations are present in
 *    the same report.
 *
 * The generated fixtures are built in memory here — a 10 KB checked-in
 * twin of the same shape lives in `fixtures/deep-nesting` for the corpus
 * tier; the 100k-level population stays generated, never committed.
 */
class WalkBudgetTest {

    private fun project(sources: Map<String, String>): Path {
        val root = Files.createTempDirectory("kosi-walkbudget-test")
        for ((path, text) in sources) {
            val file = root.resolve(path)
            Files.createDirectories(file.parent)
            file.writeText(text)
        }
        return root
    }

    /** `return s + s + ...` with [terms] terms: one PSI nesting level per term. */
    private fun chain(terms: Int): String = Array(terms) { "s" }.joinToString(" + ")

    private fun deepText(terms: Int): String =
        "package stress\n\nfun deep(s: String): String {\n    return ${chain(terms)}\n}\n"

    private val normalFile = """
        package stress

        class Normal {
            fun ok(x: String): String = x.reversed()
        }
    """.trimIndent()

    @Test
    fun psiDepthMeasureIsIterativeAndMonotone() {
        AnalysisEnvironment.createForSyntax().use { env ->
            val flat = env.parseFile("package t\n\nfun f() = 1\n")
            val nested = env.parseFile("package t\n\nfun f() = (((((((1)))))))\n")
            val flatDepth = WalkBudgets.psiMaxDepth(flat)
            val nestedDepth = WalkBudgets.psiMaxDepth(nested)
            assertTrue(flatDepth in 2..20, "a flat file measures a small depth, got $flatDepth")
            assertTrue(nestedDepth > flatDepth, "nesting must measure deeper: $nestedDepth vs $flatDepth")
        }
    }

    @Test
    fun aFilePastTheWalkBudgetDegradesToANamedDiagnosticAndTheRunCompletes() {
        val root = project(
            mapOf(
                "src/main/kotlin/deep.kt" to deepText(WalkBudgets.PSI_DEPTH_CAP + 100),
                "src/main/kotlin/normal.kt" to normalFile,
            ),
        )
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.SYNTAX), commit = "test")
        val cap = report.diagnostics.filter { it.code == DiagnosticCodes.PSI_DEPTH_CAP }
        assertEquals(1, cap.size, "exactly one psi-depth-cap diagnostic expected: ${report.diagnostics}")
        val namedDepth = Regex("nests (\\d+)").find(cap[0].message)?.groupValues?.get(1)?.toIntOrNull()
        assertTrue(
            cap[0].message.contains("deep.kt") && namedDepth != null && namedDepth > WalkBudgets.PSI_DEPTH_CAP,
            "the diagnostic names the file and a depth past the budget: ${cap[0].message}",
        )
        // The deep file's functions are absent; the sibling's are present.
        val names = report.declarations.map { it.name }
        assertTrue("Normal" in names, "the healthy sibling must be analysed: $names")
        assertTrue("deep" !in names, "the deep file's declarations must be absent: $names")
        assertEquals(2, report.stats.fileCount, "both files stay in files[]")
    }

    @Test
    fun aFileUnderTheWalkBudgetAnalysesFullyOnTheBigStack() {
        // 1,900 terms: ~1,903 PSI levels, under the cap, and measured to
        // overflow any default thread stack (1,250 suffices). This is the
        // restore-proof for runOnAnalysisStack: without it the test dies
        // with P28's exit-3 StackOverflowError.
        val root = project(mapOf("src/main/kotlin/deep.kt" to deepText(1_900)))
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.SYNTAX), commit = "test")
        assertTrue(
            report.diagnostics.none { it.code == DiagnosticCodes.PSI_DEPTH_CAP },
            "a file under the budget must not be capped: ${report.diagnostics}",
        )
        assertEquals(listOf("deep"), report.declarations.map { it.name })
        // The operator usages the walk derives from the chain: ~1,899 `plus`
        // calls — the walk really descended, it did not quietly stop.
        val plus = report.usages.count { it.name == "plus" }
        assertTrue(plus > 1_800, "the chain's operator usages must be walked: $plus")
    }

    @Test
    fun theResolvedTierSkipsTheSameFileWithTheSameDiagnostic() {
        val root = project(
            mapOf(
                "src/main/kotlin/deep.kt" to deepText(WalkBudgets.PSI_DEPTH_CAP + 100),
                "src/main/kotlin/normal.kt" to normalFile,
            ),
        )
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        val cap = report.diagnostics.filter { it.code == DiagnosticCodes.PSI_DEPTH_CAP }
        // One from ResolvedAnalyzer's walk, one from KirLowering's — both
        // passes guard the same tree independently.
        assertTrue(cap.size >= 1, "the resolved tier must name the capped file: ${report.diagnostics}")
        assertTrue(cap.all { it.message.contains("deep.kt") }, "every cap diagnostic names deep.kt")
        val names = report.declarations.map { it.name }
        assertTrue("Normal" in names, "the healthy sibling must be analysed: $names")
        assertTrue("deep" !in names, "the deep file's declarations must be absent: $names")
    }
}
