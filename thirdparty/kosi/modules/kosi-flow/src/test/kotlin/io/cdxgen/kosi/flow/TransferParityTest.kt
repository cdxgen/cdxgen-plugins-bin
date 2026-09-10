package io.cdxgen.kosi.flow

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * kosi carries TWO transfer functions over the same KIR: `TaintEngine`'s,
 * which reports slices over `TaintFact`, and `SummaryAnalysis`'s, which
 * computes parameter summaries over `SummaryFact`. They are line-for-line
 * parallel — the same joins, the same field and index handling, the same
 * unknown-call default — and they MUST agree, or a summary describes a
 * function differently from the engine that consumes it.
 *
 * Nothing enforced that. R62 is what the drift looks like in miniature: the
 * per-fact provenance R54 introduced was applied to the joins in both files
 * and to the index and unknown-call merges in NEITHER, and only a reader
 * comparing the two files by eye would have noticed.
 *
 * Unifying the two is the real fix and is a phase of its own. Until then
 * this pins the cheapest observable that catches the likeliest drift: an
 * opcode one transfer learned and the other did not. A new `KirIns` handled
 * in one file and forgotten in the other fails here, naming the opcode.
 */
class TransferParityTest {

    private fun moduleFile(relative: String): Path {
        // Gradle runs tests with the module directory as the working dir;
        // fall back to walking up so the test also runs from the repo root.
        var dir: Path? = Path.of("").toAbsolutePath()
        while (dir != null) {
            val candidate = dir.resolve(relative)
            if (Files.isRegularFile(candidate)) return candidate
            dir = dir.parent
        }
        error("cannot find $relative from ${Path.of("").toAbsolutePath()}")
    }

    /** The `is Kir…` cases of the named file's `transfer` function. */
    private fun handledOpcodes(relative: String): Set<String> {
        val text = Files.readString(moduleFile(relative))
        val start = text.indexOf("    private fun transfer(")
        assertTrue(start >= 0, "no transfer function in $relative")
        val end = text.indexOf("\n    private fun ", start + 10).let { if (it < 0) text.length else it }
        return Regex("""is (Kir\w+)""").findAll(text.substring(start, end)).map { it.groupValues[1] }.toSet()
    }

    @Test
    fun bothTransfersHandleTheSameOpcodes() {
        val base = "modules/kosi-flow/src/main/kotlin/io/cdxgen/kosi/flow"
        val engine = handledOpcodes("$base/TaintEngine.kt")
        val summary = handledOpcodes("$base/Summaries.kt")
        assertTrue(engine.size > 15, "the extraction found only ${engine.size} opcodes — it stopped matching")
        assertEquals(
            emptyList(),
            (engine - summary).sorted(),
            "the reporting engine handles opcodes the summary analysis ignores: a summary will disagree with its caller",
        )
        assertEquals(
            emptyList(),
            (summary - engine).sorted(),
            "the summary analysis handles opcodes the reporting engine ignores",
        )
    }
}
