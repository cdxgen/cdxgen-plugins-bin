package io.cdxgen.kosi.cli

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Argument-parser contract. Negative cases first: an unknown flag and a
 * dropped value are usage errors, because an option the report echoes but did
 * not apply is worse than no option at all.
 */
class DefaultsFromParserTest {

    private val known = setOf("dir", "out", "roots", "backend", "pretty", "help", "include-stdlib")
    private val booleans = setOf("pretty", "help", "include-stdlib")

    private fun parse(vararg args: String) = ParsedArgs.parse(args.toList(), known, booleans)

    @Test
    fun unknownFlagIsUsageError() {
        val e = assertFailsWith<UsageException> { parse("--bogus", "x") }
        assertTrue(e.message!!.contains("unknown flag --bogus"))
    }

    @Test
    fun missingValueIsUsageError() {
        assertFailsWith<UsageException> { parse("--dir") }
    }

    @Test
    fun singleDashFlagsRejected() {
        assertFailsWith<UsageException> { parse("-dir", "x") }
    }

    @Test
    fun booleanFlagRejectsAnInlineNonBoolean() {
        assertFailsWith<UsageException> { parse("--pretty=sometimes") }
    }

    @Test
    fun repeatedFlagsKeepEveryOccurrence() {
        // The defect this guards: an implementation that indexed occurrences
        // from the second one reported only the last root, so `--roots main
        // --roots tests` silently analysed the default roots.
        assertEquals(listOf("main", "tests"), parse("--roots", "main", "--roots", "tests").values("roots"))
        assertEquals(listOf("tests"), parse("--roots", "tests").values("roots"))
        assertEquals(emptyList(), parse("--dir", ".").values("roots"))
    }

    @Test
    fun repeatedSingleValueFlagTakesTheLast() {
        assertEquals("b", parse("--dir", "a", "--dir", "b").value("dir"))
    }

    @Test
    fun flagValueAndFlagEqualsValueAgree() {
        assertEquals(parse("--dir", "some/path").value("dir"), parse("--dir=some/path").value("dir"))
    }

    @Test
    fun booleansDefaultAndNegate() {
        assertTrue(parse("--include-stdlib").bool("include-stdlib", default = false))
        assertFalse(parse("--no-include-stdlib").bool("include-stdlib", default = true))
        assertTrue(parse().bool("include-stdlib", default = true))
    }

    @Test
    fun unknownBackendIsUsageError() {
        assertEquals(ExitCodes.USAGE, Main.run(arrayOf("analyze", "--backend", "mir", "--dir", ".")))
    }

    @Test
    fun resolvedBackendRejectedInPhase0() {
        // Rejected as a usage error WITH the phase-0 explanation, never as a
        // silent degrade to the syntax tier.
        assertEquals(ExitCodes.USAGE, Main.run(arrayOf("analyze", "--backend", "resolved", "--dir", ".")))
    }

    @Test
    fun unknownAnalyzeFlagIsUsageErrorEndToEnd() {
        assertEquals(ExitCodes.USAGE, Main.run(arrayOf("analyze", "--dir", ".", "--nope", "1")))
    }
}
