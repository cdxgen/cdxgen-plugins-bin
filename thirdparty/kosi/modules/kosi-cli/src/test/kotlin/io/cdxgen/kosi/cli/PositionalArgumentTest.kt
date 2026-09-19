package io.cdxgen.kosi.cli

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * P24 review: `kosi analyze /some/project` analysed the WORKING DIRECTORY.
 *
 * The parser collected positional arguments into a list no command ever
 * read, so a path given the way every other CLI accepts one was dropped in
 * silence and `--dir`'s default of `.` took over. The output was a valid,
 * deterministic, internally consistent report about a tree the caller never
 * named — the worst shape a wrong answer can take, and the explanation for
 * part 3's "429 files" observation and for the wrong baseline published in
 * 09-PRECISION.md §1.
 *
 * The rule this pins is the one the flag vocabulary already follows: an
 * argument the tool cannot honour is a usage error (exit 2), never a
 * silently dropped one.
 */
class PositionalArgumentTest {

    private fun parse(args: List<String>) = ParsedArgs.parse(
        args,
        known = setOf("dir", "pretty"),
        booleans = setOf("pretty"),
    )

    @Test
    fun aBarePathIsARefusalAndNamesTheFlagThatTakesIt() {
        val parsed = parse(listOf("/some/project", "--pretty"))
        val failure = assertFailsWith<UsageException> {
            parsed.requireNoPositionals("analyze", "--dir <path>")
        }
        assertTrue(
            failure.message!!.contains("/some/project") && failure.message!!.contains("--dir"),
            "the refusal must name the argument it cannot honour and the flag that takes it: ${failure.message}",
        )
    }

    @Test
    fun theFlagFormIsUntouched() {
        val parsed = parse(listOf("--dir", "/some/project"))
        parsed.requireNoPositionals("analyze", "--dir <path>")
        assertEquals("/some/project", parsed.value("dir"))
    }

    @Test
    fun everythingAfterADoubleDashIsPositionalAndThereforeARefusalToo() {
        val parsed = parse(listOf("--dir", "/a", "--", "/b"))
        assertFailsWith<UsageException> { parsed.requireNoPositionals("analyze", "--dir <path>") }
    }
}
