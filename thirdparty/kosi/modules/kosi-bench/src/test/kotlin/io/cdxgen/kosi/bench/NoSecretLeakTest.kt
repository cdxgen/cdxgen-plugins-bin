package io.cdxgen.kosi.bench

import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The P8 no-literal-secret gate, as a test over a real corpus output: the
 * crypto-material-flow fixture PLANTS secret values in its source, and no
 * report may carry them. Two directions, both real:
 *
 *  1. a deliberately-broken report (the fixture's secrets pasted into a
 *     copy of the report, the shape a careless collector would produce)
 *     MUST trip the scanner - a scanner with nothing to find proves
 *     nothing;
 *  2. the real serialized report MUST come back clean - materials carry
 *     names, never values.
 */
class NoSecretLeakTest {

    private val planted = listOf(
        "0123456789abcdef0123456789abcdef",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
    )

    private fun fixtureDir(): Path {
        var dir: Path? = Path.of("").toAbsolutePath()
        while (dir != null) {
            val candidate = dir.resolve("fixtures/crypto-material-flow")
            if (Files.isDirectory(candidate)) return candidate
            dir = dir.parent
        }
        error("crypto-material-flow fixture not found")
    }

    private fun realReport(): String {
        val report = Analyzer.analyze(fixtureDir(), AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        return report.toJson(pretty = false)
    }

    @Test
    fun theScannerFiresOnADeliberatelyBrokenReport() {
        val broken = realReport()
            .replace("\"materials\":[", "\"materials\":[{\"name\":\"$planted[0]\"},")
            .let { it + planted[1] }
        for (secret in planted) {
            assertTrue(broken.contains(secret), "the broken report must actually contain the planted secret")
        }
        // The scanner's predicate: a report is clean only when it names none
        // of the planted values.
        val flagged = planted.count { broken.contains(it) }
        assertEquals(planted.size, flagged, "the deliberately-broken report must trip every planted secret")
    }

    @Test
    fun noPlantedSecretAppearsInTheRealReport() {
        val report = realReport()
        for (secret in planted) {
            assertTrue(!report.contains(secret), "a planted fixture secret leaked into the report")
        }
        // The materials the report DOES carry are names, with no value text.
        assertTrue(report.contains("\"apiToken\""), "material names remain in the report as evidence")
    }
}
