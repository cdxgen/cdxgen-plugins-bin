package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.JsonWriter
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The report contract promises two machines analysing the same tree produce
 * the same bytes. WHERE the tree is checked out is not part of that tree, so
 * it must not reach the report — and a classpath pin given as a path relative
 * to the analysed directory must resolve against that directory rather than
 * whatever the process's working directory happens to be.
 *
 * the golden gate recorded the pin as an ABSOLUTE path, so every
 * `classpath_file` fixture digested its own checkout location and the gate
 * could only pass in the directory the goldens were generated in.
 */
class ClasspathFileLocationTest {

    private fun project(dir: Path): Path {
        Files.createDirectories(dir.resolve("src/main/kotlin"))
        Files.writeString(
            dir.resolve("src/main/kotlin/App.kt"),
            "package app\n\nfun main() { println(\"hi\") }\n",
        )
        Files.writeString(dir.resolve("classpath.txt"), "# no jars, just a pin that exists\n")
        return dir
    }

    private fun optionsFor(file: String) = AnalyzeOptions(
        backend = Backend.RESOLVED,
        classpathFile = file,
    )

    private fun optionsSection(report: io.cdxgen.kosi.schema.KosiReport): String {
        val w = JsonWriter()
        report.options.writeJson(w)
        return w.render()
    }

    @Test
    fun relativeClasspathFileResolvesAgainstTheAnalysedDirectory() {
        val root = project(Files.createTempDirectory("kosi-cp-relative"))
        // The file exists relative to the ANALYSED dir, and nowhere near the
        // process's working directory — if it were resolved against the CWD
        // the analysis would fail outright with "does not exist".
        val report = Analyzer.analyze(root, optionsFor("classpath.txt"), commit = "test")
        assertEquals("classpath.txt", report.options.classpathFile)
    }

    @Test
    fun theCheckoutLocationDoesNotReachTheOptionsSection() {
        // The same project, the same pin, two different locations on disk:
        // the recorded options must be identical, which is the property the
        // golden gate's `options` digest rests on.
        val first = project(Files.createTempDirectory("kosi-cp-here"))
        val second = project(Files.createTempDirectory("kosi-cp-elsewhere"))
        assertTrue(first != second, "the two checkouts must be distinct locations")

        val a = optionsSection(Analyzer.analyze(first, optionsFor("classpath.txt"), commit = "test"))
        val b = optionsSection(Analyzer.analyze(second, optionsFor("classpath.txt"), commit = "test"))
        assertEquals(a, b, "two checkouts of the same tree must record the same options")
        assertTrue(
            first.toString() !in a && second.toString() !in a,
            "no checkout path may appear in the recorded options: $a",
        )
    }
}
