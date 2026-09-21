package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * What the source-coverage denominator counts.
 *
 * A source ROOT is a main source root, so a repository's test files are
 * present but never sought. Counting them against discovery makes a project
 * with a large test suite look exactly like one whose modules were dropped
 * — and those are opposite facts, which is the whole reason the ratio
 * exists. Measured on kotlinx.coroutines: 651 of its 1 061 files are tests,
 * so the raw ratio reads 0.54 where discovery of the files a root could
 * hold is 0.97.
 *
 * Both numbers stay published; only the one the diagnostic reads changes.
 */
class SourceCoverageDenominatorTest {

    private val tmp: Path = Files.createTempDirectory("kosi-coverage")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    private fun write(relative: String) {
        val path = tmp.resolve(relative)
        Files.createDirectories(path.parent)
        Files.writeString(path, "class X\n")
    }

    @Test
    fun theMavenGradleTestTreeIsCountedSeparately() {
        write("src/main/kotlin/Main.kt")
        write("src/test/kotlin/MainTest.kt")
        write("src/test/java/OtherTest.java")
        val (present, tests) = SourceCollector.presentCounts(tmp)
        assertEquals(3, present)
        assertEquals(2, tests)
    }

    /** The kotlinx layout: `<module>/<set>/src` beside `<module>/<set>/test`. */
    @Test
    fun theKotlinxTestTreeIsCountedSeparately() {
        write("core/common/src/Flow.kt")
        write("core/common/test/FlowTest.kt")
        write("core/jvm/test/JvmFlowTest.kt")
        val (present, tests) = SourceCollector.presentCounts(tmp)
        assertEquals(3, present)
        assertEquals(2, tests)
    }

    /** Android and multiplatform source-set spellings. */
    @Test
    fun theSourceSetTestSpellingsAreCountedSeparately() {
        write("app/src/main/kotlin/App.kt")
        write("app/src/androidTest/kotlin/AppAndroidTest.kt")
        write("app/src/commonTest/kotlin/AppCommonTest.kt")
        write("app/src/jvmTest/kotlin/AppJvmTest.kt")
        val (present, tests) = SourceCollector.presentCounts(tmp)
        assertEquals(4, present)
        assertEquals(3, tests)
    }

    /**
     * The negative that keeps the rule from swallowing real code: a package
     * or class whose NAME contains "test" is not a test directory.
     */
    @Test
    fun aDirectoryThatMerelyMentionsTestingIsNotATestTree() {
        write("src/main/kotlin/com/example/testing/Harness.kt")
        write("src/main/kotlin/com/example/Contest.kt")
        write("src/main/kotlin/TestUtilities.kt")
        val (present, tests) = SourceCollector.presentCounts(tmp)
        assertEquals(3, present)
        assertEquals(0, tests, "a main-source package was counted as tests")
    }

    @Test
    fun theRatioTheDiagnosticReadsIgnoresTheTestTree() {
        val coverage = io.cdxgen.kosi.schema.SourceCoverage(
            discovered = 397,
            present = 1061,
            testPresent = 651,
        )
        assertEquals(0.37, coverage.ratio, 0.01, "the raw ratio still reports what is on disk")
        assertEquals(0.96, coverage.nonTestRatio, 0.01, "discovery of the files a main root could hold")
    }

    /** A tree of nothing but tests cannot divide by zero, and is not a gap. */
    @Test
    fun aTestOnlyTreeIsFullCoverage() {
        val coverage = io.cdxgen.kosi.schema.SourceCoverage(discovered = 0, present = 40, testPresent = 40)
        assertEquals(1.0, coverage.nonTestRatio)
    }
}
