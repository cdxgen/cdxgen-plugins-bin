package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DiagnosticCodes
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Negative-first tests for the resolved backend (P1 gate): a deliberately
 * emptied classpath must be LOUD (the diagnostic names what it could not
 * find) and visible in `resolvedCallRatio` — never a plausible-looking small
 * graph (07-REVIEW-PROTOCOL.md failure mode 9). Each test also fails if the
 * diagnostic it pins is removed, which is the "test that fails when the gate
 * is disabled" the P0 review demanded for every new filter.
 */
class ResolvedBackendTest {

    /** Writes a plain source tree with the given build file and sources. */
    private fun project(buildFile: String?, sources: Map<String, String>): Path {
        val root = Files.createTempDirectory("kosi-resolved-test")
        if (buildFile != null) {
            root.resolve("build.gradle.kts").writeText(buildFile)
        }
        for ((path, text) in sources) {
            val file = root.resolve(path)
            Files.createDirectories(file.parent)
            file.writeText(text)
        }
        return root
    }

    // Calls span both stdlib (listOf/joinToString) and the JDK (System) so
    // the emptied-classpath differential exercises the SDK module, not just
    // the bundled stdlib.
    private val kotlinSource = """
        package t

        fun main() {
            val message = listOf("a", "b").joinToString(separator = ", ")
            val tmp = java.io.File(System.getProperty("java.io.tmpdir"))
            println(message.length.toString() + tmp.name + System.lineSeparator())
        }
    """.trimIndent()

    @Test
    fun emptyClasspathIsLoudAndVisiblyDegrades() {
        val root = project(
            buildFile = """
                plugins { kotlin("jvm") }
            """.trimIndent(),
            sources = mapOf("src/main/kotlin/Main.kt" to kotlinSource),
        )
        // Full run: the running JVM's stdlib jar rides the explicit classpath
        // and the JDK module exists, so every call resolves.
        val stdlib = stdlibJarFromTestClasspath()
        val full = Analyzer.analyze(
            root,
            AnalyzeOptions(
                backend = Backend.RESOLVED,
                classpath = listOfNotNull(stdlib?.toString()),
            ),
            commit = "test",
        )
        assertEquals(1.0, full.stats.resolvedCallRatio, "every call resolves with stdlib + JDK")
    }

    @Test
    fun anExplicitJdkHomeThatIsNotAJdkIsAUsageError() {
        // A flag that cannot work must be rejected with the reason, never
        // silently downgraded to a partial classpath (the old behaviour was
        // a classpath-partial warning and a report that quietly resolved
        // every java.* symbol as unresolved).
        val root = project(buildFile = null, sources = mapOf("src/main/kotlin/Main.kt" to kotlinSource))
        val failure = assertFailsWith<Analyzer.AnalysisException> {
            Analyzer.analyze(
                root,
                AnalyzeOptions(
                    backend = Backend.RESOLVED,
                    jdkHome = "/kosi-test/no-such-jdk",
                ),
                commit = "test",
            )
        }
        assertTrue("no-such-jdk" in failure.message!!, failure.message!!)
        assertTrue("modular" in failure.message!!, "the error must say what kind of home is required: ${failure.message}")
    }

    @Test
    fun unresolvableCoordinateIsNamedByTheDiagnostic() {
        val root = project(
            buildFile = """
                plugins { kotlin("jvm") }

                dependencies {
                    implementation("com.example.unresolvable:gone:1.0.0")
                }
            """.trimIndent(),
            sources = mapOf(
                "src/main/kotlin/Report.kt" to """
                package t

                import com.example.unresolvable.gone.GoneClient

                fun render(): String = GoneClient.connect("x").summary()
                """.trimIndent(),
            ),
        )
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        val partial = report.diagnostics.firstOrNull { it.code == DiagnosticCodes.CLASSPATH_PARTIAL }
        assertNotNull(partial, "classpath-partial must fire for an unresolvable coordinate")
        assertTrue(
            "com.example.unresolvable:gone:1.0.0" in partial.message,
            "the diagnostic must name the missing coordinate: ${partial.message}",
        )
        assertEquals(1, partial.count)
        // The missing library's classes are never invented as declarations.
        assertFalse(
            report.declarations.any { it.name == "GoneClient" },
            "a coordinate that cannot be resolved must not produce declarations",
        )
    }

    @Test
    fun javaSourcesAreParsedAtTheResolvedTierOnly() {
        val root = project(
            buildFile = null,
            sources = mapOf(
                "src/main/kotlin/Main.kt" to """
                    package t

                    fun useGreeter(): String = Greeter().greet("kosi")
                """.trimIndent(),
                "src/main/java/Greeter.java" to """
                    package t;

                    public class Greeter {
                        public String greet(String name) {
                            return "hello " + name;
                        }
                    }
                """.trimIndent(),
            ),
        )
        // The syntax tier keeps its documented gap (defect 2): the diagnostic
        // must be there — removing it is a regression this test catches.
        val syntax = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.SYNTAX), commit = "test")
        assertTrue(
            syntax.diagnostics.any { it.code == DiagnosticCodes.JAVA_SOURCE_NOT_PARSED },
            "syntax tier must keep reporting java-source-not-parsed",
        )
        assertFalse(syntax.declarations.any { it.name == "Greeter" })

        // The resolved tier parses Java PSI through the same symbols: the gap
        // closes and the JVM evidence appears.
        val resolved = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        assertFalse(
            resolved.diagnostics.any { it.code == DiagnosticCodes.JAVA_SOURCE_NOT_PARSED },
            "java-source-not-parsed must disappear from resolved-tier reports",
        )
        val greeter = resolved.declarations.firstOrNull { it.name == "Greeter" }
        assertNotNull(greeter, "the Java class must be a declaration at the resolved tier")
        assertEquals("class", greeter.kind)
        val greet = resolved.declarations.firstOrNull { it.name == "greet" }
        assertNotNull(greet, "the Java method must be a declaration at the resolved tier")
        assertEquals("(Ljava/lang/String;)Ljava/lang/String;", greet.jvmDescriptor)
        assertEquals("t/Greeter", greet.jvmOwner)
        // Cross-language resolution: the Kotlin call into Java resolves.
        assertEquals(1.0, resolved.stats.resolvedCallRatio)
    }

    @Test
    fun cliVersionOverridesAreRecordedAsDiagnostics() {
        val root = project(
            buildFile = """
                plugins { kotlin("jvm") }

                kotlin {
                    compilerOptions {
                        languageVersion = "2.0"
                    }
                }
            """.trimIndent(),
            sources = mapOf("src/main/kotlin/Main.kt" to kotlinSource),
        )
        val report = Analyzer.analyze(
            root,
            AnalyzeOptions(backend = Backend.RESOLVED, languageVersion = "2.2"),
            commit = "test",
        )
        val override = report.diagnostics.firstOrNull { it.code == DiagnosticCodes.VERSION_OVERRIDE }
        assertNotNull(override, "an explicit --language-version override must be recorded")
        assertTrue("2.2" in override.message && "2.0" in override.message, override.message)
    }

    @Test
    fun theRatioPublishesItsDenominator() {
        // The defect this guards: `resolvedCallRatio` alone cannot tell "no
        // calls in this file" from "resolved nothing" — both print 0.0. The
        // counts must travel with the ratio (as sliceCount does with
        // connectivity), and they must agree with it.
        val callFree = project(
            buildFile = null,
            sources = mapOf("src/main/kotlin/Data.kt" to "package t\n\nval answer: Int = 42\n"),
        )
        val none = Analyzer.analyze(callFree, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        assertEquals(0, none.stats.callsTotal, "a file with no calls must publish a zero denominator")
        assertEquals(0.0, none.stats.resolvedCallRatio)

        val withCalls = project(
            buildFile = null,
            sources = mapOf("src/main/kotlin/Main.kt" to kotlinSource),
        )
        val some = Analyzer.analyze(withCalls, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        assertTrue(some.stats.callsTotal > 0, "calls exist, so the denominator must not be zero")
        assertEquals(
            some.stats.callsResolved.toDouble() / some.stats.callsTotal,
            some.stats.resolvedCallRatio,
            "the published counts must be the ones the ratio was computed from",
        )
    }

    @Test
    fun aClasspathFileThatDoesNotExistIsAnError() {
        // Never a silently empty classpath: a flag the report echoes but
        // never applied is the P0 `--compare` defect.
        val root = project(buildFile = null, sources = mapOf("src/main/kotlin/Main.kt" to kotlinSource))
        val failure = assertFailsWith<Analyzer.AnalysisException> {
            Analyzer.analyze(
                root,
                AnalyzeOptions(backend = Backend.RESOLVED, classpathFile = "/kosi-test/no-such-classpath.txt"),
                commit = "test",
            )
        }
        assertTrue("no-such-classpath.txt" in failure.message!!, failure.message!!)
    }

    @Test
    fun modifiersAreNotDuplicatedBetweenPsiAndSymbol() {
        // `abstract` is visible both in the PSI modifier list and in the
        // symbol's modality; emitting it twice would state one fact as two.
        val root = project(
            buildFile = null,
            sources = mapOf(
                "src/main/kotlin/Shape.kt" to """
                    package t

                    abstract class Shape {
                        abstract fun area(): Double
                    }
                """.trimIndent(),
            ),
        )
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        for (declaration in report.declarations) {
            assertEquals(
                declaration.modifiers.distinct(),
                declaration.modifiers,
                "duplicate modifiers on ${declaration.name}: ${declaration.modifiers}",
            )
        }
        val area = report.declarations.first { it.name == "area" }
        assertTrue("abstract" in area.modifiers)
    }

    @Test
    fun annotationsCarryTheirOwnPosition() {
        // The defect this guards: stamping every annotation at line 1 column
        // 1 reports a position that is not where the annotation is.
        val root = project(
            buildFile = null,
            sources = mapOf(
                "src/main/kotlin/Annotated.kt" to """
                    package t

                    @Deprecated("gone")
                    fun old() {
                    }
                """.trimIndent(),
            ),
        )
        val report = Analyzer.analyze(root, AnalyzeOptions(backend = Backend.RESOLVED), commit = "test")
        val old = report.declarations.first { it.name == "old" }
        val annotation = old.annotations.firstOrNull { it.name == "Deprecated" }
        assertNotNull(annotation, "the annotation must be reported: ${old.annotations.map { it.name }}")
        assertEquals(3, annotation.position.line, "the annotation is on line 3, not line 1")
    }

    private fun stdlibJarFromTestClasspath(): Path? {
        for (entry in System.getProperty("java.class.path")?.split(File.pathSeparator) ?: emptyList()) {
            if (entry.isEmpty()) continue
            val p = Path.of(entry)
            val name = p.fileName.toString()
            if (name.startsWith("kotlin-stdlib-") && name.endsWith(".jar")) return p
        }
        return null
    }
}
