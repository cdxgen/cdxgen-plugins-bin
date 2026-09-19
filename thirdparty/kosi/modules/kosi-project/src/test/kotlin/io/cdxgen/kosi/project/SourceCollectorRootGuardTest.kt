package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P24 §0: the report's population is the analysis root, and nothing else.
 *
 * The two escapes this pins were handed over undiagnosed by the part-3
 * baseline work (09-PRECISION.md §1's incidental observations): a probe run
 * reported 429 files and slices from kosi's own fixture tree while analysing
 * a directory holding one Kotlin file, and one report published an identical
 * slice twice. Neither reproduces on a clean checkout — every discovery
 * path resolves its source roots inside the root — but the collector is one
 * `root.resolve(sourceRoot)` away from both whenever a build file names an
 * escaping `srcDir`, and a threat-model claim ("a report contains only the
 * analysed project's code") must be true by construction, not by the
 * absence of a reproducer. The same file reachable at two relative paths
 * (an escaping root that re-enters the tree, or overlapping module roots)
 * was collected twice because the dedup keyed on the RELATIVE path.
 */
class SourceCollectorRootGuardTest {

    private val tmp: Path = Files.createTempDirectory("kosi-collector-guard")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    private fun write(dir: String, name: String, text: String = "package x\n") {
        Files.createDirectories(tmp.resolve(dir))
        Files.writeString(tmp.resolve("$dir/$name"), text)
    }

    @Test
    fun anEscapingSrcDirCollectsNothingOutsideTheAnalysisRoot() {
        write("app/src/main/kotlin", "Inside.kt")
        // The tree OUTSIDE the analysis root: reachable only through the
        // module's escaping relative srcDir.
        val outside = Files.createTempDirectory("kosi-collector-guard-outside")
        try {
            Files.writeString(outside.resolve("Outside.kt"), "package y\n")
            Files.writeString(
                tmp.resolve("app/build.gradle.kts"),
                """
                plugins { kotlin("jvm") }
                sourceSets { main { srcDir("../../${outside.fileName}") } }
                """.trimIndent(),
            )
            Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\ninclude(\"app\")")
            val modules = ProjectDiscovery.discover(tmp).modules
            val collected = SourceCollector.collect(tmp, modules)
            assertEquals(listOf("app/src/main/kotlin/Inside.kt"), collected.map { it.relativePath },
                "a srcDir that escapes the analysis root must contribute nothing")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun anAbsoluteSrcDirCollectsNothingOutsideTheAnalysisRoot() {
        write("app/src/main/kotlin", "Inside.kt")
        val outside = Files.createTempDirectory("kosi-collector-guard-outside")
        try {
            Files.writeString(outside.resolve("Outside.kt"), "package y\n")
            Files.writeString(
                tmp.resolve("app/build.gradle.kts"),
                """
                plugins { kotlin("jvm") }
                sourceSets { main { srcDir("${outside.toString().replace("\\", "\\\\")}") } }
                """.trimIndent(),
            )
            Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\ninclude(\"app\")")
            val modules = ProjectDiscovery.discover(tmp).modules
            val collected = SourceCollector.collect(tmp, modules)
            assertTrue(collected.none { it.absolutePath.startsWith(outside) },
                "an absolute srcDir must not pull another tree into the report")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aFileReachableAtTwoRelativePathsIsCollectedOnce() {
        write("src/main/kotlin", "One.kt")
        // Two module roots that both reach the same file: the module's own
        // precise root, and an escaping root that resolves back into the tree
        // through `..`. Relative paths differ, so the old relative-path dedup
        // kept both copies — the duplicated-slice shape.
        Files.writeString(
            tmp.resolve("build.gradle.kts"),
            """
            plugins { kotlin("jvm") }
            sourceSets { main { srcDir("../${tmp.fileName}/src/main/kotlin") } }
            """.trimIndent(),
        )
        val modules = ProjectDiscovery.discover(tmp).modules
        val collected = SourceCollector.collect(tmp, modules)
        assertEquals(1, collected.size,
            "one file is one file, whatever number of roots reach it: ${collected.map { it.relativePath }}")
    }
}
