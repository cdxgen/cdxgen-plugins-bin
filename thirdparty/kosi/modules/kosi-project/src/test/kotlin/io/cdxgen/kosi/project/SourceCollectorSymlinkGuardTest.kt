package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assumptions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The analysed tree must own everything the report is built from, and a
 * committed symbolic link is the tree reaching outside itself. Before the
 * no-follow rule, `Files.isRegularFile` answered about a link's target, so
 * a repository that committed `src/main/kotlin/Secret.kt` as a link to a
 * file elsewhere had that file parsed and its routes published, and a
 * linked `build.gradle.kts` or `gradle.properties` steered discovery with
 * text from outside the tree.
 *
 * The analysis root itself stays the operator's choice: a `--dir` that is
 * a link keeps working, exactly as before.
 */
class SourceCollectorSymlinkGuardTest {

    private val tmp: Path = Files.createTempDirectory("kosi-symlink-guard")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    /** Symlinks need privileges on Windows; skip rather than fail there. */
    private fun symlink(target: Path, link: Path): Boolean =
        try {
            Files.createSymbolicLink(link, target)
            true
        } catch (_: Exception) {
            false
        } catch (_: Error) {
            false
        }

    @Test
    fun aLinkedSourceFileIsNotCollectedButItsRegularSiblingIs() {
        val outside = Files.createTempDirectory("kosi-symlink-guard-outside")
        try {
            Files.writeString(outside.resolve("Secret.kt"), "package outside\n")
            Files.createDirectories(tmp.resolve("src/main/kotlin"))
            Files.writeString(tmp.resolve("src/main/kotlin/Inside.kt"), "package inside\n")
            val link = tmp.resolve("src/main/kotlin/Secret.kt")
            Assumptions.assumeTrue(symlink(outside.resolve("Secret.kt"), link), "symbolic links are unavailable here")

            Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\n")
            val modules = ProjectDiscovery.discover(tmp).modules
            val collected = SourceCollector.collect(tmp, modules)
            assertEquals(listOf("src/main/kotlin/Inside.kt"), collected.map { it.relativePath },
                "a linked source is the tree reaching outside itself")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aLinkedGradlePropertiesDoesNotSteerDiscovery() {
        val outside = Files.createTempDirectory("kosi-symlink-guard-outside")
        try {
            Files.writeString(outside.resolve("gradle.properties"), "group=stolen\n")
            Assumptions.assumeTrue(
                symlink(outside.resolve("gradle.properties"), tmp.resolve("gradle.properties")),
                "symbolic links are unavailable here",
            )
            Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\n")

            val result = ProjectDiscovery.discover(tmp)
            assertTrue(
                result.modules.none { it.purl.contains("stolen") },
                "a linked gradle.properties must not contribute the group: ${result.modules.map { it.purl }}",
            )
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aLinkedSettingsFileLeavesTheTreeUnrecognisedAsGradle() {
        val outside = Files.createTempDirectory("kosi-symlink-guard-outside")
        try {
            Files.writeString(outside.resolve("settings.gradle.kts"), "rootProject.name = \"outside\"\n")
            Assumptions.assumeTrue(
                symlink(outside.resolve("settings.gradle.kts"), tmp.resolve("settings.gradle.kts")),
                "symbolic links are unavailable here",
            )
            Files.writeString(tmp.resolve("src.kt"), "package x\n")

            val result = ProjectDiscovery.discover(tmp)
            assertEquals("none", result.buildSystem,
                "a linked settings file is not the project's own; the plain tree is the honest answer")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun theAnalysisRootItselfMayBeASymlink() {
        // The layout a real Gradle project has: discovery resolves the
        // source root under `--dir`, which makes the linked root an
        // INTERMEDIATE component of every walked path — and intermediate
        // links were always followed, before and after the no-follow rule.
        // A bare tree with no build files keeps its old answer too: the
        // walk yields only the link itself, nothing is collected.
        Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\n")
        Files.createDirectories(tmp.resolve("src/main/kotlin"))
        Files.writeString(tmp.resolve("src/main/kotlin/App.kt"), "package x\n")
        val linkedRoot = tmp.resolve("linked-root")
        Assumptions.assumeTrue(symlink(tmp, linkedRoot), "symbolic links are unavailable here")

        val result = ProjectDiscovery.discover(linkedRoot)
        val collected = SourceCollector.collect(linkedRoot, result.modules)
        assertEquals(listOf("src/main/kotlin/App.kt"), collected.map { it.relativePath },
            "`--dir` as a link keeps working: the operator chose that directory")
    }
}
