package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assumptions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The analysed tree must own everything the report is built from. A
 * committed symbolic link to a file (`src/main/kotlin/Secret.kt`) or to a
 * directory (`src`, a module directory), and a module path that names a
 * directory outside the tree, would each let the report carry routes and
 * values from files the repository does not contain.
 *
 * The analysis root itself stays the operator's choice: a `--dir` that is
 * a link keeps working.
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
        // Discovery resolves the source root under `--dir`, so the linked
        // root is a middle component of every walked path. Containment
        // compares real paths, so the link's own target counts as inside.
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

    private fun writeRoute(file: Path, route: String) {
        Files.createDirectories(file.parent)
        Files.writeString(file, "package x\nclass C { fun f() = \"$route\" }\n")
    }

    @Test
    fun aSourceDirectoryLinkedOutsideTheTreeIsNotWalked() {
        val outside = Files.createTempDirectory("kosi-symlink-guard-outside")
        try {
            writeRoute(outside.resolve("main/kotlin/Victim.kt"), "/victim")
            Files.writeString(tmp.resolve("settings.gradle.kts"), "rootProject.name = \"guard\"\n")
            Files.writeString(tmp.resolve("build.gradle.kts"), "")
            Assumptions.assumeTrue(symlink(outside, tmp.resolve("src")), "symbolic links are unavailable here")

            val result = ProjectDiscovery.discover(tmp)
            val collected = SourceCollector.collect(tmp, result.modules)
            assertTrue(collected.none { it.relativePath.endsWith("Victim.kt") },
                "a source root reached through a linked `src` is outside the tree: ${collected.map { it.relativePath }}")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun gradleMembersOutsideTheTreeAreDropped() {
        val outside = Files.createTempDirectory("kosi-symlink-guard-outside")
        try {
            Files.writeString(outside.resolve("build.gradle.kts"), "")
            writeRoute(outside.resolve("src/main/kotlin/Victim.kt"), "/victim")
            val absolute = outside.toAbsolutePath().toString().replace('\\', '/')
            val linked = symlink(outside, tmp.resolve("linked"))
            Files.writeString(
                tmp.resolve("settings.gradle.kts"),
                "rootProject.name = \"guard\"\n" +
                    "includeProject(\":abs\", \"$absolute\")\n" +
                    (if (linked) "include(\":linked\")\n" else ""),
            )
            Files.writeString(tmp.resolve("build.gradle.kts"), "")
            writeRoute(tmp.resolve("src/main/kotlin/App.kt"), "/app")

            val result = ProjectDiscovery.discover(tmp)
            val collected = SourceCollector.collect(tmp, result.modules)
            assertEquals(listOf("src/main/kotlin/App.kt"), collected.map { it.relativePath })
            assertTrue(result.modules.none { it.modulePath.startsWith("..") || Path.of(it.modulePath).isAbsolute || it.modulePath == "linked" },
                "members outside the tree: ${result.modules.map { it.modulePath }}")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun mavenModulesOutsideTheTreeAreDropped() {
        val parent = Files.createTempDirectory("kosi-symlink-guard-maven")
        try {
            val project = Files.createDirectories(parent.resolve("project"))
            val outside = Files.createDirectories(parent.resolve("outside"))
            Files.writeString(outside.resolve("pom.xml"), "<project><artifactId>victim</artifactId></project>")
            writeRoute(outside.resolve("src/main/kotlin/Victim.kt"), "/victim")
            val linked = symlink(outside, project.resolve("linked"))
            val absolute = outside.toAbsolutePath().toString()
            Files.writeString(
                project.resolve("pom.xml"),
                "<project><artifactId>app</artifactId><modules>" +
                    "<module>$absolute</module><module>../outside</module>" +
                    (if (linked) "<module>linked</module>" else "") +
                    "<module>.</module></modules></project>",
            )
            writeRoute(project.resolve("src/main/kotlin/App.kt"), "/app")

            val result = ProjectDiscovery.discover(project)
            assertEquals(listOf("app"), result.modules.map { it.name },
                "only the project's own pom is a module, and `.` does not loop")
            val collected = SourceCollector.collect(project, result.modules)
            assertEquals(listOf("src/main/kotlin/App.kt"), collected.map { it.relativePath })
        } finally {
            parent.toFile().deleteRecursively()
        }
    }
}
