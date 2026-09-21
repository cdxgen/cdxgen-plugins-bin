package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Members a settings file includes through a LOCAL HELPER.
 *
 * kotlinx.coroutines declares 17 of its 20 members as
 * `module("reactive/kotlinx-coroutines-rx2")`, where `module` is a function
 * declared three lines above that runs `include(name)` on a SUBSTRING and
 * then relocates the project. Nothing in the file states the member
 * literally — not the include (a variable) and not the relocation
 * (`project(":${'$'}name")`). The include scanner saw none of them, so those
 * members' sources were never collected: the repo sat at 29% source
 * coverage with no diagnostic naming the cause.
 *
 * The rule under test: a quoted relative path that IS a directory holding a
 * Gradle build file is a member, whatever function was applied to it — and
 * a string that is not stays ignored, which is the half that keeps the rule
 * from inventing members out of every literal in the file.
 */
class GradleHelperMemberTest {

    private val tmp: Path = Files.createTempDirectory("kosi-gradle-helper")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    private fun module(path: String, sources: String = "src/main/kotlin") {
        Files.createDirectories(tmp.resolve(path).resolve(sources))
        Files.writeString(tmp.resolve(path).resolve("build.gradle.kts"), "plugins { kotlin(\"jvm\") }\n")
    }

    private fun settings(text: String) = Files.writeString(tmp.resolve("settings.gradle.kts"), text)

    private fun discoveredPaths(): Set<String> =
        GradleDiscovery.discover(tmp).modules.map { it.modulePath }.toSet()

    @Test
    fun aMemberIncludedThroughALocalHelperIsFound() {
        module("reactive/kotlinx-coroutines-rx2")
        module("ui/kotlinx-coroutines-swing")
        settings(
            """
            rootProject.name = "coroutines-like"
            fun module(path: String) {
                val name = path.substringAfterLast("/")
                include(name)
                project(":${'$'}name").projectDir = file(path)
            }
            module("reactive/kotlinx-coroutines-rx2")
            module("ui/kotlinx-coroutines-swing")
            """.trimIndent(),
        )
        val paths = discoveredPaths()
        assertTrue("reactive/kotlinx-coroutines-rx2" in paths, "helper-included member missing: $paths")
        assertTrue("ui/kotlinx-coroutines-swing" in paths, "helper-included member missing: $paths")
    }

    /**
     * The disk is the arbiter, and this is why the rule is safe: a settings
     * file is full of quoted strings — plugin ids, versions, repository
     * URLs, the root project's own name — and none of them is a directory
     * with a build file.
     */
    @Test
    fun aQuotedStringThatIsNotABuildableModuleIsNotAMember() {
        module("app")
        Files.createDirectories(tmp.resolve("docs"))
        settings(
            """
            pluginManagement {
                repositories { maven(url = "https://example.invalid/repo") }
                plugins { id("org.example.plugin") version "1.2.3" }
            }
            rootProject.name = "not-a-module"
            include("app")
            weirdHelper("docs")
            """.trimIndent(),
        )
        val paths = discoveredPaths()
        assertTrue("app" in paths, "the ordinary include broke: $paths")
        assertTrue("docs" !in paths, "a directory with no build file is not a member: $paths")
        assertTrue(
            paths.none { it.contains("example") || it.contains("1.2.3") },
            "plugin/repository literals became members: $paths",
        )
    }

    /** An ordinary include and a helper include of the same dir is ONE member. */
    @Test
    fun aMemberIsNotDiscoveredTwice() {
        module("app")
        settings(
            """
            include("app")
            module("app")
            """.trimIndent(),
        )
        assertEquals(
            1,
            GradleDiscovery.discover(tmp).modules.count { it.modulePath == "app" },
            "the same directory was added as two members",
        )
    }
}
