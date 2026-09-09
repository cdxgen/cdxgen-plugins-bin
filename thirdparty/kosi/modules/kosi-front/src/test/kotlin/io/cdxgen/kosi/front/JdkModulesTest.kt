package io.cdxgen.kosi.front

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The resolved tier's JDK substrate (docs/KOSI.md defect 3). These tests pin
 * the JVM-side facts that the native image depends on: the resolution order
 * for a JDK home, the refusal of homes that name no modular JDK, and the
 * completeness and determinism of the module-image extraction that the
 * image's SDK module is built from.
 */
class JdkModulesTest {

    @Test
    fun resolutionPrefersExplicitThenJavaHomeThenEnvironment() {
        val real = Path.of(System.getProperty("java.home"))
        val other = Files.createTempDirectory("kosi-jdk-other")

        // Explicit flag wins over everything, even when the other sources
        // name different homes.
        assertEquals(
            real,
            (JdkModules.resolve(real, property = { other.toString() }, env = { other.toString() })
                as JdkModules.Resolution.Found).home,
        )
        // No flag: java.home next.
        assertEquals(
            real,
            (JdkModules.resolve(null, property = { real.toString() }, env = { other.toString() })
                as JdkModules.Resolution.Found).home,
        )
        // Neither java.home (the image case) nor a flag: JAVA_HOME.
        assertEquals(
            real,
            (JdkModules.resolve(null, property = { null }, env = { real.toString() })
                as JdkModules.Resolution.Found).home,
        )
    }

    @Test
    fun aResolutionFailureNamesEverySourceTried() {
        val none = JdkModules.resolve(null, property = { null }, env = { null })
        assertTrue(none is JdkModules.Resolution.NotFound, "expected NotFound, got $none")
        assertTrue("java.home is unset" in none.tried, none.tried)
        assertTrue("JAVA_HOME is unset" in none.tried, none.tried)
        assertTrue("--jdk-home" in none.tried, "the message must name the escape hatch: ${none.tried}")
    }

    @Test
    fun anEmptyDirectoryIsNotAJdkHome() {
        val empty = Files.createTempDirectory("kosi-jdk-empty")
        val resolution = JdkModules.resolve(empty)
        assertTrue(resolution is JdkModules.Resolution.Invalid, "expected Invalid, got $resolution")
        assertTrue("modular" in (resolution as JdkModules.Resolution.Invalid).message, resolution.message)
    }

    @Test
    fun aJreShapedTreeWithoutModulesIsRejected() {
        // A directory that merely looks like a JDK (has bin/) but carries no
        // module image must not be mistaken for one.
        val fake = Files.createTempDirectory("kosi-jdk-fake")
        Files.createDirectories(fake.resolve("bin"))
        fake.resolve("bin/java").writeText("#!/bin/sh\n")
        val resolution = JdkModules.resolve(fake)
        assertTrue(resolution is JdkModules.Resolution.Invalid, "expected Invalid, got $resolution")
    }

    @Test
    fun theModuleImageExtractsCompletelyAndDeterministically() {
        val home = Path.of(System.getProperty("java.home"))
        val image = home.resolve("lib").resolve("modules")
        if (!Files.isRegularFile(image)) {
            // An exploded-JDK machine has no module image to extract; the
            // resolution half of the contract is covered above.
            return
        }
        // The JVM route reads the same image through the public jrt
        // filesystem; the image substrate reads it through the jimage reader
        // and asserts the same shape in the native runs.
        val jars = JdkModules.extractedModuleJars(home)
        assertTrue(jars.size >= 10, "a real module image yields many modules; got ${jars.size}")
        assertTrue(jars == jars.sorted(), "root order must be deterministic")
        val javaBase = jars.firstOrNull { it.fileName.toString() == "module-java.base.jar" }
        assertNotNull(javaBase, "java.base must be among the extracted module jars: ${jars.take(5)}")

        // THE property the per-module split exists for: entries are relative
        // to their module, so the search scope's package trie derives
        // java.lang.String — not java.base.java.lang.String — from the path.
        // (A single merged jar failed exactly this way and resolved nothing.)
        ZipFile(javaBase.toFile()).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            assertTrue(names.size > 1000, "java.base has thousands of entries; got ${names.size}")
            assertTrue(
                names.contains("java/lang/String.class"),
                "entries must be module-relative; got ${names.take(10)}",
            )
            assertTrue(
                names.none { it.startsWith("java.base/") },
                "an entry carrying the module prefix would corrupt the package trie",
            )
            // Fixed timestamps: no wall-clock time enters the archive.
            assertTrue(
                zip.entries().asSequence().all { it.time == 315532800000L },
                "every entry must carry the fixed epoch timestamp",
            )
        }

        // Reuse: a second call over the same image hits the cache and
        // returns the same jars unchanged.
        val again = JdkModules.extractedModuleJars(home)
        assertEquals(jars, again, "extraction must be cached per (path, size, mtime) stamp")
    }
}
