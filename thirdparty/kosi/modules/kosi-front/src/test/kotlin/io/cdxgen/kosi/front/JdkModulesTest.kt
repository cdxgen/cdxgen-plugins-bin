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
        // `installed` is stubbed empty on purpose: the real scan reads the
        // host, and a linux runner with /usr/lib/jvm would resolve a JDK
        // here and make this a test of the machine rather than the message.
        val none = JdkModules.resolve(
            null,
            property = { null },
            env = { null },
            installed = { emptyList() },
        )
        assertTrue(none is JdkModules.Resolution.NotFound, "expected NotFound, got $none")
        assertTrue("java.home is unset" in none.tried, none.tried)
        assertTrue("JAVA_HOME is unset" in none.tried, none.tried)
        assertTrue("--jdk-home" in none.tried, "the message must name the escape hatch: ${none.tried}")
    }

    /**
     * The image case. `java.home` is structurally unset in a native image,
     * so with no `JAVA_HOME` the old order ran out of sources and every
     * `java.*` symbol resolved to nothing — measured on
     * `fixtures/java-interop` as 1 of 2 calls resolved against the JVM's 2,
     * exit 0 and a warning either way. The launcher on `PATH` is where a
     * JDK actually is.
     */
    @Test
    fun aJdkOnThePathIsFoundWhenNeitherJavaHomeNorTheEnvironmentNamesOne() {
        val real = Path.of(System.getProperty("java.home"))
        val bin = real.resolve("bin")
        if (!java.nio.file.Files.isRegularFile(bin.resolve("java"))) {
            println("JdkModulesTest: no launcher at $bin; PATH discovery not exercised here")
            return
        }
        val resolution = JdkModules.resolve(
            null,
            property = { null },
            env = { key -> if (key == "PATH") bin.toString() else null },
            installed = { JdkModules.installedHomes(
                env = { key -> if (key == "PATH") bin.toString() else null },
                roots = emptyList(),
            ) },
        )
        assertTrue(resolution is JdkModules.Resolution.Found, "expected Found, got $resolution")
        assertEquals(real.toRealPath(), resolution.home.toRealPath())
    }

    /**
     * Every macOS JDK unpacks to `<bundle>/Contents/Home`, and a user who
     * points `JAVA_HOME` at the bundle gets a run with no JDK rather than an
     * error. The bundle is one `resolve` away, so it is followed.
     */
    @Test
    fun aMacOsBundleDirectoryResolvesToTheHomeInside() {
        val bundle = Files.createTempDirectory("kosi-jdk-bundle")
        val home = bundle.resolve("Contents").resolve("Home")
        Files.createDirectories(home.resolve("lib"))
        home.resolve("lib/modules").writeText("not a real image, but the marker this classifies on")
        val resolution = JdkModules.resolve(
            null,
            property = { bundle.toString() },
            env = { null },
            installed = { emptyList() },
        )
        assertTrue(resolution is JdkModules.Resolution.Found, "expected Found, got $resolution")
        assertEquals(home, resolution.home)
    }

    @Test
    fun installedHomesInventsNothingFromAnEmptyPathAndNoRoots() {
        // Hermetic on any host: both inputs are stubbed, so this asserts
        // the scan's own behaviour rather than what the machine happens to
        // have installed.
        assertTrue(
            JdkModules.installedHomes(env = { null }, roots = emptyList()).isEmpty(),
            "with no PATH and no install roots the scan must find nothing",
        )
    }

    @Test
    fun installedHomesReadsAnInstallRootNewestNameFirst() {
        val root = Files.createTempDirectory("kosi-jdk-root")
        for (name in listOf("jdk-17", "jdk-25", "jdk-21")) {
            Files.createDirectories(root.resolve(name).resolve("lib"))
            root.resolve(name).resolve("lib/modules").writeText("marker")
        }
        val found = JdkModules.installedHomes(env = { null }, roots = listOf(root.toString()))
        assertEquals(
            listOf("jdk-25", "jdk-21", "jdk-17"),
            found.map { it.fileName.toString() },
            "directory enumeration order must not decide which JDK is picked",
        )
        val resolution = JdkModules.resolve(
            null,
            property = { null },
            env = { null },
            installed = { found },
        )
        assertEquals(root.resolve("jdk-25"), (resolution as JdkModules.Resolution.Found).home)
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
