package io.cdxgen.kosi.project

import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The offline resolver is the resolved tier's honesty mechanism: a
 * classpath-partial diagnostic is only as trustworthy as the scan that feeds
 * it. These tests pin the text scanning (Gradle literals, version catalogs,
 * Maven XML), the project-local locator and the package-prefix index.
 */
class ClasspathResolverTest {

    @Test
    fun scansGradleLiteralsVersionsTomlAndPom() {
        val dir = Files.createTempDirectory("kosi-cp-test")

        val gradle = dir.resolve("build.gradle.kts")
        gradle.writeText(
            """
            dependencies {
                implementation("com.google.guava:guava:33.2.0-jre")
                api("org.jetbrains.kotlinx:kotlinx-coroutines-core:${'$'}{coroutinesVersion}")
                testImplementation("junit:junit:4.13.2")
            }
            """.trimIndent(),
        )
        val scanned = ClasspathResolver.scan(gradle)
        assertEquals(
            listOf(
                ClasspathResolver.Coordinate("com.google.guava", "guava", "33.2.0-jre"),
                // A version referenced through a property is recorded version-less:
                // the locator picks the highest cached version or reports it missing.
                ClasspathResolver.Coordinate("org.jetbrains.kotlinx", "kotlinx-coroutines-core", null),
                ClasspathResolver.Coordinate("junit", "junit", "4.13.2"),
            ),
            scanned,
        )

        val toml = dir.resolve("libs.versions.toml")
        toml.writeText(
            """
            [versions]
            kotlin = "2.4.0"

            [libraries]
            kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
            """.trimIndent(),
        )
        assertEquals(
            listOf(ClasspathResolver.Coordinate("org.jetbrains.kotlin", "kotlin-stdlib", null)),
            ClasspathResolver.scan(toml).filter { it.group == "org.jetbrains.kotlin" },
        )

        val pom = dir.resolve("pom.xml")
        pom.writeText(
            """
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.jetbrains.kotlin</groupId>
                  <artifactId>kotlin-stdlib</artifactId>
                  <version>2.4.0</version>
                </dependency>
                <dependency>
                  <groupId>javax.servlet</groupId>
                  <artifactId>servlet-api</artifactId>
                  <scope>provided</scope>
                </dependency>
              </dependencies>
            </project>
            """.trimIndent(),
        )
        val pomDeps = ClasspathResolver.scan(pom)
        assertEquals(1, pomDeps.size, "provided scope is not a resolution target: $pomDeps")
        assertEquals("org.jetbrains.kotlin", pomDeps.first().group)
    }

    @Test
    fun locatesProjectLocalBuildOutputs() {
        val root = Files.createTempDirectory("kosi-cp-root")
        val module = root.resolve("app")
        val libs = module.resolve("build/libs")
        Files.createDirectories(libs)
        val jar = libs.resolve("app-core-1.2.0.jar")
        ZipOutputStream(Files.newOutputStream(jar)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write("Manifest-Version: 1.0\n".toByteArray())
            zos.closeEntry()
        }

        val found = ClasspathResolver.locate(
            ClasspathResolver.Coordinate("dev.example", "app-core", "1.2.0"),
            root,
            setOf(module),
        )
        assertNotNull(found, "build/libs jars must be locatable offline")

        val missing = ClasspathResolver.locate(
            ClasspathResolver.Coordinate("dev.example", "absent-artifact", "9.9.9"),
            root,
            setOf(module),
        )
        assertNull(missing, "an absent coordinate must stay absent")
    }

    @Test
    fun packageIndexAttributesImportsToTheLongestMatchingPrefix() {
        val root = Files.createTempDirectory("kosi-cp-idx")
        val libs = root.resolve("build/libs")
        Files.createDirectories(libs)
        val jar = libs.resolve("lib-1.0.jar")

        // The index reads jar entries; the entries here are records of where
        // classes live, not compiled code.
        ZipOutputStream(Files.newOutputStream(jar)).use { zos ->
            for (name in listOf(
                "com/example/deep/Thing.class",
                "com/example/Other.class",
                "META-INF/MANIFEST.MF",
            )) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(ByteArray(0))
                zos.closeEntry()
            }
        }

        val index = ClasspathResolver.packageIndex(
            listOf(ClasspathResolver.ResolvedJar(jar, "pkg:maven/dev.example/lib@1.0", null)),
        )
        assertEquals("pkg:maven/dev.example/lib@1.0", ClasspathResolver.purlForImport("com.example.Other", index))
        assertEquals("pkg:maven/dev.example/lib@1.0", ClasspathResolver.purlForImport("com.example.deep.Tool", index))
        assertNull(ClasspathResolver.purlForImport("org.other.Vector", index))
    }

    @Test
    fun resolveReportsEveryMissingCoordinate() {
        val root = Files.createTempDirectory("kosi-cp-missing")
        val module = root.resolve("app")
        Files.createDirectories(module)
        module.resolve("build.gradle.kts").writeText(
            """
            dependencies {
                implementation("com.example.unresolvable:gone:1.0.0")
                implementation("com.example.also-gone:far:2.0.0")
            }
            """.trimIndent(),
        )
        val result = ClasspathResolver.resolve(root, emptyList(), null, listOf(module))
        assertEquals(
            listOf(
                "com.example.also-gone:far:2.0.0",
                "com.example.unresolvable:gone:1.0.0",
            ),
            result.missing,
            "every coordinate the offline resolver cannot find must be reported",
        )
        assertTrue(result.jars.isEmpty())
    }

    /**
     * Kotlin multiplatform publishing files the JVM artifact under the
     * PARENT's directory: `io.ktor:ktor-server-core` resolves for a JVM
     * consumer to `ktor-server-core-jvm-<version>.jar`, sitting in
     * `ktor-server-core/<version>/<hash>/`. Matching only the exact name
     * reported every such coordinate as unlocatable with the jar already in
     * the cache — which is all of Ktor and all of kotlinx, so a real Ktor
     * application resolved a third of its calls because its own framework
     * was missing from the classpath it had been given.
     */
    @Test
    fun locatesMultiplatformJarsFiledUnderTheParentArtifact() {
        val root = Files.createTempDirectory("kosi-cp-kmp")
        val module = root.resolve("app")
        Files.createDirectories(module)
        module.resolve("build.gradle.kts").writeText(
            """
            dependencies {
                implementation("io.example:multi-core:1.6.7")
                implementation("io.example:plain-core:1.6.7")
            }
            """.trimIndent(),
        )
        // The project-local cache, in files-2.1 layout.
        val cache = root.resolve(".gradle")
        val multi = cache.resolve("io.example/multi-core/1.6.7/abc123")
        Files.createDirectories(multi)
        writeJar(multi.resolve("multi-core-jvm-1.6.7.jar"), "io/example/multi/Api.class")
        val plain = cache.resolve("io.example/plain-core/1.6.7/def456")
        Files.createDirectories(plain)
        writeJar(plain.resolve("plain-core-1.6.7.jar"), "io/example/plain/Api.class")

        val result = ClasspathResolver.resolve(root, emptyList(), null, listOf(module))
        val names = result.jars.map { it.jar.fileName.toString() }.sorted()
        assertTrue(
            names.contains("multi-core-jvm-1.6.7.jar"),
            "the multiplatform JVM jar must be located under its parent artifact; got $names",
        )
        assertTrue(names.contains("plain-core-1.6.7.jar"), "the exactly-named jar must still be located")
        assertTrue(result.missing.isEmpty(), "nothing is missing: both jars are in the cache, got ${result.missing}")
    }

    /**
     * A neighbouring jar whose suffix is NOT a Kotlin target must not be
     * picked up: the platform-suffixed name is accepted for the suffixes
     * Kotlin's own publishing emits, never as a wildcard over the directory.
     */
    @Test
    fun ignoresNeighbouringJarsThatAreNotPlatformVariants() {
        val root = Files.createTempDirectory("kosi-cp-kmp-neg")
        val module = root.resolve("app")
        Files.createDirectories(module)
        module.resolve("build.gradle.kts").writeText(
            """dependencies { implementation("io.example:odd-core:1.0.0") }""",
        )
        val dir = root.resolve(".gradle/io.example/odd-core/1.0.0/abc123")
        Files.createDirectories(dir)
        writeJar(dir.resolve("odd-core-sources-1.0.0.jar"), "io/example/odd/Api.class")

        val result = ClasspathResolver.resolve(root, emptyList(), null, listOf(module))
        assertTrue(result.jars.isEmpty(), "a sources jar is not the artifact; got ${result.jars}")
        assertEquals(listOf("io.example:odd-core:1.0.0"), result.missing)
    }

    /** A minimal but real jar: the resolver rejects anything it cannot open. */
    private fun writeJar(path: java.nio.file.Path, entry: String) {
        ZipOutputStream(Files.newOutputStream(path)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write("Manifest-Version: 1.0\n".toByteArray())
            zos.closeEntry()
            zos.putNextEntry(ZipEntry(entry))
            zos.write(byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte()))
            zos.closeEntry()
        }
    }
}
