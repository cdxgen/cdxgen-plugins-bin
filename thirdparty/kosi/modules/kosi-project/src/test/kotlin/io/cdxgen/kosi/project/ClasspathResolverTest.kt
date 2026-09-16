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
     * P17 (R105): a classpath file may BIND a coordinate to a committed jar
     * (`g:a:v=libs/foo.jar`). A bare coordinate resolves against the
     * machine-local Gradle cache, so a fixture pinning one was
     * machine-dependent through the classpath-partial diagnostic; the bound
     * form attaches the jar with the coordinate (maven purl, marker-visible)
     * and resolves identically on every machine. A bound jar that is missing
     * is LOUD — a pin nobody can read is a broken pin (R73's shape).
     */
    @Test
    fun boundCoordinateLinesResolveToTheCommittedJar() {
        val root = Files.createTempDirectory("kosi-cp-bound")
        val module = root.resolve("app")
        val libs = module.resolve("libs")
        Files.createDirectories(libs)
        val jar = libs.resolve("marker-3.2.0.jar")
        ZipOutputStream(Files.newOutputStream(jar)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write("Manifest-Version: 1.0\n".toByteArray())
            zos.closeEntry()
        }
        val classpathFile = module.resolve("classpath.txt")
        classpathFile.writeText(
            """
            org.springframework.boot:spring-boot-starter-actuator:3.2.0=libs/marker-3.2.0.jar
            org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0=libs/absent.jar
            """.trimIndent() + "\n",
        )
        val result = ClasspathResolver.resolve(root, emptyList(), classpathFile, listOf(module))
        assertEquals(1, result.jars.size, "the bound jar attaches with its coordinate: ${result.jars}")
        val resolved = result.jars.first()
        assertEquals(jar, resolved.jar)
        assertEquals("pkg:maven/org.springframework.boot/spring-boot-starter-actuator@3.2.0", resolved.purl)
        assertEquals(
            ClasspathResolver.Coordinate("org.springframework.boot", "spring-boot-starter-actuator", "3.2.0"),
            resolved.coordinate,
        )
        assertEquals(
            listOf("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0=absent.jar"),
            result.missing,
            "a bound jar that is not on disk must be reported, never silently skipped",
        )
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

    // ---- P15: Gradle Module Metadata file names, and AndroidX variant siblings

    /**
     * A publisher may name its artifact file anything — `Turbine-jvm.jar`,
     * `window-core.aar` — and the `.module` beside it is the publisher's
     * own declaration of those names. noneinandroid's 266 unlocatable
     * coordinates included exactly this shape, with the jar already in the
     * cache. Gradle stores each file under its own content hash, so the
     * `.module` and the artifact it names sit in DIFFERENT hash
     * directories; the search must span the whole version directory. The
     * metadata-usage variant (kotlin-metadata) is never picked even when
     * its file is the only one present.
     */
    @Test
    fun locatesArtifactsThroughGradleModuleMetadataFileNames() {
        val root = Files.createTempDirectory("kosi-cp-gmm")
        val module = root.resolve("app")
        Files.createDirectories(module)
        module.resolve("build.gradle.kts").writeText(
            """
            dependencies {
                implementation("io.example:turbine:1.2.0")
                implementation("io.example:meta-only:1.2.0")
            }
            """.trimIndent(),
        )
        // turbine: the .module in hash A declares Turbine-jvm.jar, which
        // lives in hash B; the metadata-usage variant declares a metadata
        // jar that ALSO exists — the java-api file must win.
        val metaDir = root.resolve(".gradle/io.example/turbine/1.2.0/aaaa")
        Files.createDirectories(metaDir)
        metaDir.resolve("turbine-1.2.0.module").writeText(
            """
            {
              "formatVersion": "1.1",
              "module": { "org.gradle.module": "io.example:turbine:1.2.0" },
              "variants": [
                {
                  "name": "jvmApiElements-published",
                  "attributes": { "org.gradle.usage": "java-api" },
                  "files": [ { "name": "Turbine-jvm.jar", "url": "Turbine-jvm.jar", "size": 1 } ]
                },
                {
                  "name": "metadataApiElements",
                  "attributes": { "org.gradle.usage": "kotlin-metadata" },
                  "files": [ { "name": "turbine-metadata-1.2.0.jar", "url": "x", "size": 1 } ]
                }
              ]
            }
            """.trimIndent(),
        )
        val jarDir = root.resolve(".gradle/io.example/turbine/1.2.0/bbbb")
        Files.createDirectories(jarDir)
        writeJar(jarDir.resolve("Turbine-jvm.jar"), "app/cash/turbine/TurbineKt.class")
        writeJar(jarDir.resolve("turbine-metadata-1.2.0.jar"), "META-INF/turbine.kotlin_module")

        // meta-only: the single declared file belongs to a kotlin-metadata
        // usage variant — not a binary root, so the coordinate is missing.
        val metaOnly = root.resolve(".gradle/io.example/meta-only/1.2.0/aaaa")
        Files.createDirectories(metaOnly)
        metaOnly.resolve("meta-only-1.2.0.module").writeText(
            """
            {
              "formatVersion": "1.1",
              "variants": [
                {
                  "name": "metadataApiElements",
                  "attributes": { "org.gradle.usage": "kotlin-metadata" },
                  "files": [ { "name": "meta-only-metadata-1.2.0.jar", "url": "x", "size": 1 } ]
                }
              ]
            }
            """.trimIndent(),
        )
        writeJar(metaOnly.resolve("meta-only-metadata-1.2.0.jar"), "META-INF/m.kotlin_module")

        val result = ClasspathResolver.resolve(root, emptyList(), null, listOf(module))
        val turbine = result.jars.firstOrNull { it.coordinate?.artifact == "turbine" }
        assertEquals(
            "Turbine-jvm.jar",
            turbine?.jar?.fileName?.toString(),
            "the metadata-declared file name is located across hash dirs, got ${result.jars.map { it.jar.fileName }}",
        )
        assertTrue(
            result.missing.contains("io.example:meta-only:1.2.0"),
            "a metadata-only variant's jar is not a binary root; missing=${result.missing}",
        )
    }

    /**
     * AndroidX multiplatform publishing: the SAME API ships under sibling
     * variant modules (`anim`, `anim-android` AAR, `anim-desktop`,
     * `anim-jvmstubs`). A variant whose binary was never downloaded —
     * the alpha/beta AndroidX builds in nowinandroid's classpath — is
     * still locatable through a sibling that WAS. The sibling chain only
     * strips/extends the known variant suffixes: a DIFFERENT library in
     * the same group is never picked up (the negative half).
     */
    @Test
    fun locatesAndroidxVariantSiblingsWhenTheDeclaredVariantHasNoBinary() {
        val root = Files.createTempDirectory("kosi-cp-sib")
        val module = root.resolve("app")
        Files.createDirectories(module)
        module.resolve("build.gradle.kts").writeText(
            """
            dependencies {
                implementation("io.example:anim-android:1.0.0")
                implementation("io.example:unrelated-lib:1.0.0")
            }
            """.trimIndent(),
        )
        // anim-android carries only metadata; the jvmstubs sibling has the jar.
        val android = root.resolve(".gradle/io.example/anim-android/1.0.0/aaaa")
        Files.createDirectories(android)
        android.resolve("anim-android-1.0.0.module").writeText(
            """
            { "formatVersion": "1.1", "variants": [
                { "name": "androidApiElements", "attributes": { "org.gradle.usage": "java-api" },
                  "files": [ { "name": "anim-android-1.0.0.aar", "url": "x", "size": 1 } ] } ] }
            """.trimIndent(),
        )
        val stubs = root.resolve(".gradle/io.example/anim-jvmstubs/1.0.0/bbbb")
        Files.createDirectories(stubs)
        writeJar(stubs.resolve("anim-jvmstubs-1.0.0.jar"), "io/example/anim/AnimatedVisibilityKt.class")

        val result = ClasspathResolver.resolve(root, emptyList(), null, listOf(module))
        val anim = result.jars.firstOrNull { it.coordinate?.artifact == "anim-android" }
        assertEquals(
            "anim-jvmstubs-1.0.0.jar",
            anim?.jar?.fileName?.toString(),
            "the declared variant's sibling supplies the binary, got ${result.jars.map { it.jar.fileName }}",
        )
        // The sibling never widens to a different library of the same group.
        assertTrue(
            result.missing.contains("io.example:unrelated-lib:1.0.0"),
            "a same-group library with a different base is NOT a variant sibling; missing=${result.missing}",
        )
    }
}
