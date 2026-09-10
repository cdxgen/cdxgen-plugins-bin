import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

// kosi-cli: hand-rolled argument parsing, subcommands (analyze, bench,
// golden, version), exit codes and diagnostics printing. No CLI library.
plugins {
    application
}

dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-project"))
    implementation(project(":kosi-front"))
    implementation(project(":kosi-kir"))
    implementation(project(":kosi-corpus"))
    implementation(project(":kosi-bench"))
    implementation(project(":kosi-graph"))
    implementation(project(":kosi-export"))
    implementation(project(":kosi-models"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass = "io.cdxgen.kosi.cli.MainKt"
}

// Deterministic provenance: inject the commit at build time (fallback
// "unknown" keeps analysis runnable outside git).
val kosiCommit = providers.exec {
    commandLine("git", "rev-parse", "HEAD")
    isIgnoreExitValue = true
}.standardOutput.asText.map { it.trim().ifEmpty { "unknown" } }

tasks.processResources {
    filesMatching("kosi-commit.txt") {
        expand("commit" to kosiCommit.get())
    }
}

// Named application run so `./gradlew :kosi-cli:run --args "analyze ..."` works.
tasks.named("run") {
    group = "kosi"
}

/**
 * Deterministic fat jar for the native-image build (05-BUILD-DIST.md §1).
 * - Strips the shaded JLine native-image entries whose
 *   native-image.properties reference config files absent from the jar —
 *   GraalVM aborts on them (KT-68829).
 * - Merges META-INF/services (ServiceLoader is how intellij-core registers).
 * - Fixed entry timestamps and sorted names: two builds of the same commit
 *   produce byte-identical jars (asserted in CI for the host platform).
 */
val kosiFatJar = tasks.register<Jar>("kosiFatJar") {
    group = "kosi"
    description = "Deterministic fat jar for native-image (KT-68829 handled)."
    archiveFileName = "kosi-all.jar"
    destinationDirectory = layout.buildDirectory.dir("dist")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    exclude(
        // KT-68829: shaded JLine ships META-INF/native-image/org.jline/...
        // properties pointing at files that are not in the jar.
        "META-INF/native-image/org.jline/**",
        "META-INF/native-image/**/jline*/**",
        // JLine is only needed by the kotlinc REPL/daemon, which kosi never
        // invokes; drop the classes as well so native-image cannot reach them.
        "org/jline/**",
        // Signature files from upstream jars cannot survive merging.
        "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC",
        "META-INF/versions/**/module-info.class", "module-info.class",
        // Native libraries of the compiler backends kosi does not use.
        "**/*.dylib", "**/*.dll", "**/*.so",
    )

    from(sourceSets.main.get().output)

    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    }) {
        exclude("META-INF/MANIFEST.MF")
    }

    // Merge ServiceLoader descriptors deterministically.
    doLast {
        val services = LinkedHashMap<String, MutableSet<String>>()
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .forEach { jar ->
                val zip = ZipFile(jar)
                zip.entries().asSequence()
                    .filter { it.name.startsWith("META-INF/services/") && !it.isDirectory }
                    .forEach { entry ->
                        val lines = zip.getInputStream(entry).bufferedReader().readLines()
                            .filter { it.isNotBlank() && !it.startsWith("#") }
                        services.getOrPut(entry.name) { LinkedHashSet() }.addAll(lines)
                    }
                zip.close()
            }
        // Rewrite in sorted order with fixed timestamps; services descriptors
        // are appended after the regular entries. Everything happens while the
        // source ZipFile is open, then both are closed.
        val target = archiveFile.get().asFile
        val tmp = ZipFile(target)
        val tmpOut = File(target.parentFile, target.name + ".tmp")
        ZipOutputStream(tmpOut.outputStream().buffered()).use { zos ->
            val serviceNames = services.keys.toSortedSet()
            val entries = tmp.entries().asSequence()
                .filter { !it.isDirectory && !it.name.startsWith("META-INF/services/") }
                .toList()
            for (entry in entries.sortedBy { it.name }) {
                val outEntry = ZipEntry(entry.name)
                outEntry.time = 315532800000L // 1980-01-01T00:00:00Z
                zos.putNextEntry(outEntry)
                tmp.getInputStream(entry).use { it.copyTo(zos) }
                zos.closeEntry()
            }
            for (name in serviceNames) {
                val outEntry = ZipEntry(name)
                outEntry.time = 315532800000L // 1980-01-01T00:00:00Z
                zos.putNextEntry(outEntry)
                zos.write(("# merged by kosiFatJar\n" + services[name]!!.sorted().joinToString("\n") + "\n").toByteArray())
                zos.closeEntry()
            }
        }
        tmp.close()
        if (!tmpOut.renameTo(target)) {
            throw GradleException("could not replace ${target.absolutePath} with rewritten fat jar")
        }
    }

    manifest {
        attributes["Main-Class"] = "io.cdxgen.kosi.cli.MainKt"
        attributes["Enable-Native-Image"] = "true"
    }
}
