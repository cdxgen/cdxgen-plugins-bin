import org.gradle.api.attributes.Attribute
import org.gradle.api.artifacts.ResolvedDependency

plugins { base }
// jitpack.io: repositories the corpus repos themselves declare (AndroGoat
// pulls com.github.yuriy-budiyev:code-scanner from jitpack; without it the
// closure pull fails the whole arm for one coordinate).
repositories { google(); mavenCentral(); maven { url = uri("https://jitpack.io") } }

val coords = File(rootProject.projectDir, "coords.txt").readLines()
    .map { it.trim() }.filter { it.isNotEmpty() && it.split(":").size >= 3 }

// The RESOLVED transitive closure, printed so the caller can list it: the
// textual fallback arm extracts a build file's DIRECT declarations, and a
// direct-only classpath leaves the transitive tree (appcompat without
// fragment/core, ktor without kotlinx) unattached — InsecureShop's
// activities then degrade with MISSING_DEPENDENCY_SUPERCLASS and its
// finding floor measures zero against a warm-looking classpath.
fun ResolvedDependency.walk(seen: MutableSet<String>) {
    val id = "$moduleGroup:$moduleName:$moduleVersion"
    if (seen.add(id)) children.forEach { it.walk(seen) }
}

tasks.register("resolveAll") { doLast {
    var ok = 0
    var failed = 0
    val androidJvm = Attribute.of("org.jetbrains.kotlin.platform.type", String::class.java)
    val libraryElements = Attribute.of("org.gradle.libraryelements", String::class.java)
    val category = Attribute.of("org.gradle.category", String::class.java)
    val usage = Attribute.of("org.gradle.usage", String::class.java)
    val jvmEnvironment = Attribute.of("org.gradle.jvm.environment", String::class.java)
    fun resolve(c: String, aar: Boolean) {
        val dep = configurations.detachedConfiguration(dependencies.create(c))
        dep.isTransitive = true
        if (aar) dep.attributes {
            attribute(androidJvm, "androidJvm")
            attribute(libraryElements, "aar")
            attribute(category, "library")
        } else {
            // an ATTRIBUTE-LESS detached configuration cannot select
            // a variant from multi-variant Gradle Module Metadata — guava
            // (jre/android), robolectric, the compose KMP roots all failed
            // here with VariantSelectionByAttributesException, so their
            // binaries never entered the cache and kosi reported them
            // unlocatable with "no binary anywhere on disk" — a WARM defect
            // wearing a resolver's clothes: every one is published. The JVM
            // consumer attributes select the standard-jvm runtime variant;
            // AndroidX AARs still come through the aar arm.
            dep.attributes {
                attribute(usage, "java-runtime")
                attribute(jvmEnvironment, "standard-jvm")
            }
        }
        val seen = linkedSetOf<String>()
        dep.resolvedConfiguration.firstLevelModuleDependencies.forEach { it.walk(seen) }
        seen.forEach { println("resolved $it") }
        // dependency metadata resolution does NOT download artifacts
        // — walking the module tree left BINARY files undownloaded, so the
        // cache held.module/.pom (and sometimes a sources jar) with no jar
        // or AAR anywhere on disk, and kosi honestly reported the coordinate
        // unlocatable. resolve() forces every artifact of the selected
        // variant to the cache, which is the whole point of warming.
        dep.resolve()
    }
    fun fetchArtifactOnly(c: String) {
        // Metadata-hostile stragglers: the artifact-only notation fetches
        // the binary without variant selection (no transitives — the arms
        // above own transitive warming).
        for (ext in listOf("jar", "aar")) {
            try {
                val dep = configurations.detachedConfiguration(dependencies.create("$c@$ext"))
                dep.isTransitive = false
                dep.resolve()
                println("resolved $c")
                return
            } catch (_: Throwable) { }
        }
        throw IllegalStateException("no binary at $c")
    }
    for (c in coords) {
        try {
            resolve(c, aar = false); ok++
        } catch (t: Throwable) {
            // AndroidX multiplatform artifacts publish AAR variants a plain
            // JVM consumer cannot match; retry with AAR variant attributes.
            try {
                resolve(c, aar = true); ok++
            } catch (t2: Throwable) {
                try {
                    fetchArtifactOnly(c); ok++
                } catch (_: Throwable) { failed++ }
            }
        }
    }
    println("downloaded $ok, failed $failed")
} }
