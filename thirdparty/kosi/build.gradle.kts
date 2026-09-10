// Root build for kosi. Per-module configuration is kept small and uniform:
// Kotlin/JVM, toolchain 21, kotlin-test via JUnit Platform, and the
// dependency allowlist from docs (02-ARCHITECTURE.md §1). Nothing outside the
// allowlist may be added without changing that doc first.

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}

/**
 * kosi is a headless CLI, but the Analysis API drags in intellij-core, which
 * initialises AWT. On macOS that registers a real application: every analyze
 * run — every test worker, every bench fixture — bounces in the Dock and
 * STEALS KEYBOARD FOCUS, which makes a corpus run over 35 fixtures unusable
 * on the machine running it. `apple.awt.UIElement` keeps the process out of
 * the Dock and the focus list; `java.awt.headless` stops the toolkit loading
 * at all. Applied to every JVM this build starts, and to the installed
 * launcher so a user's own `kosi analyze` is quiet too.
 */
val HEADLESS_JVM_ARGS = listOf("-Djava.awt.headless=true", "-Dapple.awt.UIElement=true")

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")

    // Repositories come from settings.gradle.kts dependencyResolutionManagement
    // so every module resolves against exactly the same list.

    the<JavaPluginExtension>().toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }

    configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        compilerOptions {
            // Bytecode target 21: native-image builds run on a GraalVM JDK 25
            // toolchain, and cdxgen helper environments ship JDK 21+.
            jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging {
            events("failed", "skipped")
            showExceptions = true
        }
        // Keep corpus runs deterministic: one worker, fixed locale/timezone.
        maxParallelForks = 1
        systemProperty("user.language", "en")
        systemProperty("user.country", "US")
        systemProperty("user.timezone", "UTC")
        jvmArgs(HEADLESS_JVM_ARGS)
    }
}

// Tier tasks named in the docs (07-REVIEW-PROTOCOL.md). Every tier is a real
// Gradle task exercised by CI; a renamed or missing tier task fails CI
// (06-CORPUS.md §5, "documented test commands must actually run").
val kosiCli = project(":kosi-cli")

fun kosiTask(name: String, description: String, configure: JavaExec.() -> Unit) =
    tasks.register(name, JavaExec::class) {
        group = "kosi"
        this.description = description
        dependsOn(kosiCli.tasks.named("jar"))
        classpath = kosiCli.objects.fileCollection().from(
            kosiCli.configurations.getByName("runtimeClasspath"),
            kosiCli.tasks.named("jar").map { (it as Jar).archiveFile },
        )
        mainClass = "io.cdxgen.kosi.cli.MainKt"
        jvmArgs(HEADLESS_JVM_ARGS)
        configure(this)
    }

kosiTask("corpusQuick", "Fixture tier: the annotation ratchet in both modes, no network.") {
    args = listOf("bench", "--tier", "fixtures", "--repo-root", rootDir.absolutePath)
}

kosiTask("corpusAsync", "Async tier (P6): coroutine/Flow fixtures, run and gated separately.") {
    args = listOf("bench", "--tier", "async", "--repo-root", rootDir.absolutePath)
}

kosiTask("corpusFull", "Fixture + async + pinned-repo tiers (network required for repo fetches).") {
    args = listOf(
        // Every tier the manifest actually carries. The old list named
        // `vuln` and `ported`, which have never existed, and omitted
        // `medium`, `android`, `kmp` and `hybrid` — four of the five pinned
        // repos — so the "full" run measured one of them (R64).
        "bench", "--tier", "fixtures,async,small,medium,android,kmp,hybrid",
        "--repo-root", rootDir.absolutePath,
        "--skip-missing-repos",
    )
}

kosiTask("kosiEap", "EAP tier: fixtures using the next version's syntax (only meaningful with -PkotlinVersion=<rc>).") {
    args = listOf("bench", "--tier", "eap", "--repo-root", rootDir.absolutePath)
}

kosiTask("golden", "Verify digest goldens for every fixture in both modes.") {
    args = listOf("golden", "--repo-root", rootDir.absolutePath)
}

kosiTask("goldenUpdate", "Regenerate digest goldens after an intentional behavior change.") {
    args = listOf("golden", "--update-goldens", "--repo-root", rootDir.absolutePath)
}

tasks.register("corpusTierList") {
    group = "kosi"
    description = "Lists the tier tasks CI must be able to run; fails if one is missing."
    doLast {
        val required = listOf("corpusQuick", "corpusAsync", "corpusFull", "kosiEap", "golden", "goldenUpdate")
        val missing = required.filter { tasks.names.none { n -> n == it } }
        if (missing.isNotEmpty()) {
            throw GradleException("missing kosi tier tasks: $missing")
        }
        println("kosi tier tasks: $required")
    }
}
