// Root build for kosi. Per-module configuration is kept small and uniform:
// Kotlin/JVM, toolchain 21, kotlin-test via JUnit Platform, and the
// dependency allowlist from docs (02-ARCHITECTURE.md §1). Nothing outside the
// allowlist may be added without changing that doc first.

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}

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
        configure(this)
    }

kosiTask("corpusQuick", "Fixture tier: the annotation ratchet in both modes, no network.") {
    args = listOf("bench", "--tier", "fixtures", "--repo-root", rootDir.absolutePath)
}

kosiTask("corpusFull", "Fixture + pinned-repo tiers (network required for repo fetches).") {
    args = listOf(
        "bench", "--tier", "fixtures,small,vuln,ported",
        "--repo-root", rootDir.absolutePath,
        "--skip-missing-repos",
    )
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
        val required = listOf("corpusQuick", "corpusFull", "golden", "goldenUpdate")
        val missing = required.filter { tasks.names.none { n -> n == it } }
        if (missing.isNotEmpty()) {
            throw GradleException("missing kosi tier tasks: $missing")
        }
        println("kosi tier tasks: $required")
    }
}
