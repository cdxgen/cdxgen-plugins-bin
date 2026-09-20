// Root build for kosi. Per-module configuration is kept small and uniform:
// Kotlin/JVM, toolchain 21, kotlin-test via JUnit Platform, and the
// dependency allowlist from docs (02-ARCHITECTURE.md §1). Nothing outside the
// allowlist may be added without changing that doc first.

import java.io.File

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

/**
 * P28 review: the heap the corpus/bench tier forks with, in GiB.
 *
 * `-Pkosi.testHeapGb=<n>` pins it (CI passes 6, the number P15 calibrated to
 * the runners). Unset, a developer's machine takes HALF its physical RAM,
 * clamped to [6, 24] — the standing rule is that the big tests run locally,
 * and a tier capped at a CI runner's budget cannot host the repos P28 exists
 * to analyse: dagger produces no report at all under 8g.
 *
 * Clamped at both ends on purpose. The floor keeps a small machine at the
 * measured-good 6g rather than something that GC-thrashes; the ceiling stops
 * a 128 GiB workstation from reserving 64 GiB it will never touch, which
 * turns a quick suite into a paging one.
 */
val kosiTestHeapGb: Int = (findProperty("kosi.testHeapGb") as String?)?.toIntOrNull()
    ?: run {
        val physicalGb = try {
            (java.lang.management.ManagementFactory.getOperatingSystemMXBean()
                as? com.sun.management.OperatingSystemMXBean)
                ?.totalMemorySize?.div(1L shl 30)?.toInt()
        } catch (_: Throwable) {
            null
        }
        ((physicalGb ?: 12) / 2).coerceIn(6, 24)
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
        jvmArgs(HEADLESS_JVM_ARGS)
    }
}

// Tier tasks named in the docs (07-REVIEW-PROTOCOL.md). Every tier is a real
// Gradle task exercised by CI; a renamed or missing tier task fails CI
// (06-CORPUS.md §5, "documented test commands must actually run").
val kosiCli = project(":kosi-cli")

// The kosi jar is Java-21 bytecode, but these tasks are registered on the
// ROOT project, which applies no Java toolchain — without an explicit
// launcher a JavaExec runs on Gradle's own JVM, and on a JDK-17 runner that
// is UnsupportedClassVersionError: class file 65 read by a class-61 runtime
// (the corpusQuick CI failure). Launch every tier task on the same 21
// toolchain the compilation uses; Test tasks in the subprojects already
// launch on it by default. The launcher comes from kosi-cli (which applies
// the JVM plugin and therefore carries the toolchain service); lazy so the
// subproject's plugins are applied before the service is queried.
val kosiLauncher by lazy {
    kosiCli.the<org.gradle.jvm.toolchain.JavaToolchainService>().launcherFor {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

fun kosiTask(name: String, description: String, configure: JavaExec.() -> Unit) =
    tasks.register(name, JavaExec::class) {
        group = "kosi"
        this.description = description
        javaLauncher = kosiLauncher
        dependsOn(kosiCli.tasks.named("jar"))
        classpath = kosiCli.objects.fileCollection().from(
            kosiCli.configurations.getByName("runtimeClasspath"),
            kosiCli.tasks.named("jar").map { (it as Jar).archiveFile },
        )
        mainClass = "io.cdxgen.kosi.cli.MainKt"
        // Bounded heap: the resolved-tier analysis peaks around 1 GiB on the
        // bundled fixtures; an unbounded default heap (25% of runner RAM)
        // makes this fork the OOM killer's first target on a shared CI box,
        // and a SIGKILLed JVM dies without a single line of output. Loud on
        // exhaustion, small at rest. hs_err files land in the project dir
        // (a native crash must leave evidence, not a silent gap).
        jvmArgs(
            HEADLESS_JVM_ARGS + listOf(
                // The bench runs ~315 analysis sessions in ONE JVM: IntelliJ
                // session caches accumulate (the unbounded fork peaked at
                // 10.3GB VmHWM locally), and on a loaded 16GB CI runner the
                // OS OOM killer then takes the whole process tree — silently.
                // Heap, metaspace and direct memory are all pinned so the
                // fork's total RSS stays bounded; ExitOnOutOfMemoryError
                // makes exhaustion a LOUD failure, not a vanished runner.
                // 3g, recalibrated in P9: the --deps tier adds the lowered
                // dependency KIR and its summaries to the workspace session,
                // and at 2g the pinned repo tiers OOMed the fork (loud, via
                // ExitOnOutOfMemoryError, but dead). ~4 GiB total still fits
                // the CI runners the matrix runs on.
                // Metaspace 512m -> 1g in P14 (the fully-warmed resolved
                // sessions attach far more dependency classes than 512m
                // survives — NoClassDefFoundError 65 minutes into a run).
                // The heap went 3g -> 8g in the same change and comes BACK
                // to 3g in P15: the 8g was never the workspace sessions'
                // cost, it was the deps tier's composed summary sink-effects
                // multiplying through unbounded param-path joins until one
                // function's escape set held 68M entries (measured with a
                // mid-run GC.class_histogram: 3.8GB SummarySinkEffect +
                // 3.8GB byte[]/String). P15 caps the joins at the engine's
                // access-path depth and budgets the escape set like the
                // state; AndroGoat's 161-jar classpath now lowers its whole
                // 300-class closure at a ~1 GiB peak in a FRESH JVM. The
                // matrix still needs 6g: ~500 sessions share one JVM and the
                // Analysis API's per-session caches accumulate (the
                // pre-P9 note in this file), the from-empty warm attaches
                // each repo's FULL transitive closure (20-40% more jars
                // than the stale partial lists P14 measured against), and
                // the deps cap is retired. At 3g and 4g the warmed matrix
                // GC-thrashed without dying (measured, P15); 6g completes,
                // and the ceiling is a measurement, not a concession.
                //
                // P28 review: 6g stays the CI ceiling (it is calibrated to
                // the runners the matrix runs on, and a fork that outgrows a
                // shared box dies as a SIGKILL with no output). It is NOT a
                // ceiling for a developer's machine, where the standing rule
                // is that the bigger tests run locally: dagger needs more
                // than 8g to produce a report at all, so a 6g tier is a tier
                // that cannot host the repos this phase exists to analyse.
                // Local runs take half of physical RAM, clamped to [6, 24]
                // GiB; CI and anyone who wants the old number pass
                // -Pkosi.testHeapGb=6. Whatever is chosen is PRINTED below
                // beside the JVM, because a heap that changes by machine and
                // is never stated is how a reproduction stops reproducing.
                "-Xmx${kosiTestHeapGb}g",
                "-XX:MaxMetaspaceSize=1g",
                "-XX:MaxDirectMemorySize=256m",
                "-XX:+ExitOnOutOfMemoryError",
                "-XX:ErrorFile=" + File(rootDir.absolutePath, "hs_err_vm_%p.log").absolutePath,
            ),
        )
        doFirst {
            // Which JVM actually runs this tier: the CI corpusQuick hang
            // (silent, ~34s in, twice) was undiagnosable without this line.
            println(
                "kosi tier JVM: " + javaLauncher.get().metadata.languageVersion.asInt() +
                    " @ " + javaLauncher.get().executablePath.asFile.absolutePath +
                    // P28 review: the heap now varies by machine (half of
                    // physical, unless -Pkosi.testHeapGb pins it). An
                    // unstated varying heap is how one machine's green run
                    // and another's OOM become impossible to compare.
                    " heap=" + kosiTestHeapGb + "g" +
                    if (findProperty("kosi.testHeapGb") != null) " (pinned)" else " (auto: half of physical)",
            )
        }
        configure(this)
    }

kosiTask("corpusQuick", "Bundled tiers: fixture + framework + crypto + async + vuln ratchets, no network.") {
    args = listOf("bench", "--tier", "fixtures,frameworks,crypto,async,vuln,deep", "--repo-root", rootDir.absolutePath)
}

kosiTask("corpusAsync", "Async tier (P6): coroutine/Flow fixtures, run and gated separately.") {
    args = listOf("bench", "--tier", "async", "--repo-root", rootDir.absolutePath)
}

kosiTask("corpusFull", "Fixture + async + pinned-repo tiers (network required for repo fetches).") {
    args = listOf(
        // Every tier the manifest actually carries. The old list named
        // `vuln` and `ported`, which have never existed, and omitted
        // `medium`, `android`, `kmp` and `hybrid` — four of the five pinned
        // repos — so the "full" run measured one of them (R64). `vuln`
        // exists since P11 (the bundled vulnerable service); `vuln-repo`
        // since P14 (the pinned deliberately-vulnerable apps whose finding
        // floors the findings ratchet enforces).
        "bench", "--tier", "fixtures,async,vuln,vuln-repo,small,medium,android,kmp,hybrid",
        "--repo-root", rootDir.absolutePath,
        "--skip-missing-repos",
    )
}

// P20 §5: the corpusChanged middle tier's repo-row runner. scripts/
// corpus-changed.sh selects the repo slugs whose declared capabilities the
// change can move, then invokes this with -Pkosi.only=slug1,slug2. A cold
// cache on one repo is a skipped row (--skip-missing-repos), never a dead
// matrix; the floors ride it every time because the script always selects
// them.
kosiTask("kosiRepoRows", "Repo-tier rows selected by scripts/corpus-changed.sh (-Pkosi.only=slug,slug).") {
    doFirst {
        val only = (project.findProperty("kosi.only") as String?)
            ?: throw GradleException("kosiRepoRows needs -Pkosi.only=slug1,slug2 (see scripts/corpus-changed.sh)")
        val tiers = (project.findProperty("kosi.repo-tiers") as String?)
            ?: "vuln-repo,small,medium,android,kmp,hybrid"
        args = listOf(
            "bench",
            "--tier", tiers,
            "--repo-root", rootDir.absolutePath,
            "--only", only,
            "--skip-missing-repos",
        )
    }
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
