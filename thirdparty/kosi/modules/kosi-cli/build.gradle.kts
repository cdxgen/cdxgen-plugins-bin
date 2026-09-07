// kosi-cli: hand-rolled argument parsing, subcommands (analyze, bench,
// golden, version), exit codes and diagnostics printing. No CLI library.
plugins {
    application
}

dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-project"))
    implementation(project(":kosi-front"))
    implementation(project(":kosi-corpus"))
    implementation(project(":kosi-bench"))
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
