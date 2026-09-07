// kosi — Kotlin Source Inspector. Module layout mirrors docs in
// $HOME/kotlin-plans/02-ARCHITECTURE.md; every module owns one concern.

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // The Analysis API standalone modules are published only here, not on
        // Maven Central. Do not declare the shadowed analysis-api-*-base
        // modules separately; they are merged into the -for-ide jars.
        maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies/")
    }
}

rootProject.name = "kosi"

include(
    ":kosi-schema",
    ":kosi-project",
    ":kosi-front",
    ":kosi-kir",
    ":kosi-graph",
    ":kosi-flow",
    ":kosi-models",
    ":kosi-bytecode",
    ":kosi-evidence",
    ":kosi-export",
    ":kosi-corpus",
    ":kosi-bench",
    ":kosi-cli",
)

// All modules live under modules/ to keep the repository root for docs,
// fixtures, corpus and the native-image metadata.
for (project in rootProject.children) {
    project.projectDir = file("modules/${project.name}")
}
