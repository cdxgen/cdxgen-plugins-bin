// kosi — Kotlin Source Inspector. Module layout mirrors docs in
// $HOME/kotlin-plans/02-ARCHITECTURE.md; every module owns one concern.

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    // -PkotlinVersion overrides the catalog's kotlin version (the EAP CI job
    // uses this to build against the newest RC); everything else in
    // gradle/libs.versions.toml stays the release pin.
    versionCatalogs {
        create("libs") {
            val eap = providers.gradleProperty("kotlinVersion")
            if (eap.isPresent) {
                version("kotlin", eap.get())
            }
        }
    }
    repositories {
        mavenCentral()
        // The Analysis API `-for-ide` artifacts are published only here, not
        // on Maven Central. Do not declare the shadowed analysis-api-*-base
        // modules separately; they are merged into the -for-ide jars (and
        // their POM entries 404 — resolved non-transitively instead).
        maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies/")
        // The unrelocated IntelliJ platform modules
        // (com.jetbrains.intellij.platform:*) the standalone session needs.
        // This is the repository JetBrains documents for platform artifacts;
        // the version is pinned in gradle/libs.versions.toml to the build
        // Kotlin itself declares (versions.intellijSdk at tag v2.4.0).
        maven("https://www.jetbrains.com/intellij-repository/releases")
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
