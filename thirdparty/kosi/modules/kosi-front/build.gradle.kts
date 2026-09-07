// kosi-front is the ONLY module allowed to import Analysis API, PSI, FIR or
// IntelliJ platform types (enforced by an import-scanning test). The syntax
// backend parses PSI directly from kotlin-compiler-embeddable; the Analysis
// API standalone artifacts are the substrate for the resolved tier.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-project"))
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlin.compiler.embeddable)
    // The -for-ide jars shadow the transitive base modules (their classes are
    // inside the jar) but their POMs still declare them — and those modules
    // are not published on any repository we can reach (verified 2026-09 for
    // 2.4.0: neither Maven Central nor the JetBrains intellij-dependencies
    // repo serves them). Exclude the phantom transitives; detekt carries the
    // same exclusion.
    implementation(libs.analysis.api.ide) {
        exclude("org.jetbrains.kotlin", "analysis-api")
    }
    implementation(libs.analysis.api.standalone.ide) {
        exclude("org.jetbrains.kotlin", "analysis-api-standalone-base")
        exclude("org.jetbrains.kotlin", "analysis-api-fir-standalone-base")
        exclude("org.jetbrains.kotlin", "analysis-api-standalone")
    }
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
