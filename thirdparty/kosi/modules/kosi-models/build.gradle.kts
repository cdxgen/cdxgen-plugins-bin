// kosi-models ships the JSON model packs (sources/sinks/passthroughs/
// sanitizers/effects) and the category registry they define. Patterns use the
// single normalised notation documented in JSON_ATTRIBUTE_REFERENCE.md and
// validated by a build-time test.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
