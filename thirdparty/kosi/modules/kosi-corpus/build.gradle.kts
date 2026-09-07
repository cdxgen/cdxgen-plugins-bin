// kosi-corpus parses and evaluates source annotations (kosi:want / want-not)
// and is shared by the unit tests and the bench harness. Categories are
// validated against the shipped packs in kosi-models.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-models"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
