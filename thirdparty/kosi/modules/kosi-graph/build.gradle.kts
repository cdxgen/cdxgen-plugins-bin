// Placeholder module for a later phase (see README.md in this directory).
// It stays wired into the build so the layout cannot drift.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
