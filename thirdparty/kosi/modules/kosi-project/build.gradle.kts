// kosi-project discovers modules and source sets by parsing build files
// (Gradle, Maven, AGP, KMP). Build files are parsed as text, never executed.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
