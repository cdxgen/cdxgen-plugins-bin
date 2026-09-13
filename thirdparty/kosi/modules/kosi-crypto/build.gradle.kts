// The crypto/CBOM collector (P8): consumes KIR + models + schema only.
// Compiler types stop at kosi-front; nothing here imports them.
dependencies {
    implementation(project(":kosi-kir"))
    implementation(project(":kosi-models"))
    implementation(project(":kosi-schema"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
