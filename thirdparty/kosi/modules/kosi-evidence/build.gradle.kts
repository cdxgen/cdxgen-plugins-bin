// kosi-evidence: non-flow security evidence collectors (02-ARCHITECTURE.md
// §8). Adds the native-interop seam (JNI / external fun / cinterop).
dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-kir"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
