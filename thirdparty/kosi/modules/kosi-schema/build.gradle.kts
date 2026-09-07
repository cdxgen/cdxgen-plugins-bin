// kosi-schema owns the v1 report types (03-SCHEMA.md), the hand-rolled
// streaming JSON writer/reader, and the option vocabulary shared by the CLI
// and the bench harness. It must stay dependency-free apart from the stdlib:
// no kotlinx.serialization, no reflection.
dependencies {
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
