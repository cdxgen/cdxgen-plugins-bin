// kosi-graph builds the call graph from lowered KIR modules (02-ARCHITECTURE.md
// §5): dispatch resolution per mode, roots, reachability, and the post-hoc
// view filter with collapsed bridge edges. It consumes kosi-kir and
// kosi-schema types ONLY — compiler types stop at kosi-front (the boundary
// test in kosi-front fails the build on a violation).
dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-kir"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
