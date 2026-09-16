// P9: the dependency-jar tier. Reads class files with the same allowlisted
// ASM the front end ships, demangles Kotlin names via `@kotlin.Metadata`
// (the protobuf reader ships in kotlin-compiler-common-for-ide, already on
// the runtime classpath), and lowers method bodies into the SAME KIR the
// source front end produces — one IR, one summariser (kosi-flow runs the
// summaries; this module only produces the KirModule and its counters).

dependencies {
    implementation(project(":kosi-kir"))
    // The `@kotlin.Metadata` protobuf reader lives in the same compiler
    // artifact the front already ships. Non-transitive like every -for-ide
    // jar: their POMs name shadowed modules published nowhere (P0
    // deviation 2).
    implementation(libs.compiler.common.ide) { isTransitive = false }
    implementation(libs.aa.asm)
    implementation(libs.kotlin.stdlib)
    // Test-only: P18's symbol-kind validation reads the endpoints pack from
    // kosi-models and checks its modelled symbols against the framework
    // sources/jars the corpus machine holds (ASM is here for the jar half).
    testImplementation(project(":kosi-models"))
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
