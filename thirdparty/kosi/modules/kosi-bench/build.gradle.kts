// kosi-bench runs the corpus matrix (security and all slots), computes the
// metrics, writes/compares baselines and digests, and implements the
// promotion gate. It must construct its options from the CLI defaults.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-project"))
    implementation(project(":kosi-front"))
    implementation(project(":kosi-corpus"))
    implementation(project(":kosi-models"))
    // Liveness gate: the test re-runs Endpoints.analyze per removed
    // pack entry, and kosi-endpoints rides kosi-front as an implementation
    // dependency that tests cannot see.
    testImplementation(project(":kosi-endpoints"))
    testImplementation(project(":kosi-kir"))
    // Depth report: EndpointCapture carries the taint engine's
    // DepthStats, whose type rides kosi-front as an implementation
    // dependency that tests cannot see.
    testImplementation(project(":kosi-flow"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
