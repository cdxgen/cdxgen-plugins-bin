// kosi-export renders kosi artifacts to interchange formats. P3 ships the
// call-graph exporters (GraphML, GEXF) — hand-rolled, deterministic, same
// discipline as the JSON writer: sorted, minified, byte-identical across
// runs. Compiler types stop at kosi-front; this module sees schema types.
dependencies {
    implementation(project(":kosi-schema"))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
