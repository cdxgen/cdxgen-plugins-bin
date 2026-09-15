plugins {
    kotlin("jvm") version "2.4.0"
    application
}

// The sample project for the kosi end-to-end gate: a small audit service
// with a cross-dependency log flow, a workspace SQL flow, crypto material
// and an outbound JDBC service. kosi never executes this build — the
// analysis classpath comes from classpath.txt (libs/timber-5.0.1.jar, the
// real published classes.jar) so the run is deterministic and offline.
dependencies {
    implementation(files("libs/timber-5.0.1.jar"))
}

application {
    mainClass.set("com.example.audit.MainKt")
}
