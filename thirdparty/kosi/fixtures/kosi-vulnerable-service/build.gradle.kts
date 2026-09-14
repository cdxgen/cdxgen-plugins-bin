// The vuln-tier entry for the cross-dependency gate: a Kotlin service with a
// REAL vulnerable dependency path. The dependency jar is COMMITTED
// (libs/timber-5.0.1.jar — the classes.jar inside the published Timber 5.0.1
// AAR, byte for byte); the declaration below documents it for humans and for
// the offline resolver, but kosi's classpath comes from classpath.txt so no
// build is ever executed.
dependencies {
    implementation(files("libs/timber-5.0.1.jar"))
}
