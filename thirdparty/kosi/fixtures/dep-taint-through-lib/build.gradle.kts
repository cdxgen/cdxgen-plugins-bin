plugins {
    kotlin("jvm")
}
// The helper jar is COMMITTED (libs/dep-helper.jar, built by helper-src/
// build.sh); the declaration below documents the dependency for humans and
// for the offline resolver, but kosi's classpath for this fixture comes from
// classpath.txt so no build is ever executed.
dependencies {
    implementation(files("libs/dep-helper.jar"))
}
