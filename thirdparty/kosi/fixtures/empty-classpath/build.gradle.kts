plugins {
    kotlin("jvm")
}

// The coordinate below does not exist on any machine: offline resolution can
// never find it, which is what makes this fixture's classpath deliberately
// emptied without depending on a particular developer's cache state.
dependencies {
    implementation("com.example.unresolvable:gone:1.0.0")
}
