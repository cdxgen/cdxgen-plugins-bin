// kosi-front is the ONLY module allowed to import Analysis API, PSI, FIR or
// IntelliJ platform types (enforced by an import-scanning test). P0 ran the
// syntax tier on kotlin-compiler-embeddable, whose IntelliJ platform is
// shaded under org.jetbrains.kotlin.com.intellij; P0's recorded deviation 2
// proved the standalone Analysis API session cannot be constructed against a
// shaded platform at all. P1 amends the dependency allowlist
// (02-ARCHITECTURE.md §1) to the working set KSP2 declares for the same
// Kotlin base: unrelocated `-for-ide` split artifacts, the unrelocated
// IntelliJ platform, and their third-party libraries. The shaded
// kotlin-compiler-embeddable is gone: mixing both jars would duplicate every
// org.jetbrains.kotlin class on one classpath, and the embeddable variant is
// binary-incompatible with the unrelocated Analysis API implementations
// (KtFile would extend the shaded PsiFile the session never sees).
// The 2.4 Analysis API surfaces its session-scoped operations as
// context-parameter declarations; consuming them needs the feature enabled
// in the consumer too (08-VERSION-POLICY.md: 2.4 syntax is in-band).
kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xcontext-parameters")
    }
}

// The resolved tier resolves builtin declarations against a REAL stdlib jar
// (the native image has no classpath jars on disk), so the stdlib file ships
// as a resource next to the code that materializes it.
val kosiStdlibJar = configurations.create("kosiStdlib") {
    attributes {
        attribute(
            org.gradle.api.attributes.Usage.USAGE_ATTRIBUTE,
            objects.named(org.gradle.api.attributes.Usage::class, org.gradle.api.attributes.Usage.JAVA_RUNTIME),
        )
        attribute(
            org.gradle.api.attributes.LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE,
            objects.named(org.gradle.api.attributes.LibraryElements::class, org.gradle.api.attributes.LibraryElements.JAR),
        )
    }
}
dependencies {
    add("kosiStdlib", "org.jetbrains.kotlin:kotlin-stdlib:2.4.0") { isTransitive = false }
}
tasks.processResources {
    dependsOn(kosiStdlibJar)
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    from(kosiStdlibJar) {
        rename { "kosi-libs/kotlin-stdlib.jar" }
    }
}

dependencies {
    implementation(project(":kosi-schema"))
    implementation(project(":kosi-project"))
    implementation(project(":kosi-kir"))
    implementation(project(":kosi-graph"))
    // P4: the taint engine and the model packs it runs on — both
    // compiler-free, so the kosi-front boundary still holds.
    implementation(project(":kosi-flow"))
    implementation(project(":kosi-endpoints"))
    implementation(project(":kosi-crypto"))
    implementation(project(":kosi-models"))
    implementation(libs.kotlin.stdlib)

    // Analysis API + unrelocated compiler. Non-transitive on purpose: the
    // -for-ide POMs declare shadowed modules that are published nowhere
    // (P0 deviation 2); transitive resolution would fail outright.
    listOf(
        libs.analysis.api.ide,
        libs.analysis.api.k2.ide,
        libs.analysis.api.standalone.ide,
        libs.analysis.api.impl.base.ide,
        libs.analysis.api.platform.ide,
        libs.low.level.api.fir.ide,
        libs.symbol.light.classes.ide,
        libs.compiler.common.ide,
        libs.compiler.fir.ide,
        libs.compiler.fe10.ide,
        libs.compiler.ir.ide,
    ).forEach {
        implementation(it) { isTransitive = false }
    }

    // Unrelocated IntelliJ platform (their POMs pull the remaining util-*
    // modules transitively) and the third-party libraries KSP2 pins.
    implementation(libs.platform.util.rt)
    implementation(libs.platform.util.cl)
    implementation(libs.platform.util.text.matching)
    implementation(libs.platform.util)
    implementation(libs.platform.util.base)
    implementation(libs.platform.util.coroutines)
    implementation(libs.platform.util.xml.dom)
    implementation(libs.platform.core)
    implementation(libs.platform.core.impl)
    implementation(libs.platform.extensions)
    implementation(libs.platform.diagnostic)
    implementation(libs.platform.diagnostic.telemetry)
    implementation(libs.java.frontback.psi)
    implementation(libs.java.frontback.psi.impl)
    implementation(libs.java.psi)
    implementation(libs.java.psi.impl)

    implementation(libs.aa.guava)
    implementation(libs.aa.asm)
    implementation(libs.aa.stax2)
    implementation(libs.aa.aalto.xml)
    implementation(libs.aa.streamex)
    implementation(libs.aa.fastutil) { isTransitive = false }
    implementation(libs.aa.jna) { isTransitive = false }
    implementation(libs.aa.jna.platform) { isTransitive = false }
    implementation(libs.aa.trove4j)
    implementation(libs.aa.log4j)
    implementation(libs.aa.jdom)
    implementation(libs.aa.coroutines)
    implementation(libs.aa.serialization.json)
    implementation(libs.aa.annotations)
    implementation(libs.aa.lz4) { isTransitive = false }
    implementation(libs.aa.opentelemetry) { isTransitive = false }
    implementation(libs.aa.collections.immutable)
    implementation(libs.aa.caffeine)
    implementation(libs.aa.javax.inject)

    // FlowFoundAcrossLanguageVersionRange evaluates corpus expectations; the
    // corpus module is compiler-free, so the kosi-front boundary holds.
    testImplementation(project(":kosi-corpus"))
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit5)
    testRuntimeOnly(libs.junit.platform.launcher)
}
