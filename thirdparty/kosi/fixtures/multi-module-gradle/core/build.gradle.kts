plugins {
    kotlin("jvm")
}

kotlin {
    compilerOptions {
        // Declares a version below the supported band: kosi must clamp and
        // emit a kotlin-language-version diagnostic, not refuse to run.
        languageVersion = KotlinVersion.KOTLIN_1_9
    }
}
