plugins {
    kotlin("jvm")
}

kotlin {
    compilerOptions {
        // 08-VERSION-POLICY.md §4 fixture 1: below FIRST_SUPPORTED. kosi
        // clamps to the band floor, emits kotlin-language-version, and keeps
        // analysing: the parser reads 1.x-era sources at 2.x language
        // versions.
        languageVersion = "1.9"
    }
}
