plugins {
    kotlin("jvm")
}

kotlin {
    compilerOptions {
        // Above the bundled compiler's published ceiling: the kotlin-version
        // diagnostic must fire BEFORE any resolution error is reported, so
        // the report never presents the version mismatch as a finding about
        // the code (08-VERSION-POLICY.md policy 4). This fixture runs only
        // in the EAP CI job, against the newest RC.
        languageVersion = "2.5"
    }
}
