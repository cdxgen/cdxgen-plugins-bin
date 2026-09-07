plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

android {
    namespace = "fixtures.kmp"
}

kotlin {
    androidTarget()
    jvm()

    sourceSets {
        val commonMain by getting
        val androidMain by getting
        val jvmMain by getting
    }
}
