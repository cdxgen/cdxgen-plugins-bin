plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "dev.kosi.fixtures.android"
    compileSdk = 36

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }
}
