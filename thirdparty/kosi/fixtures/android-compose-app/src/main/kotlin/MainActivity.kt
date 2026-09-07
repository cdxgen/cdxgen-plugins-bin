// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not module name=app platform=ios
//
// Positive half: Android platform detection plus variant source roots.
// kosi:want module name=app platform=android
// kosi:want declaration name=MainActivity kind=class
// kosi:want declaration name=debugProbe kind=function
// kosi:want declaration name=releaseProbe kind=function
// kosi:want usage name=android.util.Log.d
package dev.kosi.fixtures.android

class MainActivity {
    fun onCreate() {
        android.util.Log.d("MainActivity", "created")
    }
}
