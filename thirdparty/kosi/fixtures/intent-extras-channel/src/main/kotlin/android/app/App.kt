package android.app

abstract class Activity {
    // A property whose JVM getter is getIntent() — the real platform's
    // shape from Kotlin's side.
    val intent: android.content.Intent get() = android.content.Intent()
    fun startActivity(intent: android.content.Intent) {}
}
