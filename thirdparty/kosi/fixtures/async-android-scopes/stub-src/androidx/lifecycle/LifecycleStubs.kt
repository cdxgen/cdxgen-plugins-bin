// The androidx symbols async-android-scopes imports, as the real artifacts
// declare them (sourced, per the P17 rule, before the stub was written):
//
//   androidx.lifecycle.ViewModel — open class with onCleared()
//     (androidx.lifecycle:lifecycle-viewmodel 2.8.0). The -ktx AAR that
//     names it in this fixture's build file is a 222-byte forwarding shell
//     at 2.8.0 (measured from the cached artifact) — the API lives in the
//     transitive lifecycle-viewmodel, which is why cache-only resolution
//     could never be deterministic for this fixture.
//   androidx.lifecycle.viewModelScope — extension property on ViewModel
//     (ViewModelKt; same transitive closure).
//   androidx.compose.runtime.LaunchedEffect — @Composable
//     fun LaunchedEffect(key1: Any?, body: suspend CoroutineScope.() -> Unit)
//     (androidx.compose.runtime:runtime 1.6.0, Composables.kt). The
//     @Composable annotation is a compose-compiler concern the resolver
//     does not need, so the stub omits it.
//
// kotlinx.coroutines.* is NOT stubbed: the committed REAL artifact
// (../shared-libs, byte-identical to Maven Central's
// kotlinx-coroutines-core-jvm-1.8.0.jar) is on the stub's compile classpath
// and on the fixture's analysis classpath.
package androidx.lifecycle

import kotlinx.coroutines.CoroutineScope

open class ViewModel {
    open fun onCleared() {}
}

val ViewModel.viewModelScope: CoroutineScope
    get() = throw UnsupportedOperationException("stub")
