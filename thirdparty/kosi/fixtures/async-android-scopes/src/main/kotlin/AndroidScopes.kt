// The Android scope shapes the pinned repos actually contain:
// viewModelScope.launch {} and LaunchedEffect. Resolution degrades loudly
// when the Android jars are absent from the caches; the builder bodies are
// analysed regardless (the lowering inlines them by name), so the taint
// question is answerable either way.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanViewModel known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~loadViewModel known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~refreshEffect known-fail=syntax:1
package fixtures.async.android

import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

class LoadViewModel : ViewModel() {
    fun loadViewModel() {
        viewModelScope.launch {
            ProcessBuilder(readLine() ?: "")
        }
    }
}

class CleanViewModel : ViewModel() {
    fun cleanViewModel() {
        viewModelScope.launch {
            ProcessBuilder("safe")
        }
    }
}

fun refreshEffect() {
    LaunchedEffect(Unit) {
        ProcessBuilder(readLine() ?: "")
    }
}
