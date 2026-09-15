// P9 fixture: the Kotlin/Native + JNI/cinterop seam as native-interop
// evidence. The positive half declares the seam three ways (an `external fun`
// bound by loadLibrary, the loadLibrary binding site itself, and a cinterop
// .def under the conventional directory); the negative half is the near-miss
// every naming heuristic would report on — PLAIN functions whose names merely
// look native, a commented-out loadLibrary, and a .def-looking file outside
// the cinterop directories.
//
// kosi:want-not signal code=native-interop fn=~plainFunction
// kosi:want-not signal code=native-interop fn=~alsoPlain
// kosi:want-not signal code=native-interop fn=stray.def
// kosi:want signal code=native-interop fn=~externalHash mode=resolved
// kosi:want signal code=native-interop fn=~NativeBridge.load mode=resolved
// kosi:want signal code=native-interop fn=~nativehash.def mode=resolved
// mode=resolved: the seam is read from the lowered KIR's modifiers and
// resolved calls (the syntax tier sees neither).
package dev.kosi.native

object NativeBridge {
    // The binding site: native code enters the process here. (An init-block
    // loadLibrary is a NAMED GAP: the lowering emits no function body for an
    // object's initializer, so this fixture binds in an ordinary function.)
    fun load() {
        System.loadLibrary("nativehash")
        // System.loadLibrary("commented-out") must never be a finding.
    }
}

external fun externalHash(data: ByteArray, salt: String): ByteArray

fun plainFunction(data: ByteArray): ByteArray = data.copyOf()

fun alsoPlain(data: ByteArray): ByteArray = data.reversedArray()
