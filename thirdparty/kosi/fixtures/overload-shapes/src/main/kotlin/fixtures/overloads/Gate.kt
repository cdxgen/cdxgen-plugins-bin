// the corpus shape NO bundled fixture held — two real Kotlin
// overloads sharing one canonical name whose bodies differ in control
// flow. survived because of exactly this absence: the fold's
// CFG cache keyed by name answered one overload's dominator question
// with its namesake's blocks, and no fixture, unit test, golden or
// corpus tier could see it, because the corpus held no two same-named
// functions at all.
//
// The two halves pin BOTH engines at the boundary:
//
//  - The FOLDER folds `endpoint(true)` — overload A's two return sites
//    both fold to the same host, so the site publishes `folded`. Overload
//    A's body is multi-block (an early return, a branch, a store) while
//    its namesake's is a single-block parameter return: the fold's CFG,
//    return-site and defined-register views must all be keyed by
//    IDENTITY, or A's verdict is answered from B's blocks (the
//    shape, held in the corpus from here on).
//
//  - The FLOW engine applies overload B's own summary at `endpoint(raw)`:
//    B returns its parameter, so taint crosses. Pre-the summary table
//    was keyed by canonical name and kept the overload whose descriptor
//    sorts last — A, whose summary moves nothing — so the relay flow was
//    MISSED: a false negative, not a refused answer. The want below is
//    that defect's permanent teeth.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Folder half: the constant overload folds through its multi-block body.
// kosi:want service protocol=https name=gate.example.internal resolution=folded mode=resolved
// kosi:want-not service protocol=https resolution=unresolved mode=resolved
//
// Flow half: taint crosses the parameter-returning overload.
// kosi:want flow source=untrusted-input sink=process-exec fn=~relay mode=resolved
package fixtures.overloads

import okhttp3.Request

/**
 * Overload A: control flow in the body, one constant on every path. Two
 * return sites, two blocks, both folding to the same host — the folder
 * must read THIS body's blocks for THIS function.
 */
fun endpoint(secure: Boolean): String {
    if (secure) return "https://gate.example.internal"
    val fallback = "https://gate.example.internal"
    return fallback
}

/**
 * Overload B: the same canonical name, a different descriptor, a body with
 * no constants at all — a parameter return that carries taint across the
 * summary boundary.
 */
fun endpoint(payload: String): String = payload

class Api {
    fun base() {
        Request.Builder().url("${endpoint(true)}/v1/items")
    }

    fun relay() {
        val raw = readLine()!!
        ProcessBuilder(endpoint(raw))
    }
}
