// P16 §3: P15 gave catch handlers their incoming CFG edges, but the
// handler's own PARAMETER still bound to nothing — `catch (e) { sink(e) }`
// after `throw RuntimeException(userInput)` is a real flow in real Kotlin
// (wrap-and-rethrow is the idiom InsecureShop itself uses), and the
// exception register existed nowhere in the KIR: a read of `e` lowered as a
// FIELD READ on `this`. The parameter is now bound on the dispatch edge in
// two shapes — at a VISIBLE throw the thrown register AND its construction
// arguments flow into it; where no throw is visible the exception is an
// unknown value that inherits whatever taint the body left live
// (tainted-if-the-body-was), clean when the body was clean.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The implicit-throw positive: parseInt throws NumberFormatException with
// the tainted input embedded in its message — no `throw` is visible, so
// this pins the unknown-exception SEED inheriting the body's live taint.
// With the defect restored (no binding at all) the handler's `e` is a
// field read on `this` and this expectation FAILS.
// kosi:want flow source=untrusted-input sink=ssrf fn=~implicitThrowCarries mode=resolved
//
// The visible-throw positive: the guarded body throws an exception BUILT
// from the tainted input. The fresh exception object's own register is
// clean (a KirNew clears it); the flow rides the construction argument,
// which is exactly the half a thrown-object-only binding would drop.
// kosi:want flow source=untrusted-input sink=ssrf fn=~visibleThrowCarries mode=resolved
//
// The negative half the phase names: a handler for a throw whose argument
// is CLEAN must not report. A visible clean throw SUPPRESSES the unknown
// seed (the thrown value is known), so neither binding can carry a fact.
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~cleanThrowStaysClean
//
// The seed's negative: a body with no throw at all and nothing tainted in
// it — the unknown exception inherits from clean registers and stays
// clean. A seed that birthed taint from nothing would report this.
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~cleanBodyStaysClean
package fixtures.catchtaint

import java.net.URI

/**
 * The implicit throw: the platform call fails on the tainted input and the
 * handler reads the exception. `e` exists only through the dispatch-edge
 * seed over the body's live registers.
 */
fun implicitThrowCarries(): URI? {
    val input = readLine() ?: return null
    try {
        Integer.parseInt(input)
    } catch (e: NumberFormatException) {
        return URI.create("https://example.invalid/failed/$e")
    }
    return null
}

/**
 * The visible throw: the exception is CONSTRUCTED from the tainted input
 * (InsecureShop's wrap idiom). The taint is on the constructor argument,
 * not the fresh object.
 */
fun visibleThrowCarries(): URI? {
    val input = readLine() ?: return null
    try {
        throw IllegalStateException("bad input: $input")
    } catch (e: IllegalStateException) {
        return URI.create("https://example.invalid/caught/$e")
    }
}

/** The clean visible throw: the handler must stay silent. */
fun cleanThrowStaysClean(): URI? {
    try {
        throw IllegalStateException("constant message")
    } catch (e: IllegalStateException) {
        return URI.create("https://example.invalid/caught/$e")
    }
}

/** The clean body: the unknown exception inherits nothing and stays clean. */
fun cleanBodyStaysClean(): URI? {
    try {
        Integer.parseInt("42")
    } catch (e: NumberFormatException) {
        return URI.create("https://example.invalid/caught/$e")
    }
    return null
}
