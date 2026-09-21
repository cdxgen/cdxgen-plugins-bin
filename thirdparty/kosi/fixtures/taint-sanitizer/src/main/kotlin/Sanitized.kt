// Negative half first: the sanitizer from the shipped model pack
// (java.security.MessageDigest.digest clears untrusted-input) must break the
// flow — the hashed value reaches the same println sink and must report
// NOTHING. A sanitizer that "cleans" by hiding the sink would fail the
// positive half below; a sanitizer that does nothing would fail this half.
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~hashed
// kosi:want-not flow source=untrusted-input sink=crypto-asset
// kosi:want-not diagnostic code=parse-error
//
// the sweep found NO bundled fixture in which a sanitizer was
// load-bearing — hashed() stayed silent even with the pack entry deleted,
// because `hash.size` is a field read (no derivation) and the entry's
// propagation suppression was never the deciding fact. `sanitizedResult`
// is the shape that makes the entry load-bearing: the sanitized RESULT
// reaches the sink DIRECTLY. With the pack entry present the result is
// clean and this stays silent; with the entry removed the unknown-call
// propagation carries the argument's taint through digest and the flow
// appears — the want-not below FAILS. Proven both ways.
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~sanitizedResult
//
// Positive half: the same source, no sanitizer in the path. The marker is
// scoped to the syntax tier (docs/KOSI.md defect 1). `byteArrayHop` pins
// that the byte-array passthrough itself moves taint — so the silence of
// `sanitizedResult` is the SANITIZER's doing, not the hop's.
// kosi:want flow source=untrusted-input sink=log-injection fn=~raw known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=log-injection fn=~byteArrayHop known-fail=syntax:1
package fixtures.sanitized

import java.security.MessageDigest

fun raw() {
    val input = readLine() ?: return
    println("raw=$input")
}

fun byteArrayHop() {
    val input = readLine() ?: return
    val bytes = input.toByteArray()
    // kotlin.text.toByteArray is a modelled passthrough: the array carries
    // the input's taint to the sink.
    println(bytes)
}

fun hashed() {
    val input = readLine() ?: return
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(input.toByteArray())
    // digest() clears untrusted-input on its result; length is an Int of a
    // clean value, so this println must stay silent.
    println("hash length=" + hash.size)
}

fun sanitizedResult() {
    val input = readLine() ?: return
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(input.toByteArray())
    // The sanitized RESULT reaches the sink directly — no field read, no
    // hop the engine could lose the taint in. Silence here is the pack
    // entry's doing and nothing else's.
    println(hash)
}

