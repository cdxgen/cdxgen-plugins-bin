// Negative half first: the sanitizer from the shipped model pack
// (java.security.MessageDigest.digest clears untrusted-input) must break the
// flow — the hashed value reaches the same println sink and must report
// NOTHING. A sanitizer that "cleans" by hiding the sink would fail the
// positive half below; a sanitizer that does nothing would fail this half.
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~hashed
// kosi:want-not flow source=untrusted-input sink=crypto-asset
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the same source, no sanitizer in the path. The marker is
// scoped to the syntax tier (docs/KOSI.md defect 1).
// kosi:want flow source=untrusted-input sink=log-injection fn=~raw known-fail=syntax:1
package fixtures.sanitized

import java.security.MessageDigest

fun raw() {
    val input = readLine() ?: return
    println("raw=$input")
}

fun hashed() {
    val input = readLine() ?: return
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(input.toByteArray())
    // digest() clears untrusted-input on its result; length is an Int of a
    // clean value, so this println must stay silent.
    println("hash length=" + hash.size)
}
