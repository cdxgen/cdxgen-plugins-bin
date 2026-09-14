// A call whose callee has NO dispatch target in the workspace must fall to
// the conservative unknown-call default, and a CONSTRUCTOR is not special.
//
// This fixture exists because it stopped being true once. The P9 branch
// carved constructors out of the summary engine's "no dispatch target" arm,
// so an unresolved constructor reported "handled" and suppressed the default
// — which silently dropped the parameter-to-return passthrough below, on
// EVERY backend, not just the dependency tier. Nothing failed: the corpus had
// no annotation for the shape and the goldens were regenerated over it.
//
// The flow must therefore cross a CALLEE boundary. The unresolved
// constructor sits inside `wrapUnresolved`, so the only way its taint reaches
// the sink is through that function's summary — which is exactly what the
// carve-out emptied. A fixture that called the constructor inline would pass
// either way: the caller's own unknown-call default would cover for it.
//
// The positive and its near-miss negative differ only in whether the
// constructor's argument is the tainted value, so an implementation that
// collapses "unresolved constructor" to "no flow" fails the first, and one
// that taints every unresolved constructor's result fails the second.
//
// The positive is scoped to the RESOLVED slots: the syntax backend cannot
// tell an unresolved constructor from any other call, so it has nothing to
// say about this shape. The negative is unscoped — no backend may invent it.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=~sinkThroughWrapper mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~sinkThroughWrapper mode=deps
// kosi:want-not flow source=untrusted-input sink=~ fn=~sinkBesideWrapper
package dev.kosi.app

import javax.naming.ldap.LdapName

/**
 * `LdapName(String)` has no body kosi can see: it lives in the JDK image, no
 * pack entry models it, and no workspace function overrides it. The
 * unknown-call default must carry the tainted argument to the result, so this
 * function's summary has to publish a parameter-to-return passthrough.
 */
fun wrapUnresolved(raw: String): String = LdapName(raw).toString()

/** The near-miss: the same unresolved constructor, the argument NOT tainted. */
fun wrapFixed(raw: String): String {
    check(raw.isNotEmpty())
    return LdapName("cn=fixed").toString()
}

fun sinkThroughWrapper(): Process =
    ProcessBuilder(wrapUnresolved(readLine() ?: "")).start()

fun sinkBesideWrapper(): Process =
    ProcessBuilder(wrapFixed(readLine() ?: "")).start()
