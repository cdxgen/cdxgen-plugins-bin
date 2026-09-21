// the CFG has no exceptional-edge instruction, so catch handlers
// lowered as standalone blocks had NO incoming edge — structurally
// unreachable, never analysed, and taint through them silently dropped. The
// four reductions below are InsecureShop's four validator findings
// (ChooserActivity.makeTempCopy x2, LoginActivity.onLogin,
// SendingDataViaActionActivity.onSendData, Util.verifyUserNamePassword),
// reduced to the smallest Kotlin that reproduces each.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// THE dropped flow, pinned: a source before the try, a sink INSIDE the
// handler. With the defect restored (handlers emitted with no in-edge) the
// handler is unreachable, the sink inside it is never analysed, and this
// expectation FAILS.
// kosi:want flow source=untrusted-input sink=ssrf fn=~sinkInHandler mode=resolved
//
// The entry-edge negative: a value SANITIZED before the try reaches the
// handler's sink clean — the exceptional edge carries the try-entry state,
// where the sanitizer has already run. An implementation that birthed the
// handler's facts from nothing (or skipped the sanitizer at the fork) would
// report this.
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~sanitizedBeforeTry
//
// The handler's clean sibling: the same handler shape sinking a value no
// source ever touched — a catch-all reachability that TAINTED the handler's
// registers wholesale would report this.
// kosi:want-not flow source=untrusted-input sink=ssrf fn=~cleanInHandler
package fixtures.catchflow

import java.net.URI

private fun risky(): String = checkNotNull(readLine())

/**
 * InsecureShop's SendingDataViaActionActivity.onSendData reduced: an EMPTY
 * catch handler. Pre-this was an unreachable block of pure control flow;
 * the dispatch chain now reaches it and `kir dump` validates the module
 * clean (pinned by KirLoweringTest, which refuses a dirty CFG).
 */
fun emptyCatch(): String {
    return try {
        risky()
    } catch (e: IllegalStateException) {
        "fallback"
    }
}

/**
 * The dropped-flow pin (LoginActivity.onLogin's shape: the handler has a
 * real effect). The sink is inside the handler; the taint is born before the
 * try. Post-both forks (try entry, try end) carry the tainted register
 * into the dispatch chain, so the handler's sink reports.
 */
fun sinkInHandler(): URI? {
    val target = readLine() ?: return null
    try {
        risky()
    } catch (e: Exception) {
        return URI.create(target)
    }
    return null
}

/**
 * The entry-edge negative: the sanitizer runs BEFORE the try, so both forks
 * carry the sanitized register and the handler's sink stays silent.
 */
fun sanitizedBeforeTry(): URI? {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    val clean = digest.digest((readLine() ?: "").toByteArray()).size
    try {
        risky()
    } catch (e: Exception) {
        return URI.create("https://example.invalid/$clean")
    }
    return null
}

/**
 * The handler's clean sibling: the same exceptional-edge shape, but the
 * handler sinks a constant no source ever touched. Reachability without a
 * fact is not a flow — a handler join that TAINTED registers wholesale
 * (instead of carrying the fork's state) would report this.
 */
fun cleanInHandler(): URI? {
    try {
        risky()
    } catch (e: Exception) {
        return URI.create("https://example.invalid/constant")
    }
    return null
}

/**
 * LoginActivity.onLogin reduced to its rethrow: the handler rethrows a
 * wrapped exception. Pre-the `throw` inside it was dead code to the
 * engine; the CFG now reaches the handler and `kir dump` validates clean.
 */
fun rethrowInHandler(): String {
    try {
        risky()
    } catch (e: Exception) {
        throw RuntimeException(e)
    }
}

/**
 * ChooserActivity.makeTempCopy reduced to its two findings at once: the try
 * body returns, the handler returns, and the lowering used to emit BOTH an
 * unreachable handler (no exceptional edge) and an unreachable trailing
// continuation (every path had returned). The handler is reachable through
// the entry fork — a throw at the FIRST call of the body — and the dead tail
// block is simply not emitted (cause B).
 */
fun tryReturnBoth(): URI? {
    return try {
        URI.create("https://example.invalid/constant")
    } catch (e: Exception) {
        null
    }
}

/**
 * Util.verifyUserNamePassword reduced: an if/else whose BOTH arms return.
// The lowering used to start the join block anyway and terminate it with a
// bare implicit `return` — an unreachable-but-emitted block. Cause B: the
// join is not emitted; the body ends at the arms.
 */
fun bothArmsReturn(username: String, password: String): Boolean {
    if (username == password) {
        return true
    } else {
        return false
    }
}
