// The vuln-tier fixture's cross-dependency half: a service that logs
// request-derived data through a REAL third-party logger. Timber is the
// published 5.0.1 binary in libs/; the sink its bytecode calls internally
// (`android.util.Log.println`) lives inside the jar's own call chain
// (`Timber.d` -> `Forest.d` -> `Tree.d` -> `DebugTree.log` -> `Log.println`),
// so only the `--deps` tier can walk a source into it. The near-miss
// negative is the literal-only sibling a collapsing implementation would
// report on.
//
// The tree is planted from an ordinary function, not an `init` block: the
// dispatch join that resolves `Tree.log` to the planted `DebugTree` needs
// the construction site as a workspace call, and an `init`-embedded one
// does not qualify today — a named dispatch-seeding boundary, recorded
// here because it is exactly the kind of shape a reviewer would assume
// equivalent.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=~ fn=~heartbeat mode=deps
// kosi:want flow source=untrusted-input sink=log-injection fn=~audit mode=deps
// kosi:want flow source=untrusted-input sink=log-injection fn=~auditWarn mode=deps
package dev.kosi.service

import timber.log.Timber

/**
 * Audits user actions through Timber. The debug tree is planted once at
 * service startup, the way every Timber quickstart wires it.
 */
class AuditService {

    /** Called once from the service bootstrap before any request lands. */
    fun initLogging() {
        Timber.plant(Timber.DebugTree())
    }

    /**
     * The tainted half: the acting user's name arrives from the request and
     * flows into the format string of a Timber call, whose dispatch chain
     * bottoms out at `Log.println` INSIDE the dependency jar.
     */
    fun audit(action: String?) {
        val user = readLine() ?: "anonymous"
        Timber.d("audit: %s by %s", action, user)
    }

    /** A second category through the same jar: warnings reach `Log.w`. */
    fun auditWarn(action: String?) {
        val user = readLine() ?: "anonymous"
        Timber.w("denied: %s for %s", action, user)
    }

    /** The clean sibling: a literal format and no arguments. */
    fun heartbeat() {
        Timber.d("heartbeat")
    }
}
