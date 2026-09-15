// The Kotlin sample project for the P11 end-to-end gate. One small audit
// service carrying every evidence kind cdxgen/evinse consumes from the kosi
// report: occurrences (usages with positions), callstacks (slice traces),
// reachability (reachableFromRoots from main), data-flow slices, crypto
// material and crypto-flow, and an outbound services[] row. The dependency
// jar is the real Timber 5.0.1 classes.jar, committed beside the sources.
package com.example.audit

import timber.log.Timber

/**
 * Writes audit lines through Timber. The tainted path only materialises
 * through the dependency's bytecode: Timber.d's dispatch chain bottoms out
 * at Log.println INSIDE libs/timber-5.0.1.jar.
 */
class AuditService {

    /** Called once from [main] before the first request lands. */
    fun initLogging() {
        Timber.plant(Timber.DebugTree())
    }

    fun audit(action: String?) {
        val user = readLine() ?: "anonymous"
        Timber.d("audit: %s by %s", action, user)
    }

    /** The clean sibling: a literal format, no arguments. */
    fun heartbeat() {
        Timber.d("heartbeat")
    }
}
