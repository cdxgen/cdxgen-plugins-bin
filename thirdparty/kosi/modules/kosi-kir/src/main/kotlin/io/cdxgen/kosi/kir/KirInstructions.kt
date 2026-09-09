package io.cdxgen.kosi.kir

/**
 * The three-address instructions of the KIR (02-ARCHITECTURE.md §4), one
 * subclass per opcode. Every instruction appends to a basic block; branch
 * and phi carry the CFG's explicit edges, everything else falls through to
 * the next block in order.
 */
sealed interface KirIns

/** Register-to-register copy (after a join, a cast-away, a re-assignment). */
data class KirAssign(val result: String, val source: String) : KirIns

/** A constant into a register. */
data class KirLoad(val result: String, val constant: KirConstant) : KirIns

/** A write to a named local (`v<name>`); parameters are stored the same way. */
data class KirStore(val target: String, val value: String) : KirIns

/** A field (or nested access path) read. */
data class KirFieldGet(val result: String, val receiver: String, val path: AccessPath) : KirIns

/** A field (or nested access path) write. */
data class KirFieldSet(val receiver: String, val path: AccessPath, val value: String) : KirIns

data class KirIndexGet(val result: String, val receiver: String, val index: String) : KirIns

data class KirIndexSet(val receiver: String, val index: String, val value: String) : KirIns

/**
 * A resolved call. `result` is null for calls whose value is dropped
 * (statement-position calls to Unit).
 */
data class KirCall(
    val result: String?,
    val callee: KirCallee,
    val receiver: String?,
    val args: List<String>,
) : KirIns

/**
 * A call site the lowering could not resolve to a callee: the name is kept,
 * no callee is invented. These are the sites a flow engine must treat as
 * unknown-propagating, and the ones resolution improvements shrink.
 */
data class KirDynamicCall(
    val result: String?,
    val name: String,
    val receiver: String?,
    val args: List<String>,
) : KirIns

/** An object creation with constructor arguments. */
data class KirNew(val result: String, val type: String, val args: List<String>) : KirIns

/**
 * A join value: one input register per predecessor block id. Emitted by the
 * `?:` desugaring and the joins of `if`/loop lowerings.
 */
data class KirPhi(val result: String, val inputs: Map<String, String>) : KirIns

/** Conditional branch; the only two-way edge in the CFG. */
data class KirBranch(val condition: String, val thenBlock: String, val elseBlock: String) : KirIns

data class KirReturn(val value: String?) : KirIns

data class KirThrow(val exception: String) : KirIns

/**
 * A suspend boundary after a suspending call (`suspend` call -> `Call` +
 * `SuspendPoint`); [result] is the register of the call it follows.
 */
data class KirSuspendPoint(val result: String) : KirIns

/** String template desugared into its concatenated parts. */
data class KirStringConcat(val result: String, val parts: List<String>) : KirIns

/**
 * A lambda: `function` names the canonical lambda body function the lowering
 * extracted, `captures` the registers frozen into it. Scope functions inline
 * the body instead and keep a call edge for evidence — see [KirCall].
 */
data class KirLambda(val result: String, val function: String, val captures: List<String>) : KirIns

/**
 * The `?:` operator at a position where the lowering cannot branch (inside a
 * call argument); at statement/return positions it lowers to phi per §4.
 */
data class KirElvis(val result: String, val value: String, val fallback: String) : KirIns

/**
 * The `?.` operator at a position where the lowering cannot branch; at
 * statement/return positions a safe call lowers to branch + phi per §4.
 */
data class KirSafeCall(val result: String, val receiver: String, val path: AccessPath) : KirIns

/** A cast; `!!` lowers to a safe cast of a known-non-null value plus a throw branch. */
data class KirCast(val result: String, val value: String, val type: String, val checked: Boolean) : KirIns

data class KirTypeCheck(val result: String, val value: String, val type: String) : KirIns
