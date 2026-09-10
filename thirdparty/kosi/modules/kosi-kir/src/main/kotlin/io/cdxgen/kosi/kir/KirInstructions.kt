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
 * (statement-position calls to Unit). `line` is the call site's source line
 * (1-based; [KIR_NO_LINE] when unknown) — the call graph's edge evidence.
 */
data class KirCall(
    val result: String?,
    val callee: KirCallee,
    val receiver: String?,
    val args: List<String>,
    val line: Int = KIR_NO_LINE,
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
    val line: Int = KIR_NO_LINE,
) : KirIns

/** An object creation with constructor arguments. */
data class KirNew(val result: String, val type: String, val args: List<String>, val line: Int = KIR_NO_LINE) : KirIns

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

/**
 * The registers one instruction WRITES. The def sets of a body are what the
 * lambda extraction reads to tell a capture (a free register the enclosing
 * scope defined) from a body-local, and what dataflow passes use to reason
 * about register liveness without re-walking operand positions.
 */
val KirIns.defs: List<String>
    get() = when (this) {
        is KirAssign -> listOf(result)
        is KirLoad -> listOf(result)
        is KirStore -> listOf(target)
        is KirFieldGet -> listOf(result)
        is KirFieldSet -> emptyList()
        is KirIndexGet -> listOf(result)
        is KirIndexSet -> emptyList()
        is KirCall -> listOfNotNull(result)
        is KirDynamicCall -> listOfNotNull(result)
        is KirNew -> listOf(result)
        is KirPhi -> listOf(result)
        is KirBranch -> emptyList()
        is KirReturn -> emptyList()
        is KirThrow -> emptyList()
        // A suspend point marks the boundary AFTER its call; the call defined
        // the register and the boundary defines nothing new.
        is KirSuspendPoint -> emptyList()
        is KirStringConcat -> listOf(result)
        is KirLambda -> listOf(result)
        is KirElvis -> listOf(result)
        is KirSafeCall -> listOf(result)
        is KirCast -> listOf(result)
        is KirTypeCheck -> listOf(result)
    }

/**
 * The registers one instruction READS. [KirLambda]'s captures count as uses:
 * a capture names a register of the ENCLOSING function, which is exactly
 * what the extraction's rewrite renames into the extracted body's capture
 * parameters.
 */
val KirIns.uses: List<String>
    get() = when (this) {
        is KirAssign -> listOf(source)
        is KirLoad -> emptyList()
        is KirStore -> listOf(value)
        is KirFieldGet -> listOf(receiver) + path.uses
        is KirFieldSet -> listOf(receiver) + path.uses + listOf(value)
        is KirIndexGet -> listOf(receiver, index)
        is KirIndexSet -> listOf(receiver, index, value)
        is KirCall -> listOfNotNull(receiver) + args
        is KirDynamicCall -> listOfNotNull(receiver) + args
        is KirNew -> args
        is KirPhi -> inputs.values.toList()
        is KirBranch -> listOf(condition)
        is KirReturn -> listOfNotNull(value)
        is KirThrow -> listOf(exception)
        is KirSuspendPoint -> listOf(result)
        is KirStringConcat -> parts
        is KirLambda -> captures
        is KirElvis -> listOf(value, fallback)
        is KirSafeCall -> listOf(receiver) + path.uses
        is KirCast -> listOf(value)
        is KirTypeCheck -> listOf(value)
    }

/** The register an access path hangs off, when any. */
val AccessPath.uses: List<String>
    get() = listOf(base)

/**
 * A copy of this instruction whose register operands are rewritten by
 * [transform]. Used by the lambda extraction to rename captures into the
 * extracted body's parameters; [defsToo] false leaves definition positions
 * (store targets, instruction results) untouched, so a body-local that
 * happens to share a name with a capture stays a body-local.
 */
fun KirIns.mapRegisters(transform: (String) -> String, defsToo: Boolean): KirIns = when (this) {
    is KirAssign -> copy(
        result = if (defsToo) transform(result) else result,
        source = transform(source),
    )

    is KirLoad -> this
    is KirStore -> copy(
        target = if (defsToo) transform(target) else target,
        value = transform(value),
    )

    is KirFieldGet -> copy(result = if (defsToo) transform(result) else result, receiver = transform(receiver), path = path.mapRegisters(transform))
    is KirFieldSet -> copy(receiver = transform(receiver), path = path.mapRegisters(transform), value = transform(value))
    is KirIndexGet -> copy(result = if (defsToo) transform(result) else result, receiver = transform(receiver), index = transform(index))
    is KirIndexSet -> copy(receiver = transform(receiver), index = transform(index), value = transform(value))
    is KirCall -> copy(
        result = if (defsToo) result?.let(transform) else result,
        receiver = receiver?.let(transform),
        args = args.map(transform),
    )

    is KirDynamicCall -> copy(
        result = if (defsToo) result?.let(transform) else result,
        receiver = receiver?.let(transform),
        args = args.map(transform),
    )

    is KirNew -> copy(result = if (defsToo) transform(result) else result, args = args.map(transform))
    is KirPhi -> copy(inputs = inputs.mapValues { (_, reg) -> transform(reg) })
    is KirBranch -> copy(condition = transform(condition))
    is KirReturn -> copy(value = value?.let(transform))
    is KirThrow -> copy(exception = transform(exception))
    is KirSuspendPoint -> copy(result = transform(result))
    is KirStringConcat -> copy(
        result = if (defsToo) transform(result) else result,
        parts = parts.map(transform),
    )

    is KirLambda -> copy(result = if (defsToo) transform(result) else result, captures = captures.map(transform))
    is KirElvis -> copy(
        result = if (defsToo) transform(result) else result,
        value = transform(value),
        fallback = transform(fallback),
    )

    is KirSafeCall -> copy(result = if (defsToo) transform(result) else result, receiver = transform(receiver), path = path.mapRegisters(transform))
    is KirCast -> copy(result = if (defsToo) transform(result) else result, value = transform(value))
    is KirTypeCheck -> copy(result = if (defsToo) transform(result) else result, value = transform(value))
}

/** A copy of this access path whose base register is rewritten by [transform]. */
fun AccessPath.mapRegisters(transform: (String) -> String): AccessPath = copy(base = transform(base))
