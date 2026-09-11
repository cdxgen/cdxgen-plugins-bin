package io.cdxgen.kosi.kir

/**
 * Const-folding over the KIR for the evidence consumers (P7/P8): what a call
 * argument's register provably contains, from the module alone plus the
 * caller-supplied workspace `const val` table and config table. A value that
 * cannot be proved is [ValueStatus.UNRESOLVED], never a guess — the
 * consumers report what the code says and mark the rest unresolved.
 *
 * Folding is a BACKWARD scan within the argument's own block: the lowering
 * defines a value register at most once per block on the straight-line path
 * to its use, so the nearest prior definition is the value. Cross-block
 * folding is deliberately absent: joins would need phi selection, and a
 * missing fold reports unresolved rather than a wrong value.
 */
class KirValueFolder(
    module: KirModule,
    /**
     * Workspace `const val` NAME -> value, only when the name maps to a
     * UNIQUE value workspace-wide (an ambiguous name never folds). Built by
     * the consumer from source text; the KIR does not carry property
     * initializers.
     */
    private val constValues: Map<String, String> = emptyMap(),
    /** Config-reader callee FQN -> argument index (the config table's key). */
    configReaders: List<Pair<String, Int>> = emptyList(),
    private val envReaders: Set<String> = DEFAULT_ENV_READERS,
    configTable: Map<String, String> = emptyMap(),
) {
    /**
     * Provenance of a folded value. FOLDED_CONST and FOLDED_TEMPLATE both
     * publish as the report's `folded` resolution; the finer distinction is
     * the crypto gate's per-FORM denominator (a `const val` read and a
     * string-template concat are different syntactic shapes).
     */
    enum class ValueStatus { LITERAL, FOLDED_CONST, FOLDED_TEMPLATE, CONFIG, ENV, UNRESOLVED }

    private val configReaderByFqn = configReaders.toMap()

    /** Config table keys -> values, supplied by the consumer's config scan. */
    private val configValues: Map<String, String> = configTable

    private val definedRegisters: Map<String, Set<String>> = module.functions.associate { fn ->
        fn.canonicalName to buildSet {
            fn.params.forEach { add(it.register) }
            for (block in fn.body?.blocks.orEmpty()) {
                for (ins in block.instructions) {
                    addAll(ins.defs)
                }
            }
        }
    }

    data class FoldedValue(val value: String?, val status: ValueStatus, val detail: String? = null) {
        val resolved: Boolean get() = value != null && status != ValueStatus.UNRESOLVED
    }

    /**
     * The provable value of [register], defined at or before instruction
     * [index] of [block] in [fn]'s body. Null when the register is not a
     * string-shaped value at all (unknown).
     */
    fun valueAt(fn: KirFunction, block: KirBlock, index: Int, register: String): FoldedValue? =
        fold(fn, block, index, register, depth = 0)

    private fun fold(fn: KirFunction, block: KirBlock, index: Int, register: String, depth: Int): FoldedValue? {
        if (depth > MAX_DEPTH) return FoldedValue(null, ValueStatus.UNRESOLVED)
        // Scan backwards for the definition of this register.
        for (i in index - 1 downTo 0) {
            val ins = block.instructions.getOrNull(i) ?: continue
            val target = defOf(ins) ?: continue
            if (target != register) continue
            return when (ins) {
                is KirLoad -> when (val constant = ins.constant) {
                    // Source string literals carry their quotes (the lowering
                    // keeps the template's source text); strip them.
                    is KirConstant.Str -> FoldedValue(constant.value.removeSurrounding("\""), ValueStatus.LITERAL)
                    is KirConstant.IntConst -> FoldedValue(constant.value.toString(), ValueStatus.LITERAL)
                    else -> null
                }

                is KirStringConcat -> {
                    // Parts are registers when defined in the function;
                    // anything else is the lowering's raw literal fragment.
                    val sb = StringBuilder()
                    var all = true
                    var status = ValueStatus.FOLDED_TEMPLATE
                    var detail: String? = null
                    for (part in ins.parts) {
                        val piece = if (part in (definedRegisters[fn.canonicalName] ?: emptySet())) {
                            resolveAbove(fn, block, i, part, depth)
                        } else {
                            FoldedValue(part, ValueStatus.FOLDED_TEMPLATE)
                        }
                        if (piece?.value == null) {
                            all = false
                            if (piece?.status == ValueStatus.UNRESOLVED) detail = piece.detail
                            break
                        }
                        if (piece.status != ValueStatus.LITERAL &&
                            piece.status != ValueStatus.FOLDED_CONST &&
                            piece.status != ValueStatus.FOLDED_TEMPLATE
                        ) {
                            status = piece.status
                            detail = piece.detail
                        }
                        sb.append(piece.value)
                    }
                    if (all) FoldedValue(sb.toString(), status, detail) else FoldedValue(null, ValueStatus.UNRESOLVED, detail)
                }

                is KirFieldGet -> {
                    // `const val` reads lower as a fieldget whose path ends in
                    // the property name; a unique workspace value folds.
                    val name = (ins.path.elements.lastOrNull() as? AccessPath.Element.Field)?.name
                    val constValue = name?.let { constValues[it] }
                    if (constValue != null) {
                        FoldedValue(constValue, ValueStatus.FOLDED_CONST)
                    } else {
                        FoldedValue(null, ValueStatus.UNRESOLVED)
                    }
                }

                is KirAssign -> fold(fn, block, i, ins.source, depth + 1)

                is KirCall -> callValue(fn, block, i, ins, depth)

                else -> FoldedValue(null, ValueStatus.UNRESOLVED)
            }
        }
        // Parameter or cross-block value: not provable on this path.
        return null
    }

    private fun resolveAbove(fn: KirFunction, block: KirBlock, index: Int, register: String, depth: Int): FoldedValue? =
        fold(fn, block, index, register, depth + 1)

    private fun callValue(fn: KirFunction, block: KirBlock, index: Int, ins: KirCall, depth: Int): FoldedValue {
        // env readers: the VALUE is the process environment of the analysed
        // build, which kosi never reads — the key name is the evidence.
        if (ins.callee.fqn in envReaders) {
            val key = ins.args.getOrNull(0)?.let { fold(fn, block, index, it, depth + 1) }
            return FoldedValue(null, ValueStatus.ENV, key?.value ?: ins.args.getOrNull(0))
        }
        val argIndex = configReaderByFqn[ins.callee.fqn] ?: return FoldedValue(null, ValueStatus.UNRESOLVED)
        val keyReg = ins.args.getOrNull(argIndex) ?: return FoldedValue(null, ValueStatus.UNRESOLVED)
        val key = fold(fn, block, index, keyReg, depth + 1) ?: return FoldedValue(null, ValueStatus.UNRESOLVED)
        val keyValue = key.value ?: return FoldedValue(null, ValueStatus.UNRESOLVED)
        val configValue = configValues[keyValue] ?: return FoldedValue(null, ValueStatus.UNRESOLVED, keyValue)
        return FoldedValue(configValue, ValueStatus.CONFIG, keyValue)
    }

    private fun defOf(ins: KirIns): String? = when (ins) {
        is KirLoad -> ins.result
        is KirStringConcat -> ins.result
        is KirFieldGet -> ins.result
        is KirAssign -> ins.result
        is KirCall -> ins.result
        is KirNew -> ins.result
        is KirSafeCall -> ins.result
        is KirCast -> ins.result
        is KirTypeCheck -> ins.result
        is KirElvis -> ins.result
        else -> null
    }

    companion object {
        private const val MAX_DEPTH = 8

        /** Callee FQNs whose result is a process-environment read. */
        val DEFAULT_ENV_READERS = setOf("java.lang.System.getenv", "kotlin.system.getenv")
    }
}
