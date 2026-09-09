package io.cdxgen.kosi.kir

/**
 * One lowered function: signature facts the call graph and taint engine
 * need (02-ARCHITECTURE.md §4), plus the CFG body. `syntheticCause` marks
 * members the lowering synthesized rather than read from source (`copy` and
 * `componentN` of a data class, accessor bodies of delegated properties) so
 * synthetic evidence stays attributable.
 */
data class KirFunction(
    val canonicalName: String,
    val jvmDescriptor: String?,
    val purl: String,
    val file: String,
    val line: Int,
    val column: Int,
    val params: List<KirParam>,
    val returnType: String?,
    val modifiers: Set<String>,
    val visibility: String,
    val enclosingClass: String?,
    val overrides: List<String>,
    val overriddenBy: List<String>,
    val annotations: List<String>,
    val syntheticCause: String? = null,
    val body: KirBody?,
)

data class KirParam(
    /** `%<n>`, in declaration order; the dispatch/extension receiver is first when present. */
    val register: String,
    val name: String?,
    val type: String?,
    val receiver: Boolean,
)

/**
 * A CFG body: an ordered list of basic blocks. The first block is the
 * entry; a block without a terminating instruction falls through to the
 * NEXT block in list order, which is why order is part of the CFG.
 */
data class KirBody(val blocks: List<KirBlock>)

data class KirBlock(
    val id: String,
    val entry: Boolean,
    val instructions: List<KirIns>,
)

/** A whole lowered module: functions in canonical-name order. */
data class KirModule(val functions: List<KirFunction>) {
    companion object {
        const val FORMAT = "kir 1"
    }
}
