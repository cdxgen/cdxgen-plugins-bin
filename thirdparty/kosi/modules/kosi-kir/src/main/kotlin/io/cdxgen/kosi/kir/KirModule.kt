package io.cdxgen.kosi.kir

/**
 * One lowered function: signature facts the call graph and taint engine
 * need (02-ARCHITECTURE.md §4), plus the CFG body. `syntheticCause` marks
 * members the lowering synthesized rather than read from source (`copy` and
 * `componentN` of a data class, accessor bodies of delegated properties) so
 * synthetic evidence stays attributable.
 *
 * P3 added the facts dispatch resolution needs, all resolved through the
 * compiler's own symbols at lowering time and compiler-free from here on:
 * `supertypes` are the enclosing class's direct supertype FQNs, `ownerFlags`
 * its kind/modality facts (`sealed`, `interface`, `enum`, `object`,
 * `companion`, `final`, `open`, `abstract`, `fun-interface`) — the sealed
 * narrowing and the exactness rules both read these. A function whose symbol
 * facts could not be computed carries empty facts; the graph then treats it
 * as open (never as exact), because missing evidence must narrow dispatch
 * toward MORE candidates, never fewer.
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
    val supertypes: List<String> = emptyList(),
    val ownerFlags: Set<String> = emptySet(),

    /** RESOLVED annotation FQNs of the enclosing class (`@RestController` on
     *  the class makes every handler method inside it a framework root). */
    val ownerAnnotations: List<String> = emptyList(),

    /**
     * Declared visibility of the enclosing class: a public member of an
     * internal class is not public API, and `--roots exported` reads this.
     */
    val ownerVisibility: String? = null,
)

/**
 * Source line of the construct, 1-based; 0 when the lowering has none. Carried
 * by the three instructions that become call-graph edges so edge evidence
 * names a line (03-SCHEMA.md edge.line).
 */
const val KIR_NO_LINE: Int = 0

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
        /**
         * `kir 2` adds the dispatch facts ([KirFunction.supertypes],
         * [KirFunction.ownerFlags]) and call-site lines. The reader accepts
         * exactly its own format version; dumps do not survive format bumps.
         */
        const val FORMAT = "kir 2"
    }
}
