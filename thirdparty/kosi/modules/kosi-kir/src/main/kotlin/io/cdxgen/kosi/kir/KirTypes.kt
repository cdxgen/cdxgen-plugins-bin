package io.cdxgen.kosi.kir

/**
 * kosi's owned intermediate representation (02-ARCHITECTURE.md §4). Nothing
 * in this module depends on a compiler type: functions arrive lowered from
 * kosi-front as interned strings, ids and small value types, and everything
 * downstream of the lowering (the flow engine from P4 on, the exporters, the
 * `kir dump` reader) consumes only what is defined here.
 *
 * Registers are strings with a fixed shape: `%<n>` for parameters, `t<n>`
 * for temporaries, `v<name>` for named locals. They are opaque outside a
 * function body.
 */

/** A field-sensitive access path: `(base, [field|index|*]*)`. */
data class AccessPath(val base: String, val elements: List<Element>) {

    sealed interface Element {
        data class Field(val name: String) : Element
        data object Index : Element

        /** Collapse marker: the real path continues but was cut at the cap. */
        data object Star : Element
    }

    val collapsed: Boolean get() = elements.lastOrNull() is Element.Star

    companion object {
        const val DEFAULT_DEPTH: Int = 5

        /** Builds a path, collapsing to `*` beyond [depth] elements. */
        fun of(base: String, elements: List<Element>, depth: Int = DEFAULT_DEPTH): AccessPath =
            if (elements.size <= depth) {
                AccessPath(base, elements)
            } else {
                AccessPath(base, elements.take(depth) + Element.Star)
            }

        fun field(base: String, vararg fields: String): AccessPath =
            of(base, fields.map { Element.Field(it) })
    }
}

/** Constants carried by [KirLoad]. */
sealed interface KirConstant {
    data class Str(val value: String) : KirConstant
    data class IntConst(val value: Long) : KirConstant
    data class FloatConst(val value: Double) : KirConstant
    data class Bool(val value: Boolean) : KirConstant
    data object Null : KirConstant
}

/** How a [KirCall] reaches its callee, decided by the lowering's resolution. */
enum class CallKind {
    /** A resolved call: `fqn` is the callee's fully qualified name. */
    STATIC,
    VIRTUAL,
    SUPER,
    EXTENSION,
    OPERATOR,

    /** A constructor; `fqn` is the constructed class, `descriptor` the `<init>` signature. */
    CONSTRUCTOR,
}

/** One callee reference: fully qualified name plus optional JVM descriptor. */
data class KirCallee(
    val fqn: String,
    val descriptor: String?,
    val kind: CallKind,
)
