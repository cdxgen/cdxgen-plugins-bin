package io.cdxgen.kosi.corpus

import io.cdxgen.kosi.models.Categories
import io.cdxgen.kosi.schema.DiagnosticCodes

/**
 * Corpus annotations, parsed from `// kosi:want ...` and
 * `// kosi:want-not ...` comments (06-CORPUS.md §5). Grammar:
 *
 *   kosi:want     <kind> key=value...   (positive expectation)
 *   kosi:want-not <kind> key=value...   (negative expectation)
 *
 * kinds and keys:
 *   flow        source=<category> sink=<category> [count=N] [mode=M]
 *   edge        from=<symbol> to=<symbol> [calltype=T]
 *   reachable   symbol=<symbol> [from=<symbol>] [maxdepth=N]
 *   usage       name=<name> [kind=call|operator|reference]
 *   import      name=<fq-name> [star=true|false]
 *   declaration name=<name> [kind=<kind>]
 *   module      name=<name> [platform=<platform>]
 *   diagnostic  code=<code> [count=N]  (positive: code present; negative: absent)
 *
 * Values match exactly unless prefixed with `~` (substring match). Negative
 * expectations are written before positive ones in every fixture (the
 * negative half is what keeps propagation rules honest).
 *
 * Scoped known-fail: `known-fail=N` marks the expectation as an expected
 * failure for every backend; `known-fail=<backend>:N` scopes it to one
 * backend (e.g. `known-fail=resolved:12`). The number is a stable defect id
 * recorded in docs/KOSI.md. A known-fail that starts passing is an XPASS and
 * FAILS the build — the two-way ratchet.
 */
data class Annotation(
    val want: Boolean,
    val kind: Kind,
    val source: String?,
    val sink: String?,
    val from: String?,
    val to: String?,
    val symbol: String?,
    val callType: String?,
    val name: String?,
    val usageKind: String?,
    val star: Boolean?,
    val declKind: String?,
    val platform: String?,
    val code: String?,
    val count: Int?,
    val mode: String?,
    val maxDepth: Int?,
    val knownFailAll: Int?,
    val knownFailByBackend: Map<String, Int>,
    val file: String,
    val line: Int,
) {
    enum class Kind(val id: String) {
        FLOW("flow"),
        EDGE("edge"),
        REACHABLE("reachable"),
        USAGE("usage"),
        IMPORT("import"),
        DECLARATION("declaration"),
        MODULE("module"),
        DIAGNOSTIC("diagnostic"),
        ;

        companion object {
            fun fromId(id: String): Kind? = entries.firstOrNull { it.id == id }
        }
    }

    val isNegative: Boolean get() = !want

    fun knownFailFor(backend: String): Int? =
        knownFailByBackend[backend] ?: knownFailAll

    fun validate(): List<String> {
        val errors = mutableListOf<String>()
        if (kind == Kind.FLOW) {
            if (source == null) errors.add("flow requires source=")
            if (sink == null) errors.add("flow requires sink=")
            for (category in listOfNotNull(source, sink)) {
                if (!Categories.isValid(category)) {
                    errors.add(Categories.vocabularyError(category))
                }
            }
        }
        if (kind == Kind.EDGE && (from == null || to == null)) errors.add("edge requires from= and to=")
        if (kind == Kind.REACHABLE && symbol == null) errors.add("reachable requires symbol=")
        if (kind == Kind.USAGE && name == null) errors.add("usage requires name=")
        if (kind == Kind.IMPORT && name == null) errors.add("import requires name=")
        if (kind == Kind.DECLARATION && name == null && declKind == null) {
            errors.add("declaration requires name= or kind=")
        }
        if (kind == Kind.MODULE && name == null) errors.add("module requires name=")
        if (kind == Kind.DIAGNOSTIC && code == null) errors.add("diagnostic requires code=")
        // Closed vocabularies. A misspelled value would make a positive
        // unsatisfiable and — worse — a negative vacuously true, which is
        // exactly what the corpus exists to prevent.
        if (usageKind != null && usageKind !in USAGE_KINDS) {
            errors.add("usage kind must be one of $USAGE_KINDS, got $usageKind")
        }
        if (declKind != null && declKind !in DECLARATION_KINDS) {
            errors.add("declaration kind must be one of $DECLARATION_KINDS, got $declKind")
        }
        if (code != null && !code.startsWith("~") && code !in DiagnosticCodes.ALL) {
            errors.add(
                "unknown diagnostic code '$code'; known: ${DiagnosticCodes.ALL.sorted()} " +
                    "(register it in DiagnosticCodes when the engine starts emitting it)",
            )
        }
        if (mode != null && mode != "security" && mode != "all") {
            errors.add("mode must be security or all, got $mode")
        }
        return errors
    }

    companion object {
        /** `usages[].usageKind` vocabulary (SyntaxAnalyzer emits exactly these). */
        val USAGE_KINDS = setOf("call", "operator", "reference")

        /** `declarations[].kind` vocabulary. */
        val DECLARATION_KINDS = setOf(
            "class", "interface", "enum", "annotation", "data-class", "sealed-class",
            "object", "companion", "function", "method", "extension-function",
            "property", "getter", "setter", "constructor", "init", "typealias",
        )

        /** Backends that may appear in scoped known-fail markers. */
        val KNOWN_BACKENDS = listOf("syntax", "resolved", "deps", "compile")
    }
}
