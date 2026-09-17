package io.cdxgen.kosi.corpus

import io.cdxgen.kosi.models.Categories
import io.cdxgen.kosi.models.EndpointModels
import io.cdxgen.kosi.schema.DiagnosticCodes

/**
 * Corpus annotations, parsed from `// kosi:want ...` and
 * `// kosi:want-not ...` comments (06-CORPUS.md §5). Grammar:
 *
 *   kosi:want     <kind> key=value...   (positive expectation)
 *   kosi:want-not <kind> key=value...   (negative expectation)
 *
 * kinds and keys:
 *   flow        source=<category> sink=<category> [count=N] [mode=M] [fn=<function>]
 *               [sourceparam=#N] [sourcetransport=T]   (P20 §1: which handler
 *               parameter a flow entered through, and its transport)
 *   signal      code=<signal-code> [fn=<symbol>]   securitySignals[] evidence
 *   edge        from=<symbol> to=<symbol> [calltype=T]
 *   reachable   symbol=<symbol> [from=<symbol>] [maxdepth=N]
 *   usage       name=<name> [kind=call|operator|reference]
 *   import      name=<fq-name> [star=true|false]
 *   declaration name=<name> [kind=<kind>]
 *   module      name=<name> [platform=<platform>]
 *   diagnostic  code=<code> [count=N]  (positive: code present; negative: absent)
 *
 * `fn=` scopes a flow expectation to the function whose canonical name
 * matches (exact, or `~substring`): with it, a fixture can demand a flow in
 * one function and demand the ABSENCE of that same-category flow in its
 * sibling, which is how the clean-sibling negative stays expressible.
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
    val fn: String?,
    val maxDepth: Int?,
    val knownFailAll: Int?,
    val knownFailByBackend: Map<String, Int>,
    val framework: String?,
    val path: String?,
    val method: String?,
    /**
     * A parameter the endpoint must carry, and the transport it arrived on.
     * `path=` pins the route; these pin what the handler READS out of it —
     * the half a context framework declares nowhere in its signature.
     */
    val pathParam: String?,
    val queryParam: String?,
    /** P14: media types / auth the endpoint must carry (or, negated, must not). */
    val consumes: String?,
    val produces: String?,
    val authentication: String?,
    val cipherMode: String?,
    val padding: String?,
    val form: String?,
    val protocol: String?,
    val resolution: String?,
    /** P20 §1: the handler value-parameter a flow entered through (`#0` = first non-receiver). */
    val sourceParam: String?,
    /** P20 §1: the transport that parameter's annotation names (path/query/header/cookie/form/body). */
    val sourceTransport: String?,
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
        ENDPOINT("endpoint"),
        CRYPTO("crypto"),
        SERVICE("service"),
        SIGNAL("signal"),
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
        if (kind == Kind.ENDPOINT && framework == null) {
            errors.add("endpoint requires framework=")
        }
        if (kind == Kind.ENDPOINT && framework != null && !Frameworks.isValid(framework)) {
            errors.add(
                "unknown framework '$framework'; known: ${Frameworks.all().sorted()} " +
                    "(add it to the shipped endpoints pack when the detector starts emitting it)",
            )
        }
        // The media/auth keys only mean something on an endpoint expectation.
        if (kind != Kind.ENDPOINT && (consumes != null || produces != null || authentication != null)) {
            errors.add("consumes=/produces=/authentication= are only valid on endpoint expectations")
        }
        if (kind == Kind.CRYPTO && name == null) errors.add("crypto requires name=")
        if (kind == Kind.SERVICE && protocol == null && name == null && path == null) {
            errors.add("service requires protocol=, name= or path=")
        }
        if (kind == Kind.SIGNAL && code == null) errors.add("signal requires code=")
        if (kind == Kind.SIGNAL && code != null && !code.startsWith("~") && code !in SIGNAL_CODES) {
            errors.add("unknown signal code '$code'; known: ${SIGNAL_CODES.sorted()}")
        }
        if (kind != Kind.FLOW && kind != Kind.ENDPOINT && kind != Kind.SIGNAL && fn != null) {
            errors.add("fn= is only valid on flow, endpoint and signal expectations")
        }
        if (form != null && form !in FORMS) {
            errors.add("form must be one of $FORMS, got $form")
        }
        if (resolution != null && resolution !in RESOLUTIONS) {
            errors.add("resolution must be one of $RESOLUTIONS, got $resolution")
        }
        // Closed vocabularies. A misspelled value would make a positive
        // unsatisfiable and — worse — a negative vacuously true, which is
        // exactly what the corpus exists to prevent.
        if (usageKind != null && usageKind !in USAGE_KINDS) {
            errors.add("usage kind must be one of $USAGE_KINDS, got $usageKind")
        }
        if (declKind != null && declKind !in DECLARATION_KINDS) {
            errors.add("declaration kind must be one of $DECLARATION_KINDS, got $declKind")
        }
        // `code=` carries TWO vocabularies: `diagnostic` expectations validate
        // against the engine's diagnostic codes, `signal` expectations against
        // the securitySignals vocabulary above. Each validates against its own.
        if (code != null && !code.startsWith("~") && kind == Kind.DIAGNOSTIC && code !in DiagnosticCodes.ALL) {
            errors.add(
                "unknown diagnostic code '$code'; known: ${DiagnosticCodes.ALL.sorted()} " +
                    "(register it in DiagnosticCodes when the engine starts emitting it)",
            )
        }
        if (mode != null && mode !in MODES) {
            errors.add("mode must be one of $MODES, got $mode")
        }
        // The parameter-identity keys only mean something on a flow expectation.
        if (kind != Kind.FLOW && (sourceParam != null || sourceTransport != null)) {
            errors.add("sourceparam=/sourcetransport= are only valid on flow expectations")
        }
        if (sourceParam != null && !SOURCE_PARAM.matches(sourceParam)) {
            errors.add("sourceparam must be #N (the handler's value-parameter index), got $sourceParam")
        }
        if (sourceTransport != null && sourceTransport !in SOURCE_TRANSPORTS) {
            errors.add("sourcetransport must be one of $SOURCE_TRANSPORTS, got $sourceTransport")
        }
        return errors
    }

    companion object {
        /** `usages[].usageKind` vocabulary (SyntaxAnalyzer emits exactly these). */
        val USAGE_KINDS = setOf("call", "operator", "reference")

        /** The bench matrix slots an annotation may scope itself to. */
        val MODES = setOf("security", "all", "resolved", "exported", "endpoint", "deps")

        /**
         * The closed `securitySignals[].code` vocabulary
         * (02-ARCHITECTURE.md §8); only `native-interop` emits today.
         */
        val SIGNAL_CODES = setOf(
            "native-interop", "unsafe-interop", "webview-config", "permissive-cors",
            "csrf-disabled", "debuggable", "cleartext-traffic", "reflection",
            "dynamic-code-load", "external-process", "serialization-config",
            "hardcoded-material",
        )

        /** The endpoint `foundBy`/framework vocabulary comes from the shipped pack. */
        val FORMS = setOf("literal", "const", "template", "config", "unresolved")

        /** The resolution vocabulary (03-SCHEMA.md UrlEvidence.resolution). */
        val RESOLUTIONS = setOf("literal", "folded", "config", "env", "unresolved")

        /** P20 §1: `sourceparam` shape and the transport vocabulary the pack's kinds name. */
        val SOURCE_PARAM = Regex("#[0-9]+")
        val SOURCE_TRANSPORTS = setOf("path", "query", "header", "cookie", "form", "body", "merged")

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


/** The closed framework vocabulary endpoint expectations validate against (the shipped pack's ids). */
object Frameworks {
    /**
     * Reserved pseudo-ids the DETECTOR emits but no pack models:
     * `unattributed` is a route whose shape matched but whose framework
     * could not be evidenced (P14) — valid in expectations, so a fixture
     * can pin that a miss is never a wrong attribution.
     */
    val RESERVED: Set<String> = setOf("unattributed")

    private val ids: Set<String> by lazy { EndpointModels.loadBuiltin().frameworkIds }

    fun all(): Set<String> = ids + RESERVED

    fun isValid(framework: String): Boolean = framework in all()
}
