package io.cdxgen.kosi.schema

/**
 * A source position. `filename` is relative to the analysis root with POSIX
 * separators; `line` and `column` are 1-based.
 */
data class Position(
    val filename: String,
    val line: Int,
    val column: Int,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("filename", filename)
        w.num("line", line)
        w.num("column", column)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<Position> { it.filename }.thenBy { it.line }.thenBy { it.column }
    }
}

/** severity for [Diagnostic]. */
enum class Severity(val id: String) {
    INFO("info"),
    WARNING("warning"),
    ERROR("error"),
    ;

    companion object {
        fun fromId(id: String): Severity? = entries.firstOrNull { it.id == id }
    }
}

/**
 * The closed registry of diagnostic codes, mirroring
 * JSON_ATTRIBUTE_REFERENCE.md §diagnostics. It lives here rather than in the
 * corpus module so there is exactly one list: [Diagnostic] rejects an
 * unregistered code, and a corpus annotation naming an unregistered code is an
 * annotation error instead of a negative expectation that passes vacuously.
 * A phase that emits a new code adds it here and to the reference doc.
 */
object DiagnosticCodes {
    const val PARSE_ERROR = "parse-error"
    const val SYNTAX_BACKEND_NO_RESOLUTION = "syntax-backend-no-resolution"
    const val JAVA_SOURCE_NOT_PARSED = "java-source-not-parsed"
    const val KOTLIN_LANGUAGE_VERSION = "kotlin-language-version"
    const val KOTLIN_VERSION = "kotlin-version"
    const val KOTLIN_API_VERSION = "kotlin-api-version"
    const val VERSION_OVERRIDE = "version-override"
    const val CLASSPATH_PARTIAL = "classpath-partial"
    const val RESOLUTION_ERRORS = "resolution-errors"
    const val NO_BUILD_FILES = "no-build-files"
    const val NO_SOURCES = "no-sources"
    const val UNREADABLE_SOURCE = "unreadable-source"

    val ALL: Set<String> = setOf(
        PARSE_ERROR,
        SYNTAX_BACKEND_NO_RESOLUTION,
        JAVA_SOURCE_NOT_PARSED,
        KOTLIN_LANGUAGE_VERSION,
        KOTLIN_VERSION,
        KOTLIN_API_VERSION,
        VERSION_OVERRIDE,
        CLASSPATH_PARTIAL,
        RESOLUTION_ERRORS,
        NO_BUILD_FILES,
        NO_SOURCES,
        UNREADABLE_SOURCE,
    )
}

/**
 * Every truncation, cap, fallback and unresolved thing becomes one of these
 * (03-SCHEMA.md rule 5). Codes are machine-readable and stable; see
 * [DiagnosticCodes] and JSON_ATTRIBUTE_REFERENCE.md §diagnostics.
 */
data class Diagnostic(
    val code: String,
    val severity: Severity,
    val message: String,
    val position: Position? = null,
    val count: Int? = null,
) {
    init {
        require(code in DiagnosticCodes.ALL) {
            "unregistered diagnostic code '$code'; add it to DiagnosticCodes and " +
                "JSON_ATTRIBUTE_REFERENCE.md"
        }
    }

    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("code", code)
        w.str("severity", severity.id)
        w.str("message", message)
        position?.writeJson(w, "position")
        if (count != null) w.num("count", count)
        w.endObject()
    }

    companion object {
        val COMPARATOR =
            compareBy<Diagnostic>({ it.code }, { it.severity.id }, { it.message })
                .thenComparing { it.position?.filename ?: "" }
                .thenComparing { it.position?.line ?: 0 }
    }
}
