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
 * Every truncation, cap, fallback and unresolved thing becomes one of these
 * (03-SCHEMA.md rule 5). Codes are machine-readable and stable; see
 * JSON_ATTRIBUTE_REFERENCE.md §diagnostics for the registry.
 */
data class Diagnostic(
    val code: String,
    val severity: Severity,
    val message: String,
    val position: Position? = null,
    val count: Int? = null,
) {
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
