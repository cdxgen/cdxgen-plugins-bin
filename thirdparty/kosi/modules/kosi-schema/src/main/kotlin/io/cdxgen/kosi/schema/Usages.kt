package io.cdxgen.kosi.schema

/**
 * LibraryUsage — canonical, cdxgen-critical (03-SCHEMA.md). `name` is the
 * dotted callee text as written (`stmt.executeQuery`, `ArrayList`), normalized
 * to whitespace-free form; `simpleName` is the last segment.
 */
data class LibraryUsage(
    val id: String,
    val name: String,
    val simpleName: String,
    val usageKind: String,
    val modulePath: String,
    val purl: String,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("filePath", filePath)
        w.str("id", id)
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.str("purl", purl)
        position.writeJson(w, "position")
        w.str("simpleName", simpleName)
        w.str("usageKind", usageKind)
        w.endObject()
    }

    companion object {
        const val KIND_CALL = "call"
        const val KIND_OPERATOR = "operator"
        const val KIND_REFERENCE = "reference"

        val COMPARATOR =
            compareBy<LibraryUsage>({ it.name }, { it.filePath }, { it.position.line }, { it.position.column })
    }
}

/** SecuritySignal — non-flow security findings (02-ARCHITECTURE.md §8). */
data class SecuritySignal(
    val code: String,
    val message: String,
    val modulePath: String,
    val purl: String,
    val filePath: String,
    val position: Position,
    /**
     * P9: the symbol the signal attaches to (the `external fun`'s canonical
     * name, the function containing the `loadLibrary` call), so corpus
     * annotations can demand a signal ON one function and the ABSENCE of the
     * same signal on its sibling — the same negative shape every other
     * evidence array has.
     */
    val symbol: String? = null,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("code", code)
        w.str("filePath", filePath)
        w.str("message", message)
        w.str("modulePath", modulePath)
        w.str("purl", purl)
        position.writeJson(w, "position")
        symbol?.let { w.str("symbol", it) }
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<SecuritySignal>({ it.code }, { it.filePath }, { it.position.line })
    }
}
