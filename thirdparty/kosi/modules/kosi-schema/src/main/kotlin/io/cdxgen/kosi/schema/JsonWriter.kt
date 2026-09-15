package io.cdxgen.kosi.schema

import java.math.BigDecimal
import java.math.RoundingMode

/**
 * Hand-rolled streaming JSON writer. No kotlinx.serialization, no reflection.
 *
 * Determinism contract (the reason this class exists):
 *  - object members are emitted sorted by key (byte-wise, locale-independent);
 *  - array order is the order the caller emits, which every producer keeps
 *    sorted by the canonical ordering of its collection;
 *  - doubles are rounded to 6 decimal places, trailing zeros stripped, always
 *    with a dot decimal separator;
 *  - the output is minified unless [pretty] is set, which uses a two-space
 *    indent.
 *
 * Containers buffer until closed so objects can be key-sorted; primitives are
 * rendered immediately. Duplicate keys are a programmer error and throw.
 *
 * Convention for `writeJson(w, key)` emitters: a type renders itself with
 * `beginObject(key)` / `endObject()`, so a caller nests it under a report key
 * by passing the key, or inside an array by leaving the key null.
 */
class JsonWriter(private val pretty: Boolean = false) {

    private sealed interface Node {
        fun render(): String
    }

    private class ObjectNode : Node {
        val members = LinkedHashMap<String, String>()
        override fun render(): String {
            if (members.isEmpty()) return "{}"
            val out = StringBuilder("{")
            var first = true
            for ((key, value) in members.toSortedMap()) {
                if (!first) out.append(',')
                first = false
                appendQuoted(out, key).append(':').append(value)
            }
            return out.append('}').toString()
        }
    }

    private class ArrayNode : Node {
        val items = mutableListOf<String>()
        override fun render(): String =
            if (items.isEmpty()) "[]" else items.joinToString(prefix = "[", postfix = "]", separator = ",")
    }

    private class Frame(val key: String?, val node: Node)

    private val stack = ArrayDeque<Frame>()

    fun beginObject(key: String? = null) {
        checkTopLevel()
        stack.addLast(Frame(key, ObjectNode()))
    }

    fun endObject() {
        val frame = popFrame<ObjectNode>()
        commit(frame.key, frame.node.render())
    }

    fun beginArray(key: String? = null) {
        checkTopLevel()
        stack.addLast(Frame(key, ArrayNode()))
    }

    fun endArray() {
        val frame = popFrame<ArrayNode>()
        commit(frame.key, frame.node.render())
    }

    fun str(key: String, value: String?) = commit(key, if (value == null) "null" else renderString(value))

    fun str(value: String) = commit(null, renderString(value))

    fun num(key: String, value: Long) = commit(key, value.toString())

    fun num(key: String, value: Int) = commit(key, value.toLong().toString())

    fun num(value: Long) = commit(null, value.toString())

    fun dbl(key: String, value: Double) = commit(key, formatDouble(value))

    fun dbl(value: Double) = commit(null, formatDouble(value))

    fun bool(key: String, value: Boolean) = commit(key, if (value) "true" else "false")

    fun bool(value: Boolean) = commit(null, if (value) "true" else "false")

    fun nul(key: String) = commit(key, "null")

    /** Renders the finished document. Exactly one top-level value is expected. */
    fun render(): String {
        check(stack.isEmpty()) { "unbalanced writer: ${stack.size} frame(s) still open" }
        check(root != null) { "nothing written" }
        return if (pretty) prettify(root!!) else root!!
    }

    // ---- internals -------------------------------------------------------

    private var root: String? = null

    private fun checkTopLevel() {
        check(stack.isNotEmpty() || root == null) { "more than one top-level value" }
    }

    private fun commit(key: String?, rendered: String) {
        val frame = stack.lastOrNull()
        if (frame == null) {
            check(root == null) { "more than one top-level value" }
            root = rendered
            return
        }
        when (val node = frame.node) {
            is ObjectNode -> {
                checkNotNull(key) { "object member without key" }
                require(!node.members.containsKey(key)) { "duplicate key: $key" }
                node.members[key] = rendered
            }
            is ArrayNode -> {
                check(key == null) { "array items must not carry a key" }
                node.items.add(rendered)
            }
        }
    }

    private inline fun <reified T : Node> popFrame(): Frame {
        val frame = stack.removeLast()
        check(frame.node is T) {
            "unbalanced begin/end: closing ${T::class.simpleName} over ${frame.node::class.simpleName}"
        }
        return frame
    }

    companion object {
        /** Deterministic double rendering: 6 dp, HALF_UP, trailing zeros stripped. */
        fun formatDouble(value: Double): String {
            require(value.isFinite()) { "non-finite double is not representable in JSON" }
            return BigDecimal(value)
                .setScale(6, RoundingMode.HALF_UP)
                .stripTrailingZeros()
                .toPlainString()
        }

        fun renderString(s: String): String = appendQuoted(StringBuilder(), s).toString()

        fun appendQuoted(sb: StringBuilder, s: String): StringBuilder {
            sb.append('"')
            for (c in s) {
                when {
                    c == '"' -> sb.append("\\\"")
                    c == '\\' -> sb.append("\\\\")
                    c == '\n' -> sb.append("\\n")
                    c == '\r' -> sb.append("\\r")
                    c == '\t' -> sb.append("\\t")
                    c == '\b' -> sb.append("\\b")
                    c.code == 12 -> sb.append("\\f")
                    c.code < 32 -> sb.append("\\u").append(String.format("%04x", c.code))
                    else -> sb.append(c)
                }
            }
            return sb.append('"')
        }

        /** Re-indents a minified document with a two-space indent (for --pretty). */
        fun prettify(minified: String): String {
            val out = StringBuilder(minified.length * 2)
            var indent = 0
            var inString = false
            var escaped = false
            var i = 0
            fun newlineIndent() {
                out.append('\n')
                repeat(indent) { out.append("  ") }
            }
            while (i < minified.length) {
                val c = minified[i]
                when {
                    inString -> {
                        out.append(c)
                        if (escaped) {
                            escaped = false
                        } else if (c == '\\') {
                            escaped = true
                        } else if (c == '"') {
                            inString = false
                        }
                    }
                    c == '"' -> {
                        inString = true
                        out.append(c)
                    }
                    c == '{' || c == '[' -> {
                        val close = if (c == '{') '}' else ']'
                        out.append(c)
                        if (nextMeaningful(minified, i) == close) {
                            out.append(close)
                            i++
                            continue
                        }
                        indent++
                        newlineIndent()
                    }
                    c == '}' || c == ']' -> {
                        indent = (indent - 1).coerceAtLeast(0)
                        newlineIndent()
                        out.append(c)
                    }
                    c == ',' -> {
                        out.append(c)
                        newlineIndent()
                    }
                    c == ':' -> out.append(": ")
                    else -> out.append(c)
                }
                i++
            }
            return out.toString()
        }

        private fun nextMeaningful(s: String, from: Int): Char {
            for (i in from + 1 until s.length) {
                if (s[i] != ' ') return s[i]
            }
            return ' '
        }
    }
}
