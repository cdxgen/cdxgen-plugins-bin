package io.cdxgen.kosi.schema

/**
 * Strict recursive-descent JSON parser over [JsonValue]. Hand-rolled to keep
 * the dependency allowlist closed; there is no reflection anywhere near it.
 */
class JsonReader(private val text: String) {

    private var pos = 0

    fun read(): JsonValue {
        val value = readValue()
        skipWhitespace()
        if (pos != text.length) fail("trailing content at offset $pos")
        return value
    }

    private fun readValue(): JsonValue {
        skipWhitespace()
        if (pos >= text.length) fail("unexpected end of input")
        return when (text[pos]) {
            '{' -> readObject()
            '[' -> readArray()
            '"' -> JsonStr(readString())
            't' -> readKeyword("true", JsonBool(true))
            'f' -> readKeyword("false", JsonBool(false))
            'n' -> readKeyword("null", JsonNullValue)
            else -> readNumber()
        }
    }

    private fun readObject(): JsonObj {
        expect('{')
        val members = LinkedHashMap<String, JsonValue>()
        skipWhitespace()
        if (peek() == '}') {
            pos++
            return JsonObj(members)
        }
        while (true) {
            skipWhitespace()
            if (peek() != '"') fail("expected object key")
            val key = readString()
            skipWhitespace()
            expect(':')
            val value = readValue()
            if (members.containsKey(key)) fail("duplicate key: $key")
            members[key] = value
            skipWhitespace()
            when (peek()) {
                ',' -> pos++
                '}' -> {
                    pos++
                    return JsonObj(members)
                }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun readArray(): JsonArr {
        expect('[')
        val items = mutableListOf<JsonValue>()
        skipWhitespace()
        if (peek() == ']') {
            pos++
            return JsonArr(items)
        }
        while (true) {
            items.add(readValue())
            skipWhitespace()
            when (peek()) {
                ',' -> pos++
                ']' -> {
                    pos++
                    return JsonArr(items)
                }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private fun readString(): String {
        expect('"')
        val sb = StringBuilder()
        while (true) {
            if (pos >= text.length) fail("unterminated string")
            when (val c = text[pos]) {
                '"' -> {
                    pos++
                    return sb.toString()
                }
                '\\' -> {
                    pos++
                    if (pos >= text.length) fail("unterminated escape")
                    when (val e = text[pos]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append(12.toChar())
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (pos + 4 >= text.length) fail("truncated unicode escape")
                            val hex = text.substring(pos + 1, pos + 5)
                            sb.append(hex.toIntOrNull(16)?.toChar() ?: fail("bad unicode escape: $hex"))
                            pos += 4
                        }
                        else -> fail("bad escape: \\$e")
                    }
                    pos++
                }
                else -> {
                    if (c.code < 0x20) fail("unescaped control character")
                    sb.append(c)
                    pos++
                }
            }
        }
    }

    private fun readNumber(): JsonNum {
        val start = pos
        if (peek() == '-') pos++
        while (pos < text.length && text[pos].isDigitOrDotOrExp()) pos++
        val raw = text.substring(start, pos)
        if (raw.isEmpty() || raw == "-") fail("bad number at offset $start")
        raw.toDoubleOrNull() ?: fail("bad number: $raw")
        return JsonNum(raw)
    }

    private fun Char.isDigitOrDotOrExp(): Boolean =
        isDigit() || this == '.' || this == 'e' || this == 'E' || this == '+' || this == '-'

    private fun readKeyword(word: String, value: JsonValue): JsonValue {
        if (pos + word.length > text.length || text.substring(pos, pos + word.length) != word) {
            fail("expected $word")
        }
        pos += word.length
        return value
    }

    private fun skipWhitespace() {
        while (pos < text.length && text[pos].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }) pos++
    }

    private fun peek(): Char {
        if (pos >= text.length) fail("unexpected end of input")
        return text[pos]
    }

    private fun expect(c: Char) {
        if (pos >= text.length || text[pos] != c) fail("expected '$c'")
        pos++
    }

    private fun fail(message: String): Nothing = throw JsonValue.JsonParseException("$message at offset $pos")

    companion object {
        fun parse(text: String): JsonValue = JsonReader(text).read()
    }
}
