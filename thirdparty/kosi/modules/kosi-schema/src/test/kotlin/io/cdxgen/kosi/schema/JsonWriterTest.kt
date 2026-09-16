package io.cdxgen.kosi.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

// Negative-first: the determinism contract is the product here. These tests
// assert the failure modes golem/rusi hit (unsorted keys, duplicate keys,
// locale-dependent doubles) fail loudly.
class JsonWriterTest {

    @Test
    fun duplicateKeysThrow() {
        val w = JsonWriter()
        w.beginObject()
        w.str("a", "1")
        assertFailsWith<IllegalArgumentException> { w.str("a", "2") }
        w.endObject()
    }

    @Test
    fun twoTopLevelValuesThrow() {
        val w = JsonWriter()
        w.beginObject()
        w.str("a", "1")
        w.endObject()
        assertFailsWith<IllegalStateException> { w.beginObject() }
        assertFailsWith<IllegalStateException> { w.beginArray() }
        assertFailsWith<IllegalStateException> { w.str("b", "2") }
    }

    @Test
    fun nonFiniteDoublesThrow() {
        val w = JsonWriter()
        w.beginObject()
        assertFailsWith<IllegalArgumentException> { w.dbl("x", Double.NaN) }
    }

    @Test
    fun keysAreSortedByteWise() {
        val w = JsonWriter()
        w.beginObject()
        w.str("zeta", "1")
        w.str("Alpha", "2")
        w.str("beta", "3")
        w.num("10", 4)
        w.num("2", 5)
        w.endObject()
        // Byte order puts digits before letters and uppercase before lowercase.
        assertEquals("""{"10":4,"2":5,"Alpha":"2","beta":"3","zeta":"1"}""", w.render())
    }

    @Test
    fun doublesAreDeterministic() {
        // The property is the determinism CONTRACT, not three lucky
        // renderings: 6dp HALF_UP, trailing zeros stripped, plain dot
        // decimal, and the render PARSES BACK to the value it names. A
        // formatting change that keeps the three originals (locale comma,
        // scientific notation, 7th-digit carry) fails the spread.
        val cases = linkedMapOf(
            0.0 to "0",
            0.5 to "0.5",
            123.456789012 to "123.456789",
            0.000001 to "0.000001",
            1.0E-7 to "0",
            -2.75 to "-2.75",
            0.0025 to "0.0025",
            1234567.5 to "1234567.5",
        )
        for ((value, expected) in cases) {
            assertEquals(expected, JsonWriter.formatDouble(value), "render of $value")
            val rendered = JsonWriter.formatDouble(value)
            assertEquals(rendered.toDouble(), JsonReader.parse("""{"v":$rendered}""").asObject().dbl("v"), "parse of render($value)")
        }
    }

    @Test
    fun nestedStructureAndPretty() {
        // The pretty half used to assert one hand-written expected string —
        // an example that happened to parse, which is exactly the class the
        // P16 review found in this file (R103: the pretty test contained no
        // empty container, so a prettifier that emitted invalid JSON passed
        // it). The properties `--pretty` actually promises: it ONLY
        // re-indents — the pretty render parses to the same value as the
        // minified one, and differs from it by whitespace OUTSIDE strings
        // alone. The string values deliberately contain characters the
        // prettifier's state machine must NOT treat as structure ({, }, ,,
        // : and escapes).
        fun write(w: JsonWriter): JsonWriter {
            w.beginObject()
            w.beginArray("items")
            w.beginObject()
            w.str("n", "a")
            w.str("tricky", "brace{close},colon:comma\\quote\"tab\t")
            w.endObject()
            w.beginObject()
            w.str("n", "b")
            w.endObject()
            w.endArray()
            w.nul("missing")
            w.bool("ok", true)
            w.endObject()
            return w
        }
        val minified = write(JsonWriter()).render()
        assertEquals("""{"items":[{"n":"a","tricky":"brace{close},colon:comma\\quote\"tab\t"},{"n":"b"}],"missing":null,"ok":true}""", minified)
        val pretty = write(JsonWriter(pretty = true)).render()
        assertEquals(JsonReader.parse(minified), JsonReader.parse(pretty), "pretty must parse to the same value")
        assertEquals(minified, whitespaceOutsideStrings(pretty), "pretty differs from minified by whitespace alone")
    }

    /** Every whitespace character that is not inside a JSON string, dropped. */
    private fun whitespaceOutsideStrings(s: String): String {
        val out = StringBuilder(s.length)
        var inString = false
        var escaped = false
        for (c in s) {
            when {
                inString -> {
                    out.append(c)
                    if (escaped) escaped = false
                    else if (c == '\\') escaped = true
                    else if (c == '"') inString = false
                }
                c == '"' -> {
                    inString = true
                    out.append(c)
                }
                !c.isWhitespace() -> out.append(c)
            }
        }
        return out.toString()
    }

    @Test
    fun prettyRendersEmptyContainersAsValidJson() {
        // P16 review: the prettifier emitted the inline `[]`/`{}` and then
        // re-read the input's own closing bracket as a close, so every
        // document containing an empty container — every kosi report —
        // came out of `--pretty` with a stray bracket and did not parse.
        // The docs promise `--pretty` ONLY re-indents, so the invariant the
        // test pins is round-trip equality with the minified render.
        fun write(w: JsonWriter): JsonWriter {
            w.beginObject()
            w.beginArray("empty")
            w.endArray()
            w.beginObject("emptyObject")
            w.endObject()
            w.beginArray("items")
            w.beginObject()
            w.beginArray("inner")
            w.endArray()
            w.str("n", "a")
            w.endObject()
            w.endArray()
            w.bool("ok", true)
            w.endObject()
            return w
        }
        val minified = write(JsonWriter()).render()
        val pretty = write(JsonWriter(pretty = true)).render()
        assertEquals(JsonReader.parse(minified), JsonReader.parse(pretty))
        assertTrue("[]" in pretty && "{}" in pretty, "empty containers stay inline: $pretty")
    }
}

class JsonReaderTest {

    @Test
    fun trailingContentFails() {
        assertFailsWith<JsonValue.JsonParseException> { JsonReader.parse("""{"a":1} junk""") }
    }

    @Test
    fun duplicateKeysFail() {
        assertFailsWith<JsonValue.JsonParseException> { JsonReader.parse("""{"a":1,"a":2}""") }
    }

    @Test
    fun trailingCommaFails() {
        assertFailsWith<JsonValue.JsonParseException> { JsonReader.parse("""[1,2,]""") }
    }

    @Test
    fun roundTripThroughWriter() {
        // The reader must give back exactly what was written for EVERY value
        // class the writer can emit — the escape machinery (quotes,
        // backslash, control characters as \uXXXX) is exercised here, not
        // just the plain scalars the original example carried: a reader (or
        // writer) that mishandled any escape would otherwise pass.
        val tricky = "quote\" back\\ nl\n cr\r tab\t bs\u0008 ff\u000C ctrl\u0001 uni héllo→"
        val w = JsonWriter()
        w.beginObject()
        w.str("name", "kosi")
        w.num("count", 42)
        w.dbl("ratio", 0.25)
        w.bool("ok", true)
        w.nul("none")
        w.str("tricky", tricky)
        w.beginArray("list")
        w.str("x")
        w.str("y")
        w.endArray()
        w.endObject()
        val doc = w.render()
        val obj = JsonReader.parse(doc).asObject()
        assertEquals("kosi", obj.str("name"))
        assertEquals(42L, obj.long("count"))
        assertEquals(0.25, obj.dbl("ratio"))
        assertEquals(true, obj.bool("ok"))
        assertEquals(JsonNullValue, obj["none"])
        assertEquals(listOf("x", "y"), obj.arr("list")!!.strings())
        assertEquals(tricky, obj.str("tricky"), "every escaped character must survive the round trip")
    }
}
