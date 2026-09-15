package io.cdxgen.kosi.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
        val w = JsonWriter()
        w.beginObject()
        w.dbl("zero", 0.0)
        w.dbl("ratio", 0.5)
        w.dbl("precise", 123.456789012)
        w.endObject()
        assertEquals("""{"precise":123.456789,"ratio":0.5,"zero":0}""", w.render())
    }

    @Test
    fun nestedStructureAndPretty() {
        val w = JsonWriter()
        w.beginObject()
        w.beginArray("items")
        w.beginObject()
        w.str("n", "a")
        w.endObject()
        w.beginObject()
        w.str("n", "b")
        w.endObject()
        w.endArray()
        w.nul("missing")
        w.bool("ok", true)
        w.endObject()
        val minified = w.render()
        assertEquals("""{"items":[{"n":"a"},{"n":"b"}],"missing":null,"ok":true}""", minified)
        val pretty = JsonWriter(pretty = true)
        pretty.beginObject()
        pretty.beginArray("items")
        pretty.beginObject()
        pretty.str("n", "a")
        pretty.endObject()
        pretty.endArray()
        pretty.nul("missing")
        pretty.bool("ok", true)
        pretty.endObject()
        assertEquals(
            "{\n  \"items\": [\n    {\n      \"n\": \"a\"\n    }\n  ],\n  \"missing\": null,\n  \"ok\": true\n}",
            pretty.render(),
        )
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
        val w = JsonWriter()
        w.beginObject()
        w.str("name", "kosi")
        w.num("count", 42)
        w.dbl("ratio", 0.25)
        w.bool("ok", true)
        w.nul("none")
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
    }
}
