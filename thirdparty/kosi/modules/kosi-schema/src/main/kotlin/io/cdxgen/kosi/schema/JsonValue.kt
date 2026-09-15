package io.cdxgen.kosi.schema

/**
 * Minimal hand-rolled JSON value model + recursive-descent reader, used for
 * baselines, digest goldens, model packs and user pattern packs. Strict JSON
 * (RFC 8259): no comments, no trailing commas, no unquoted keys. Duplicate
 * keys in an object are rejected rather than silently overwritten.
 *
 * Object key order is *preserved* while reading (LinkedHashMap) so round-trip
 * comparisons behave predictably; writers still emit sorted keys.
 */
sealed interface JsonValue {
    fun asObject(): JsonObj = throw JsonParseException("expected object, got ${this::class.simpleName}")
    fun asArray(): JsonArr = throw JsonParseException("expected array, got ${this::class.simpleName}")
    fun asString(): String = throw JsonParseException("expected string, got ${this::class.simpleName}")
    fun asLong(): Long = throw JsonParseException("expected number, got ${this::class.simpleName}")
    fun asDouble(): Double = throw JsonParseException("expected number, got ${this::class.simpleName}")
    fun asBoolean(): Boolean = throw JsonParseException("expected boolean, got ${this::class.simpleName}")

    class JsonParseException(message: String) : IllegalArgumentException(message)
}

data class JsonObj(val members: LinkedHashMap<String, JsonValue>) : JsonValue {
    override fun asObject(): JsonObj = this

    operator fun get(key: String): JsonValue? = members[key]

    fun str(key: String): String? = (members[key] as? JsonStr)?.value

    fun long(key: String): Long? = (members[key] as? JsonNum)?.asLong()

    fun dbl(key: String): Double? = (members[key] as? JsonNum)?.asDouble()

    fun bool(key: String): Boolean? = (members[key] as? JsonBool)?.value

    fun obj(key: String): JsonObj? = members[key] as? JsonObj

    fun arr(key: String): JsonArr? = members[key] as? JsonArr

    fun strList(key: String): List<String> = arr(key)?.strings() ?: emptyList()
}

data class JsonArr(val items: MutableList<JsonValue>) : JsonValue {
    override fun asArray(): JsonArr = this

    fun strings(): List<String> = items.map { it.asString() }

    fun objects(): List<JsonObj> = items.map { it.asObject() }
}

data class JsonStr(val value: String) : JsonValue {
    override fun asString(): String = value
}

data class JsonNum(val raw: String) : JsonValue {
    override fun asLong(): Long = raw.toLongOrNull() ?: raw.toDouble().toLong()
    override fun asDouble(): Double = raw.toDouble()
}

data class JsonBool(val value: Boolean) : JsonValue {
    override fun asBoolean(): Boolean = value
}

data object JsonNullValue : JsonValue
