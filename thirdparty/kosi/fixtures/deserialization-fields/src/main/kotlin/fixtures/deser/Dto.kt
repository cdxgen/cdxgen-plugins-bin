// — the produced object carries the input's taint on its FIELDS.
//
// A deserializer (Jackson readValue, kotlinx decodeFromString, Gson
// fromJson) hands back an OBJECT whose fields hold the input's content —
// which is how a request body reaches a sink through a DTO. Until this
// phase the pack modelled the call as a SINK (deserializing untrusted bytes
// is a finding) and as a passthrough (the result register carries the
// input's taint) — but a FIELD READ of the result derived nothing, so the
// DTO hop, the most common server-side shape, was invisible.
//
// Positive halves — one per library, the field read must reach the sink:
// kosi:want flow source=untrusted-input sink=sql-query fn=~jacksonThroughDto known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~kotlinxThroughDto known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~gsonThroughDto known-fail=syntax:1
// The crossBoundaryDto want above carries known-fail=163 (the boundary's
// wildcard field channel); these three are found in the same frame.
//
// Negative halves:
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~cleanInputNoFlow
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~unrelatedObjectNoFlow
// kosi:want-not diagnostic code=parse-error
package fixtures.deser

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.gson.Gson
import kotlinx.serialization.json.Json

data class UserDto(val name: String, val role: String)

private fun query(value: String) {
    val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:dto")
    conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + value + "'")
}

fun jacksonThroughDto() {
    val body = readLine() ?: ""
    val mapper = ObjectMapper()
    val user = mapper.readValue(body, UserDto::class.java)
    query(user.name)
}

fun kotlinxThroughDto(strategy: kotlinx.serialization.DeserializationStrategy<UserDto>) {
    val body = readLine() ?: ""
    val json = Json()
    val user = json.decodeFromString(strategy, body)
    query(user.name)
}

fun gsonThroughDto() {
    val body = readLine() ?: ""
    val gson = Gson()
    val user = gson.fromJson(body, UserDto::class.java)
    query(user.name)
}

// The CROSS-BOUNDARY half: the callee deserializes, the CALLER reads the
// field. The summary channel that would carry "param N's taint reaches
// EVERY field of the return" (the wildcard mirror of paramToReturnFields)
// does not exist yet, so the DTO hop dies at the boundary — counted, not
// silent.
// kosi:want flow source=untrusted-input sink=sql-query fn=~crossBoundaryDto known-fail=163
fun deserializeInside(raw: String): UserDto {
    val mapper = ObjectMapper()
    return mapper.readValue(raw, UserDto::class.java)
}

fun crossBoundaryDto() {
    val raw = readLine() ?: ""
    val user = deserializeInside(raw)
    query(user.name)
}

// A CLEAN input through the same boundary carries nothing — the DTO's fields
// read clean, and the deserialization SINK (if it were live on the input)
// is not what this negative is about.
fun cleanInputNoFlow() {
    val mapper = ObjectMapper()
    val user = mapper.readValue("constant", UserDto::class.java)
    query(user.name)
}

// A tainted value on an object that did NOT come out of a deserializer: the
// taint sits on the object's own fields (the channels), and a field read
// derives nothing extra — fieldBearing must not leak to ordinary objects.
fun unrelatedObjectNoFlow() {
    val dto = UserDto(name = "fixed", role = "user")
    query(dto.name + (readLine() ?: "").length.toString())
}
