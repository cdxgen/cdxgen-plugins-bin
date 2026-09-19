// kotlinx.serialization's Json at its real package. The real
// decodeFromString is an inline reified extension on String taking a
// DeserializationStrategy; the stub keeps the call shape the fixture makes.
package kotlinx.serialization.json

import kotlinx.serialization.DeserializationStrategy

class Json {
    fun <T> decodeFromString(deserializer: DeserializationStrategy<T>, string: String): T = error("stub")
}
