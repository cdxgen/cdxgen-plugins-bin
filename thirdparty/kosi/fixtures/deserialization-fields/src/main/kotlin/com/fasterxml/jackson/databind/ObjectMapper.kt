// Jackson's ObjectMapper at its real package, with the real readValue
// signature the fixture exercises (the generic class-value overload).
package com.fasterxml.jackson.databind

class ObjectMapper {
    fun <T> readValue(content: String, valueType: Class<T>): T = error("stub")
}
