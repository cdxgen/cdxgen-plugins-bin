package com.fasterxml.jackson.databind

class ObjectMapper {
    fun <T> readValue(content: String, valueType: Class<T>): T = throw UnsupportedOperationException()
}
