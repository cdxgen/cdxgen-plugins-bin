// Ktor 1.x's call and its parameter readers, at the 1.x packages
// (verified against ktor-server-core-jvm 1.6.7, the corpus pin).
package io.ktor.application

class ApplicationCall1 {
    val parameters: Map<String, String> get() = emptyMap()
}
