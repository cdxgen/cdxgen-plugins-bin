// Ktor's parameter map. The read is an INDEXED get, not a named method:
// `call.parameters["id"]`.
package io.ktor.http

interface Parameters {
    operator fun get(name: String): String?
}
