// The stub at the framework's real FQN. `parameters` is an ABSTRACT
// property — no backing field, a method call on the JVM — exactly the
// shape Ktor declares.
package io.ktor.server.application

interface ApplicationCall {
    val parameters: Map<String, String>
}
