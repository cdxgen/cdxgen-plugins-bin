// Ktor 1.x's authentication wrapper at its 1.x package.
package io.ktor.auth

import io.ktor.routing.Route1

fun Route1.authenticate(provider: String? = null, build: suspend Route1.() -> Unit): Unit = Unit
