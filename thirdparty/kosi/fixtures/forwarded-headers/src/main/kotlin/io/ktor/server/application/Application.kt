// Stub of the Ktor 2/3 shapes the forwarded-header rule reads: plugins are
// top-level ApplicationPlugin values installed through Application.install.
package io.ktor.server.application

class Application

class ApplicationPlugin<C>

fun <C> Application.install(plugin: ApplicationPlugin<C>, configure: C.() -> Unit = {}) {}
