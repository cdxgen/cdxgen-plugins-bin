// ktor-server-host-common 2.x by shape: the engine environment builder,
// whose rootPath prefixes every route (ktor.io "Configuration in code").
package io.ktor.server.engine

import io.ktor.server.application.Application

class ApplicationEngineEnvironmentBuilder {
    var rootPath: String = ""
    fun module(body: Application.() -> Unit) {}
}

fun applicationEngineEnvironment(builder: ApplicationEngineEnvironmentBuilder.() -> Unit): Any = Any()

// ktor-server-core 3.x: the server configuration builder, rootPath the same.
class ServerConfigBuilder {
    var rootPath: String = ""
    fun module(body: Application.() -> Unit) {}
}

fun serverConfig(builder: ServerConfigBuilder.() -> Unit): Any = Any()
