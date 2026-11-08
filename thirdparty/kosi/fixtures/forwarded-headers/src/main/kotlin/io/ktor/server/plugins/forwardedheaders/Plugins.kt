// Ktor declares both plugins as top-level vals (ForwardedHeaders.kt and
// XForwardedHeaders.kt in ktor-server-forwarded-header).
package io.ktor.server.plugins.forwardedheaders

import io.ktor.server.application.ApplicationPlugin

class ForwardedHeadersConfig

class XForwardedHeadersConfig

val ForwardedHeaders: ApplicationPlugin<ForwardedHeadersConfig> = ApplicationPlugin()

val XForwardedHeaders: ApplicationPlugin<XForwardedHeadersConfig> = ApplicationPlugin()
