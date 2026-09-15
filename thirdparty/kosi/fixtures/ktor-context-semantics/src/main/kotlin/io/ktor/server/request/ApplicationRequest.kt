// Ktor declares its readers as ABSTRACT properties — no backing field, so
// reading one runs a method on the JVM.
package io.ktor.server.request

import io.ktor.http.Parameters

interface ApplicationRequest {
    val queryParameters: Parameters
    val headers: Parameters
}
