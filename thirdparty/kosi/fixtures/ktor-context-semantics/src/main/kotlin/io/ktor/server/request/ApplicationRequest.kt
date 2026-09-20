// Ktor declares its readers as ABSTRACT properties — no backing field, so
// reading one runs a method on the JVM.
package io.ktor.server.request

import io.ktor.http.Parameters

interface ApplicationRequest {
    val queryParameters: Parameters
    val headers: Parameters
    /** ktor's own API: the request's cookies (api.ktor.io, ApplicationRequest). */
    val cookies: Parameters
}

/** The single-header reader (ktor docs, Headers and cookies: `request.header(name)`). */
fun ApplicationRequest.header(name: String): String? = null

/** The raw query string (ktor docs: `request.queryString()`). */
fun ApplicationRequest.queryString(): String = ""
