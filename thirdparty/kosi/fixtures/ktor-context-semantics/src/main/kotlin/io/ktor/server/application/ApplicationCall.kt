package io.ktor.server.application

import io.ktor.http.Parameters
import io.ktor.server.request.ApplicationRequest

interface ApplicationCall {
    /** Path AND query parameters together: the map cannot say which is which. */
    val parameters: Parameters
    val request: ApplicationRequest
}
