// http4k-core 5.x by shape: Method is an enum; a handler is a function.
package org.http4k.core

enum class Method { GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH, PURGE, HEAD }

interface Request
class Response(val body: String = "")

typealias HttpHandler = (Request) -> Response
