// spring-webmvc 5.3.18 by SHAPE (javap): every verb as VERB(pattern, handler) and the
// predicate-building VERB(pattern); path(pattern) / path(pattern, handler);
// nest on a String or a predicate; String.invoke(handler).
package org.springframework.web.servlet.function

class ServerRequest
class ServerResponse
class RequestPredicate
class MediaType { companion object { val APPLICATION_JSON = MediaType() } }

class RouterFunctionDsl {
    fun GET(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun GET(pattern: String): RequestPredicate = RequestPredicate()
    fun POST(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun POST(pattern: String): RequestPredicate = RequestPredicate()
    fun PUT(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun PUT(pattern: String): RequestPredicate = RequestPredicate()
    fun PATCH(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun PATCH(pattern: String): RequestPredicate = RequestPredicate()
    fun DELETE(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun DELETE(pattern: String): RequestPredicate = RequestPredicate()
    fun HEAD(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun HEAD(pattern: String): RequestPredicate = RequestPredicate()
    fun OPTIONS(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun OPTIONS(pattern: String): RequestPredicate = RequestPredicate()
    fun path(pattern: String): RequestPredicate = RequestPredicate()
    fun path(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun accept(vararg mediaType: MediaType): RequestPredicate = RequestPredicate()
    fun String.nest(r: RouterFunctionDsl.() -> Unit) {}
    fun RequestPredicate.nest(r: RouterFunctionDsl.() -> Unit) {}
    operator fun String.invoke(f: (ServerRequest) -> ServerResponse) {}
}

fun router(routes: RouterFunctionDsl.() -> Unit): Unit = Unit
