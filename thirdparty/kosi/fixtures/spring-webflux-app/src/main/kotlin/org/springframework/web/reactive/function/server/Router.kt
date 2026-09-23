// spring-webflux 5.3.18 by SHAPE (javap): router { } builds a
// RouterFunctionDsl, coRouter { } a separate CoRouterFunctionDsl; routes are
// VERB(pattern, handler) / VERB(pattern, predicate, handler); path(pattern,
// handler) and invoke(pattern, handler) serve any method; nest(pattern |
// predicate, block) nests. The previous stub modelled path(prefix) { } as
// nesting, which the real API does not have.
package org.springframework.web.reactive.function.server

class ServerRequest
class ServerResponse
class RequestPredicate
class MediaType { companion object { val APPLICATION_JSON = MediaType() } }

class RouterFunctionDsl {
    fun GET(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun POST(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun PATCH(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun DELETE(pattern: String, predicate: RequestPredicate, f: (ServerRequest) -> ServerResponse) {}
    fun path(pattern: String): RequestPredicate = RequestPredicate()
    fun path(pattern: String, f: (ServerRequest) -> ServerResponse) {}
    fun accept(vararg mediaType: MediaType): RequestPredicate = RequestPredicate()
    fun String.nest(r: RouterFunctionDsl.() -> Unit) {}
    fun RequestPredicate.nest(r: RouterFunctionDsl.() -> Unit) {}
    operator fun String.invoke(f: (ServerRequest) -> ServerResponse) {}
}

class CoRouterFunctionDsl {
    fun GET(pattern: String, f: suspend (ServerRequest) -> ServerResponse) {}
    fun PUT(pattern: String, f: suspend (ServerRequest) -> ServerResponse) {}
    fun path(pattern: String): RequestPredicate = RequestPredicate()
    fun accept(vararg mediaType: MediaType): RequestPredicate = RequestPredicate()
    fun String.nest(r: CoRouterFunctionDsl.() -> Unit) {}
    fun RequestPredicate.nest(r: CoRouterFunctionDsl.() -> Unit) {}
}

fun router(routes: RouterFunctionDsl.() -> Unit): Unit = Unit
fun coRouter(routes: CoRouterFunctionDsl.() -> Unit): Unit = Unit
