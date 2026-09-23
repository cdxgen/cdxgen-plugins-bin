// ratpack.io/manual/current/api/ratpack/core/handling/Chain.html, by shape:
// get/post/.. (path, handler) serve one method, path(path, handler) any,
// prefix(path, action) nests. Handler is a SAM, so a lambda is a handler.
package ratpack.core.handling

fun interface Action<T> {
    fun execute(t: T)
}

interface Chain {
    fun get(path: String, handler: Handler): Chain
    fun post(path: String, handler: Handler): Chain
    fun path(path: String, handler: Handler): Chain
    fun prefix(prefix: String, action: Action<Chain>): Chain
}
