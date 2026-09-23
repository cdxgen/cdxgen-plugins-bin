// ratpack-core 1.9 by shape: Chain in ratpack.handling (2.x moved it to
// ratpack.core.handling).
package ratpack.handling

interface Chain {
    fun get(path: String, handler: Handler): Chain
    fun post(path: String, handler: Handler): Chain
    fun put(path: String, handler: Handler): Chain
    fun patch(path: String, handler: Handler): Chain
    fun delete(path: String, handler: Handler): Chain
    fun options(path: String, handler: Handler): Chain
    fun path(path: String, handler: Handler): Chain
    fun prefix(prefix: String, action: ratpack.func.Action<Chain>): Chain
}
