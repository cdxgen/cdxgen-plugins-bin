// Ratpack's request, at the 2.x package (the JPMS rename in 2.0.0-rc-1 moved
// `ratpack.http` to `ratpack.core.http`). Method names transcribed from
// ratpack.io/manual/current/api/ratpack/core/http/Request.html.
package ratpack.core.http

interface Headers { operator fun get(name: String): String? }
interface MultiValueMap<K, V> { operator fun get(key: K): V? }
interface TypedData { val text: String }
interface Promise<T> { fun map(f: (T) -> Any?): Promise<T> }

interface Request {
    fun getQueryParams(): MultiValueMap<String, String>
    fun getHeaders(): Headers
    fun getCookies(): Set<String>
    fun oneCookie(name: String): String?
    fun getBody(): Promise<TypedData>
    fun getBodyStream(): Promise<TypedData>
}
