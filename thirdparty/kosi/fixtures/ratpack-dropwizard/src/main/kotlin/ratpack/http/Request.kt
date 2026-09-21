// Ratpack 1.x: the SAME API at the pre-JPMS package. R168's lesson is that a
// framework named in one spelling is invisible in the other, so the fixture
// carries both and the liveness sweep can see both.
package ratpack.http

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
