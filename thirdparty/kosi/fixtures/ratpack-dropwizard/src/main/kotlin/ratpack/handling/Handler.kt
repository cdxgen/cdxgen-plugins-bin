// Ratpack 1.x handling package (2.0.0-rc-1 moved these to ratpack.core.*).
package ratpack.handling

import ratpack.http.Request

interface Context {
    fun getRequest(): Request
    fun render(o: Any?)
}

fun interface Handler {
    fun handle(context: Context)
}
