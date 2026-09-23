// ratpack-core 1.9 by shape: Action lives in ratpack.func.
package ratpack.func

fun interface Action<T> {
    fun execute(t: T)
}
