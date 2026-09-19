// The HOMONYM negative: an annotation named GET in THIS package, with no
// Retrofit anywhere in this file's scope. Resolved-FQN matching must not see
// Retrofit in it — a short-name match would publish a services[] row for an
// annotation the library has never heard of.
// kosi:want-not service protocol=https path=homonym/{x} mode=resolved
package fixtures.outbound

@Target(AnnotationTarget.FUNCTION)
annotation class GET(val value: String)

interface Lookalike {
    @GET("homonym/{x}")
    fun thing(x: String): String
}

fun callsLookalike(l: Lookalike, x: String) {
    l.thing(x)
}
