// Retrofit's method annotations at their real package, with the real
// `value` parameter that carries the relative path.
package retrofit2.http

@Target(AnnotationTarget.FUNCTION)
annotation class GET(val value: String)

@Target(AnnotationTarget.FUNCTION)
annotation class POST(val value: String)

@Target(AnnotationTarget.FUNCTION)
annotation class PUT(val value: String)

@Target(AnnotationTarget.FUNCTION)
annotation class DELETE(val value: String)
