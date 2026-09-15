// JAX-RS annotations at their real fully-qualified names.
package javax.ws.rs

@Target(AnnotationTarget.CLASS) annotation class ApplicationPath(val value: String = "")
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION) annotation class Path(val value: String = "")
@Target(AnnotationTarget.FUNCTION) annotation class GET
