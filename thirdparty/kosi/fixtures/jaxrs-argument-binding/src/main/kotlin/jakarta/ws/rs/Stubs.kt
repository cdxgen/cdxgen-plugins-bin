// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package jakarta.ws.rs

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class Path(val value: String)

@Target(AnnotationTarget.FUNCTION) annotation class GET

@Target(AnnotationTarget.FUNCTION) annotation class POST
