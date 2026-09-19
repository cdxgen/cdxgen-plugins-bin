// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package jakarta.ws.rs.container

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class Suspended(val value: String = "")

interface ResourceContext
