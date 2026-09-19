// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package jakarta.ws.rs.core

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class Context(val value: String = "")

interface Application

interface Configuration

interface HttpHeaders

interface Request

interface SecurityContext

interface UriInfo
