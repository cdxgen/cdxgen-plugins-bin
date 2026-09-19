// Feign's request-line annotation at its real package; the value carries
// method and path together ("GET /users").
package feign

@Target(AnnotationTarget.FUNCTION)
annotation class RequestLine(val value: String)
