// The Jakarta REST annotations a Dropwizard resource is built from: Dropwizard
// resources ARE Jakarta REST resources (Jersey), which is why kosi needs no
// dropwizard framework entry — only the knowledge that @Auth is injected.
package jakarta.ws.rs

@Target(AnnotationTarget.FUNCTION) annotation class GET
@Target(AnnotationTarget.FUNCTION) annotation class POST
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION) annotation class Path(val value: String)
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class QueryParam(val value: String)
