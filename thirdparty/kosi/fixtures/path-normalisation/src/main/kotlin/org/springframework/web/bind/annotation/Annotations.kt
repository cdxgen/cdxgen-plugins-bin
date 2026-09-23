// The framework's annotations, declared here at their REAL fully-qualified
// names so the fixture needs no Spring jar. Framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package org.springframework.web.bind.annotation

@Target(AnnotationTarget.CLASS) annotation class RestController
@Target(AnnotationTarget.FUNCTION) annotation class GetMapping(vararg val value: String)
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class RequestParam(val value: String = "")
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class PathVariable(val value: String = "")
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class RequestBody
