// Spring MVC's annotations at their real package.
package org.springframework.web.bind.annotation

@Target(AnnotationTarget.CLASS) annotation class RestController
@Target(AnnotationTarget.FUNCTION) annotation class GetMapping(val value: String = "")
@Target(AnnotationTarget.FUNCTION) annotation class PostMapping(val value: String = "")
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class RequestParam(val value: String = "")
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class SessionAttribute(val value: String = "")
@Target(AnnotationTarget.VALUE_PARAMETER) annotation class RequestAttribute(val value: String = "")
