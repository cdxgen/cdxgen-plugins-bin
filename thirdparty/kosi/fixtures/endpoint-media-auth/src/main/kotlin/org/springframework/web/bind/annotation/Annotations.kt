// Spring's routing annotations with the media-type arguments, at their
// real FQNs. `consumes`/`produces` are NAMED arguments — the channel
// added to the annotation evidence, because the argument's name is the
// only difference between the two lists.
package org.springframework.web.bind.annotation

@Target(AnnotationTarget.CLASS) annotation class RestController
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class RequestMapping(
    val value: String = "",
    val consumes: Array<String> = [],
    val produces: Array<String> = [],
)
@Target(AnnotationTarget.FUNCTION)
annotation class GetMapping(val value: String = "", val produces: Array<String> = [])
