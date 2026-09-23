// atom-tools#92. Every Spring mapping spelling against annotations whose
// `value`/`path` are arrays, as they are in the real spring-web jar: before
// the fix each of these published `pathTemplate ""`, and the verbose
// `@RequestMapping(method = [..])` also published `httpMethod []`.
//
// app-beta declares the SAME canonical classes with a different class
// prefix: a canonical name is not unique across a multi-module build, and a
// handler must take its OWN module's `@RequestMapping`, never a sibling's.
//
// kosi:want endpoint framework=spring-mvc path=/alpha/positional method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha/named-array method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha/path-kw method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha/verbose method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha/multi-a method=PUT mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha/multi-b method=PATCH mode=resolved
// kosi:want endpoint framework=spring-mvc path=/alpha method=GET fn=~Api.root mode=resolved
// kosi:want endpoint framework=spring-mvc path=/health fn=~Health.health count=2 mode=resolved
//
// Negative half. The verbose form serves POST only; a `produces` constant
// is not a path; alpha's routes never appear under beta's prefix and
// vice versa; no route is published with an empty path.
// kosi:want-not endpoint framework=spring-mvc path=/alpha/verbose method=GET
// kosi:want-not endpoint framework=spring-mvc path=/alpha/application/json
// kosi:want-not endpoint framework=spring-mvc path=/beta/positional
// kosi:want-not endpoint framework=spring-mvc path=/alpha/only-beta
// kosi:want-not endpoint framework=spring-mvc path=/alpha/beta/only-beta
// kosi:want-not diagnostic code=parse-error
package fixtures.mappingshapes.web

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/alpha")
class Api {
    @GetMapping("/positional")
    fun positional(): String = "a"

    @GetMapping(value = ["/named-array"])
    fun namedArray(): String = "b"

    @GetMapping(path = ["/path-kw"])
    fun pathKeyword(): String = "c"

    @RequestMapping(value = ["/verbose"], method = [RequestMethod.POST])
    fun verbose(): String = "d"

    @RequestMapping(path = ["/multi-a", "/multi-b"], method = [RequestMethod.PUT, RequestMethod.PATCH])
    fun multi(): String = "e"

    @GetMapping(produces = ["application/json"])
    fun root(): String = "f"
}

@RestController
class Health {
    @GetMapping("/health")
    fun health(): String = "ok"
}
