// NO framework jar and NO stub: every annotation here is unresolved, the
// way a default offline run sees a Spring app whose starters are
// version-less (spring-web never arrives). kosi found ZERO endpoints on
// every Spring, Quarkus and Micronaut repo of the corpus in that state.
// The file's explicit import names the FQN — Kotlin's own rule — and a
// star import may resolve a name only to an FQN the endpoints pack models,
// only when exactly one star package yields one.
//
// kosi:want endpoint framework=spring-mvc path=/explicit/items method=GET fn=~ExplicitApi.items mode=resolved
// kosi:want endpoint framework=spring-mvc path=/star/items/{id} method=DELETE pathparam=id fn=~StarApi.remove mode=resolved
// kosi:want diagnostic code=annotation-import-resolved mode=resolved
package fixtures.noclasspath

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/explicit")
class ExplicitApi {
    @GetMapping("/items")
    fun items(): List<String> = emptyList()
}
