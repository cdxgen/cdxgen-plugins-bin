// The sibling module of app-alpha: same canonical names, its own prefix.
// Its expectations live in app-alpha/…/Api.kt with the rest of the fixture.
//
// kosi:want endpoint framework=spring-mvc path=/beta/only-beta method=GET mode=resolved
package fixtures.mappingshapes.web

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = ["/beta"])
class Api {
    @GetMapping("/only-beta")
    fun onlyBeta(): String = "g"
}

@RestController
class Health {
    @GetMapping("/health")
    fun health(): String = "ok"
}
