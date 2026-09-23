// Negative half. The file's OWN package declares a `GetMapping`: Kotlin
// resolves the local declaration before any star import, so this is not
// Spring's annotation and no endpoint exists. Two star packages that BOTH
// model `GET` (jakarta and javax JAX-RS) are ambiguous: nothing is guessed.
//
// kosi:want-not endpoint framework=spring-mvc path=/shadow/items
// kosi:want-not endpoint framework=quarkus path=/ambiguous
package fixtures.noclasspath.shadow

import org.springframework.web.bind.annotation.*
import jakarta.ws.rs.*
import javax.ws.rs.*

annotation class GetMapping(val value: String = "")

@RestController
@RequestMapping("/shadow")
class Shadowed {
    @GetMapping("/items")
    fun items(): String = "x"
}

@Path("/ambiguous")
class Ambiguous {
    @GET
    fun get(): String = "y"
}
