// Negative half: a DTO carrying a HOMONYM GetMapping declared in the DTO's
// own package. The detector matches the framework's package segments, so
// this must not become an endpoint; neither may the private mapping-SHAPED
// method name below.
// kosi:want-not endpoint framework=spring-mvc path=~/dtos mode=resolved
// kosi:want-not endpoint framework=spring-mvc fn=~internalGetUsers mode=resolved
// kosi:want-not endpoint framework=spring-mvc fn=~EmptyController mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=~/ghost-route mode=resolved
package fixtures.springmvc

import fixtures.springmvc.dto.GetMapping

annotation class Marker

@RestController
class DtoApi {
    @GetMapping("/users/dtos")
    fun dtos(): List<String> = listOf("d1")
}

private fun internalGetUsers(): String = "hidden"

// A mapping-shaped METHOD NAME on a real controller is still not an endpoint
// without a mapping annotation - and a commented-out route stays commented:
// @GetMapping("/ghost-route")
// fun ghostRoute(): String = "nope"
