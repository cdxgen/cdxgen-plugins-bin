// A route's URL is not what its annotation says. `@GetMapping("/orders")`
// under `server.servlet.context-path=/api/v2` is served at
// `/api/v2/orders`, and reporting `/orders` is a WRONG url, not a partial
// one — a consumer matching it against traffic or an allowlist gets no hit.
// The value was already in the config table kosi reads; it just was not
// composed in.
//
// kosi:want-not diagnostic code=parse-error
//
// The resolved backend is the one that can see a framework annotation at
// its fully-qualified name, so the positives are scoped to it.
// kosi:want endpoint framework=spring-mvc path=/api/v2/orders mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/v2/orders/recent mode=resolved
// The application-relative path must NOT be what gets reported, on any
// backend.
// kosi:want-not endpoint framework=spring-mvc path=/orders
package fixtures.endpointbasepath

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class OrderApi {
    @GetMapping("/orders")
    fun list(): List<String> = listOf("a", "b")

    @GetMapping("/orders/recent")
    fun recent(): List<String> = listOf("b")
}
