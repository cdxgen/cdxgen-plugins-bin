// No base path anywhere in this module: Spring Data REST serves at the
// root. A sibling module's base (/api/data, /v2, /api/query) never leaks in.
//
// kosi:want endpoint framework=spring-mvc path=/couriers method=POST pathunresolved=none mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/api/data/couriers
// kosi:want-not endpoint framework=spring-mvc path=/v2/couriers
// kosi:want-not endpoint framework=spring-mvc path=/api/query/couriers
package fixtures.datarest

import org.springframework.data.rest.webmvc.RepositoryRestController
import org.springframework.web.bind.annotation.PostMapping

@RepositoryRestController
class CourierCommands {
    @PostMapping("/couriers")
    fun create(): String = "c"
}
