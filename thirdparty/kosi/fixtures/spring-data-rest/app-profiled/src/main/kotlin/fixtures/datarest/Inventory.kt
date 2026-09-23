// Spring Boot's precedence, not "any disagreement is ambiguous": the plain
// `application.properties` is what a default run serves; a `prod` profile
// file, a same-location YAML file and a TEST resource do not erase it.
// Before, any of them made the key ambiguous and dropped the base path.
//
// kosi:want endpoint framework=spring-mvc path=/a/inventory pathunresolved=none mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/prod/inventory
// kosi:want-not endpoint framework=spring-mvc path=/yaml/inventory
// kosi:want-not endpoint framework=spring-mvc path=/test/inventory
// kosi:want-not endpoint framework=spring-mvc path=/inventory
package fixtures.datarest

import org.springframework.data.rest.webmvc.RepositoryRestController
import org.springframework.web.bind.annotation.GetMapping

@RepositoryRestController
class Inventory {
    @GetMapping("/inventory")
    fun inventory(): String = "i"
}
