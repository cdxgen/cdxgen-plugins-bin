// Two config files in ONE module disagree about the base path. Neither is
// guessed: the route stays relative and says why.
//
// kosi:want endpoint framework=spring-mvc path=/stock pathunresolved=~disagree mode=resolved
// kosi:want diagnostic code=endpoint-path-unresolved mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/a/stock
// kosi:want-not endpoint framework=spring-mvc path=/b/stock
package fixtures.datarest

import org.springframework.data.rest.webmvc.RepositoryRestController
import org.springframework.web.bind.annotation.GetMapping

@RepositoryRestController
class Stock {
    @GetMapping("/stock")
    fun stock(): String = "s"
}
