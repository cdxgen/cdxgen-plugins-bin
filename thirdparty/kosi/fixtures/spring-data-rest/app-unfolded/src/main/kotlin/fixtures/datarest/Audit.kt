// A setter whose argument does not fold (a parameter): the base is unknown,
// and the route says so rather than reading as the root.
//
// kosi:want endpoint framework=spring-mvc path=/audit pathunresolved=~fold mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/audit pathunresolved=none
package fixtures.datarest

import org.springframework.data.rest.core.config.RepositoryRestConfiguration
import org.springframework.data.rest.webmvc.BasePathAwareController
import org.springframework.web.bind.annotation.GetMapping

class Prefixer {
    fun apply(config: RepositoryRestConfiguration, prefix: String) {
        config.setBasePath(prefix)
    }
}

@BasePathAwareController
class Audit {
    @GetMapping("/audit")
    fun audit(): String = "a"
}
