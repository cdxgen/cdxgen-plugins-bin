// Negative half: a @RestController with NO mapped methods. The class marker
// alone publishes nothing.
// kosi:want-not endpoint framework=spring-mvc fn=~EmptyController mode=resolved
package fixtures.springmvc

import org.springframework.web.bind.annotation.RestController

@RestController
class EmptyController
