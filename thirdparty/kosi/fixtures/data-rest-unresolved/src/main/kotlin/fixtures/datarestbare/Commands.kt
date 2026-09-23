// @RepositoryRestController with spring-data-rest-webmvc ABSENT from the
// classpath: its meta-annotation @BasePathAwareController cannot be walked,
// so only the import names it. The class is still a controller, and it is
// still served under spring.data.rest.base-path.
//
// kosi:want endpoint framework=spring-mvc path=/api/couriers/{id}/assign method=POST fn=~CourierCommands.assign mode=resolved
// kosi:want endpoint framework=spring-mvc path=/health method=GET fn=~PlainApi.health mode=resolved
//
// Negative half: a plain @RestController is not under the data-rest base,
// the command is not served at the bare root, and an unannotated class is
// not a controller.
// kosi:want-not endpoint framework=spring-mvc path=/api/health
// kosi:want-not endpoint framework=spring-mvc path=/couriers/{id}/assign
// kosi:want-not endpoint framework=spring-mvc fn=~NotAController.hidden
// kosi:want-not diagnostic code=parse-error
package fixtures.datarestbare

import org.springframework.data.rest.webmvc.RepositoryRestController
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RepositoryRestController
class CourierCommands {
    @PostMapping("/couriers/{id}/assign")
    fun assign(@PathVariable id: Long): String = "assigned $id"
}

@RestController
class PlainApi {
    @GetMapping("/health")
    fun health(): String = "ok"
}

class NotAController {
    @GetMapping("/hidden")
    fun hidden(): String = "h"
}
