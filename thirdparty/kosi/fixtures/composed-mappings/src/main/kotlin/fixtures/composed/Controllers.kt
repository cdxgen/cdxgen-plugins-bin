// Conventions measured missing: composed annotations (Spring's own
// @GetMapping is one), custom stereotypes, server-side @HttpExchange (Spring
// 6.1), JAX-RS verb designators ("annotated with the @HttpMethod
// annotation"), and Quarkus Reactive Routes.
//
// kosi:want endpoint framework=spring-mvc path=/composed/items method=POST fn=~ComposedApi.create mode=resolved
// kosi:want endpoint framework=spring-mvc path=/stereo/ping method=GET fn=~StereotypeApi.ping mode=resolved
// kosi:want endpoint framework=spring-mvc path=/persons/{id} method=GET fn=~PersonController.getPerson mode=resolved
// kosi:want endpoint framework=spring-mvc path=/persons method=POST fn=~PersonController.addPerson mode=resolved
// kosi:want endpoint framework=quarkus path=/dav/doc method=PROPFIND mode=resolved
// kosi:want endpoint framework=quarkus-reactive-routes path=/rb/hello method=GET mode=resolved
// kosi:want endpoint framework=quarkus-reactive-routes path=/rb/world method=POST mode=resolved
// kosi:want endpoint framework=quarkus-reactive-routes path=/rb/say-hi pathunresolved=~derived mode=resolved
//
// Negative half: an @HttpExchange interface NOTHING serves is an HTTP
// client, not an endpoint; the abstract member is not a second endpoint.
// kosi:want-not endpoint framework=spring-mvc fn=~RemoteClient.fetch
// kosi:want-not endpoint framework=spring-mvc fn=~PersonService.getPerson
package fixtures.composed

import io.quarkus.vertx.web.Route
import io.quarkus.vertx.web.RouteBase
import jakarta.ws.rs.HttpMethod
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.service.annotation.GetExchange
import org.springframework.web.service.annotation.HttpExchange
import org.springframework.web.service.annotation.PostExchange

@RequestMapping(method = [RequestMethod.POST], consumes = ["application/json"])
annotation class PostJson(vararg val value: String = [])

@RestController
annotation class ApiController

@RestController
@RequestMapping("/composed")
class ComposedApi {
    @PostJson("/items")
    fun create(): String = "c"
}

@ApiController
@RequestMapping("/stereo")
class StereotypeApi {
    @GetMapping("/ping")
    fun ping(): String = "p"
}

@HttpExchange("/persons")
interface PersonService {
    @GetExchange("/{id}")
    fun getPerson(@PathVariable id: Long): String

    @PostExchange
    fun addPerson(): String
}

@RestController
class PersonController : PersonService {
    override fun getPerson(id: Long): String = "p$id"
    override fun addPerson(): String = "added"
}

@HttpExchange("https://api.example.com")
interface RemoteClient {
    @GetExchange("/data")
    fun fetch(): String
}

@HttpMethod("PROPFIND")
annotation class PROPFIND

@jakarta.ws.rs.Path("/dav")
class DavResource {
    @PROPFIND
    @jakarta.ws.rs.Path("/doc")
    fun find(): String = "d"
}

@RouteBase(path = "rb")
class ReactiveRoutes {
    @Route(methods = [Route.HttpMethod.GET])
    fun hello(): String = "h"

    @Route(path = "world", methods = [Route.HttpMethod.POST])
    fun world(): String = "w"

    @Route(methods = [Route.HttpMethod.GET])
    fun sayHi(): String = "s"
}
