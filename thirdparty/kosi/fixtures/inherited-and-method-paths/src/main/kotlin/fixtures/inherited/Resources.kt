// Two conventions no fixture carried, both measured wrong on real code:
//
// 1. JAX-RS spells a method's path on its OWN @Path beside the verb, and
//    the spec concatenates it with the class's. Every method-level @Path
//    was dropped: each resource method published at its class path.
// 2. A mapping declared on an INTERFACE (JAX-RS; Spring's interface
//    controllers, the OpenAPI-generator shape) belongs to the implementing
//    method, which declares no mapping of its own.
//
// kosi:want endpoint framework=quarkus path=/items/{id} method=GET fn=~ItemResource.one pathparam=id mode=resolved
// kosi:want endpoint framework=quarkus path=/items method=HEAD fn=~ItemResource.probe mode=resolved
// kosi:want endpoint framework=quarkus path=/items method=OPTIONS fn=~ItemResource.options mode=resolved
// kosi:want endpoint framework=quarkus path=/users/{id} method=GET fn=~UserResourceImpl.user mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/orders method=POST fn=~OrdersController.create mode=resolved
//
// Negative half: a method-level path is never flattened onto its class
// path, and the interface's abstract member is not a second endpoint.
// kosi:want-not endpoint framework=quarkus path=/items method=GET fn=~ItemResource.one
// kosi:want-not endpoint framework=quarkus fn=~UserApi.user
// kosi:want-not endpoint framework=spring-mvc fn=~OrdersApi.create
// kosi:want-not diagnostic code=parse-error
package fixtures.inherited

import jakarta.ws.rs.GET
import jakarta.ws.rs.HEAD
import jakarta.ws.rs.OPTIONS
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Path("/items")
class ItemResource {
    @GET
    @Path("/{id: [0-9]+}")
    fun one(@PathParam("id") id: String): String = id

    @HEAD
    fun probe(): String = ""

    @OPTIONS
    fun options(): String = ""
}

@Path("/users")
interface UserApi {
    @GET
    @Path("/{id}")
    fun user(@PathParam("id") id: String): String
}

class UserResourceImpl : UserApi {
    override fun user(id: String): String = id
}

@RequestMapping("/api")
interface OrdersApi {
    @PostMapping("/orders")
    fun create(): String
}

@RestController
class OrdersController : OrdersApi {
    override fun create(): String = "created"
}
