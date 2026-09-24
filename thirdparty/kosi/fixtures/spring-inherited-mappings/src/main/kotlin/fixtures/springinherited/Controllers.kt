// Mappings a controller INHERITS (atom-tools#95). kosi found a base-class
// or interface-default mapping only when the controller redeclared the
// member: the shared-CRUD base-controller layout published nothing, with
// nothing marking the gap. Spring serves an inherited handler under the
// subclass's own type-level mapping (or, lacking one, the hierarchy's),
// but only on a subclass that is itself a component.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=spring-mvc path=/pa/a-inherited method=GET fn=~BaseA.f mode=resolved
// kosi:want endpoint framework=spring-mvc path=/pb/b-inherited method=GET fn=~ChildB.g mode=resolved
// kosi:want endpoint framework=spring-mvc path=/pc/c-iface method=GET fn=~IfaceC.h mode=resolved
// kosi:want endpoint framework=spring-mvc path=/pd/d-direct method=GET fn=~DirectD.i mode=resolved
// kosi:want endpoint framework=spring-mvc path=/users/{id} method=GET fn=~CrudController.one mode=resolved
// kosi:want endpoint framework=spring-mvc path=/users method=POST fn=~CrudController.create mode=resolved
// kosi:want endpoint framework=spring-mvc path=/orders/{id} method=GET fn=~CrudController.one mode=resolved
// kosi:want endpoint framework=spring-mvc path=/orders method=POST fn=~CrudController.create mode=resolved
// kosi:want endpoint framework=spring-mvc path=/leaf/deep method=GET fn=~Root.deep mode=resolved
// kosi:want endpoint framework=spring-mvc path=/shared/health method=GET fn=~PrefixedBase.health mode=resolved
// kosi:want endpoint framework=quarkus path=/things/{id} method=GET fn=~BaseResource.byId mode=resolved
//
// Negative half: an unmarked base is not itself a controller, and its
// mapping is never published without the subclass's prefix; a subclass
// that is not a component serves nothing; an override is published once,
// at the override; the controller's own prefix wins over the hierarchy's.
// kosi:want-not endpoint framework=spring-mvc path=/a-inherited
// kosi:want-not endpoint framework=spring-mvc path=/c-iface
// kosi:want-not endpoint framework=spring-mvc path=/{id}
// kosi:want-not endpoint framework=spring-mvc path=/deep
// kosi:want-not endpoint framework=spring-mvc fn=~BaseB.g
// kosi:want-not endpoint framework=spring-mvc path=/plain/a-inherited
// kosi:want-not endpoint framework=quarkus path=/{id}
package fixtures.springinherited

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

abstract class BaseA { @GetMapping("/a-inherited") open fun f() = "ok" }
@RestController @RequestMapping("/pa") class ChildA : BaseA()

abstract class BaseB { @GetMapping("/b-inherited") open fun g() = "ok" }
@RestController @RequestMapping("/pb") class ChildB : BaseB() { override fun g() = "ok" }

interface IfaceC { @GetMapping("/c-iface") fun h() = "ok" }
@RestController @RequestMapping("/pc") class ChildC : IfaceC

@RestController @RequestMapping("/pd") class DirectD { @GetMapping("/d-direct") fun i() = "ok" }

// The shared-CRUD layout: one generic base, one controller per resource.
abstract class CrudController<T> {
    @GetMapping("/{id}") fun one(id: String): String = id
    @PostMapping fun create(): String = "created"
}
class User
class Order
@RestController @RequestMapping("/users") class UserController : CrudController<User>()
@RestController @RequestMapping("/orders") class OrderController : CrudController<Order>()

// Two levels down, through an unmarked intermediate.
abstract class Root { @GetMapping("/deep") fun deep() = "ok" }
abstract class Middle : Root()
@RestController @RequestMapping("/leaf") class Leaf : Middle()

// The type-level mapping comes from the hierarchy when the controller
// declares none; an override in the controller is published only there.
@RequestMapping("/shared")
abstract class PrefixedBase {
    @GetMapping("/health") fun health() = "up"
}
@RestController class PrefixedChild : PrefixedBase()

// Not a component: inherits the mapping, serves nothing.
class Plain : BaseA()

// JAX-RS: a resource method inherited from a base class.
abstract class BaseResource {
    @GET @Path("/{id}") fun byId(id: String): String = id
}
@Path("/things") class ThingResource : BaseResource()
