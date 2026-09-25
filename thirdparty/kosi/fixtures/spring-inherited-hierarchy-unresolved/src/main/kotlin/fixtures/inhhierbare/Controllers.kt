// The jar-less twin of spring-inherited-hierarchy (no spring-web on the
// classpath), same wants.
//
// Inherited mappings across a deeper hierarchy (atom-tools#95 review). The
// first fix published a base-class mapping on each inheriting controller,
// but took the class-level path from the DECLARING class rather than the
// nearest one, lost the routes of a controller whose parent overrides the
// member without re-mapping it, read an overload as an override, and
// published an abstract controller's inherited routes. Spring's merged
// annotation search finds the type-level path on the handler type first,
// then its interfaces, then its superclass, recursively.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=spring-mvc path=/mid/deep method=GET fn=~R1.deep mode=resolved
// kosi:want endpoint framework=spring-mvc path=/gc/b method=GET fn=~MidB.g mode=resolved
// kosi:want endpoint framework=spring-mvc path=/impl/api method=GET fn=~AbstractImpl.a mode=resolved
// kosi:want endpoint framework=spring-mvc path=/o/ov/{id} method=GET fn=~OvBase.find mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/x method=GET fn=~Direct.x mode=resolved
// kosi:want endpoint framework=spring-mvc path=/iface/o method=GET fn=~Ordered.o mode=resolved
// kosi:want endpoint framework=spring-mvc path=/own/w method=GET fn=~Owned.w mode=resolved
// kosi:want endpoint framework=spring-mvc path=/p9/b9 method=GET fn=~Base9.b9 mode=resolved
// kosi:want endpoint framework=spring-mvc path=/p10/same-base method=GET mode=resolved
//
// Negative half: never the declaring class's prefix when a nearer one
// exists, never an abstract controller's inherited route, never another
// package's same-named base, never a route without its inherited prefix.
// kosi:want-not endpoint framework=spring-mvc path=/root/deep
// kosi:want-not endpoint framework=spring-mvc path=/deep
// kosi:want-not endpoint framework=spring-mvc path=/p8/b8
// kosi:want-not endpoint framework=spring-mvc path=/p10/same-other
// kosi:want-not endpoint framework=spring-mvc path=/x
// kosi:want-not endpoint framework=spring-mvc path=/o
// kosi:want-not endpoint framework=spring-mvc path=/super/o
// kosi:want-not endpoint framework=spring-mvc path=/iface/w
package fixtures.inhhierbare

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

// The nearest class-level path wins: Mid's, not Root's.
@RequestMapping("/root") abstract class R1 { @GetMapping("/deep") fun deep() = "ok" }
@RequestMapping("/mid") abstract class M1 : R1()
@RestController class L1 : M1()

// An override in an unmarked class in the middle: the controller below it
// inherits the override, and the mapping with it.
abstract class BaseB { @GetMapping("/b") open fun g() = "ok" }
abstract class MidB : BaseB() { override fun g() = "mid" }
@RestController @RequestMapping("/gc") class GC : MidB()

// Interface controller -> abstract implementation -> concrete controller.
interface Api { @GetMapping("/api") fun a(): String }
abstract class AbstractImpl : Api { override fun a() = "x" }
@RestController @RequestMapping("/impl") class Impl : AbstractImpl()

// An overload (same name, same arity, other type) is not an override.
abstract class OvBase { @GetMapping("/ov/{id}") fun find(id: Long) = "ok" }
@RestController @RequestMapping("/o") class OvChild : OvBase() { fun find(name: String) = name }

// A marked but ABSTRACT class is not a component; its unmarked concrete
// subclass is not one either.
abstract class B8 { @GetMapping("/b8") fun m8() = "ok" }
@RestController @RequestMapping("/p8") abstract class M8 : B8()
class L8 : M8()

// A method declared on the controller itself, its class path inherited.
@RequestMapping("/api") abstract class ApiBase
@RestController class Direct : ApiBase() { @GetMapping("/x") fun x() = "ok" }

// Interfaces before the superclass; the controller's own path wins over both.
@RequestMapping("/iface") interface Tagged
@RequestMapping("/super") abstract class SuperBase
@RestController class Ordered : SuperBase(), Tagged { @GetMapping("/o") fun o() = "ok" }
@RestController @RequestMapping("/own") class Owned : SuperBase(), Tagged { @GetMapping("/w") fun w() = "ok" }

// A base in another package, and a same-named base in a third.
@RestController @RequestMapping("/p9") class C9 : fixtures.inhhierbare.base.Base9()
@RestController @RequestMapping("/p10") class C10 : fixtures.inhhierbare.base.Same()
