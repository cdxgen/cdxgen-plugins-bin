// Mapping paths held in constants, spring-web typed (stubs): the resolved
// twin of spring-const-paths-unresolved, same wants.
// (atom-tools#95 follow-up). The annotation does not type, so its argument
// arrives as written, and kosi published the identifier as the path
// (`/IN_COMPANION`, `/Holder.IN_OBJECT`). A reference now folds against the
// analysed sources the way Kotlin folds a `const val`, or it is a path kosi
// cannot prove, reported with pathUnresolved.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=spring-mvc path=/c-in-companion method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/a-top-level method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/b-in-object method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/d-literal method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/v2/users method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/v2/orders method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/v2/items/{id} method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/base/child method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/one method=GET fn=~C1.qualified pathunresolved=none mode=resolved
//
// Negative half: an identifier is never a path; a qualified name picks its
// owner's value, never the other same-named constant's; a constant from a
// library the run cannot see stays unresolved.
// kosi:want endpoint framework=spring-mvc fn=~C1.external pathunresolved=~MISSING mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/IN_COMPANION
// kosi:want-not endpoint framework=spring-mvc path=/TOP_LEVEL
// kosi:want-not endpoint framework=spring-mvc path=/Holder.IN_OBJECT
// kosi:want-not endpoint framework=spring-mvc path=/DUPLICATE
// kosi:want-not endpoint framework=spring-mvc path=/MISSING
// kosi:want-not endpoint framework=spring-mvc path=/ExternalPaths.MISSING
// kosi:want-not endpoint framework=spring-mvc path=/two
package fixtures.springconst

import com.acme.shared.ExternalPaths
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

const val TOP_LEVEL = "/a-top-level"
object Holder { const val IN_OBJECT = "/b-in-object" }

// Composed the ways Kotlin folds at compile time.
object Paths {
    const val API = "/api"
    const val V2 = "$API/v2"
    const val USERS = V2 + "/users"
    const val ORDERS = "${Paths.V2}/orders"
    const val ITEM = "$V2/items/{id}"
    const val BASE = "/base"
}

// The same name, two values: only the owner says which one a use means.
object First { const val DUPLICATE = "/one" }
object Second { const val DUPLICATE = "/two" }

@RestController
class C1 {
    companion object { const val IN_COMPANION = "/c-in-companion" }
    @GetMapping(IN_COMPANION)     fun a() = "ok"
    @GetMapping(TOP_LEVEL)        fun b() = "ok"
    @GetMapping(Holder.IN_OBJECT) fun c() = "ok"
    @GetMapping("/d-literal")     fun d() = "ok"
    @GetMapping(Paths.USERS)      fun users() = "ok"
    @GetMapping(Paths.ORDERS)     fun orders() = "ok"
    @GetMapping(Paths.ITEM)       fun item() = "ok"
    @GetMapping(First.DUPLICATE)  fun qualified() = "ok"
    @GetMapping(ExternalPaths.MISSING) fun external() = "ok"
}

@RestController
@RequestMapping(Paths.BASE)
class Prefixed {
    @GetMapping("/child") fun child() = "ok"
}
