// A `@get:`-targeted mapping lands on the getter METHOD, and Spring maps
// that getter. A companion-object FUNCTION is not mapped (Spring registers
// no Companion bean), so it must publish nothing.
// kosi:want endpoint framework=spring-mvc path=/status fn=~GetterApi.getStatusText mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/comp mode=resolved
// kosi:want-not diagnostic code=parse-error
package fixtures.getter

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class GetterApi {
    @get:GetMapping("/status")
    val statusText: String get() = "ok"

    companion object {
        @GetMapping("/comp")
        fun comp(): String = "unmapped"
    }
}
