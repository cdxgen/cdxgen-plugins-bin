package fixtures.noclasspath

import org.springframework.web.bind.annotation.*
import java.util.*

@RestController
@RequestMapping("/star")
class StarApi {
    @DeleteMapping("/items/{id}")
    fun remove(@PathVariable("id") id: String): String = id
}
