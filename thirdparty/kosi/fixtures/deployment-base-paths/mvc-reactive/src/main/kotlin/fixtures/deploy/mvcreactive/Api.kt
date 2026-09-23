package fixtures.deploy.mvcreactive

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class Api {
    @GetMapping("/c")
    fun c(): String = "c"
}
