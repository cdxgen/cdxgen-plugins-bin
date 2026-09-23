package fixtures.deploy.mvcservletpath

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class Api {
    @GetMapping("/b")
    fun b(): String = "b"
}
