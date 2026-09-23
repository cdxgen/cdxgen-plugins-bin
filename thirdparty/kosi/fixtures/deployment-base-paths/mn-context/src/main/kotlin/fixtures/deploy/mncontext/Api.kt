package fixtures.deploy.mncontext

import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get

@Controller("/m")
class Api {
    @Get("/x")
    fun x(): String = "x"
}

// Not a @Controller: Micronaut routes nothing here.
class NotAController {
    @Get("/nope")
    fun nope(): String = "n"
}
