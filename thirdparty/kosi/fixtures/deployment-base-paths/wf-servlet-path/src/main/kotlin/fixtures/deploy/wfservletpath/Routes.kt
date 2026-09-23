package fixtures.deploy.wfservletpath

import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.router

fun routes(): Unit = router {
    GET("/fn") { _: ServerRequest -> ServerResponse() }
}
