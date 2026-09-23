// WebMvc.fn: the servlet stack's own functional router
// (org.springframework.web.servlet.function.RouterFunctionDsl), the same
// builder surface as WebFlux's. None of it was modelled.
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=PUT mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=PATCH mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=DELETE mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=HEAD mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/r method=OPTIONS mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/any anymethod=true mode=resolved
// kosi:want endpoint framework=spring-mvc path=/mvc/also anymethod=true mode=resolved
// kosi:want endpoint framework=spring-mvc path=/p/r2 method=GET mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/p
// kosi:want-not endpoint framework=spring-mvc path=/r
package fixtures.webmvcfn

import org.springframework.web.servlet.function.ServerRequest
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.router

fun routes(): Unit = router {
    "/mvc".nest {
        GET("/r") { _: ServerRequest -> ServerResponse() }
        POST("/r") { _: ServerRequest -> ServerResponse() }
        PUT("/r") { _: ServerRequest -> ServerResponse() }
        PATCH("/r") { _: ServerRequest -> ServerResponse() }
        DELETE("/r") { _: ServerRequest -> ServerResponse() }
        HEAD("/r") { _: ServerRequest -> ServerResponse() }
        OPTIONS("/r") { _: ServerRequest -> ServerResponse() }
        path("/any") { _: ServerRequest -> ServerResponse() }
        "/also" { _: ServerRequest -> ServerResponse() }
    }
    path("/p").nest {
        GET("/r2") { _: ServerRequest -> ServerResponse() }
    }
}
