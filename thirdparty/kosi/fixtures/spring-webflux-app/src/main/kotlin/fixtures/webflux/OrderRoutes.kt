// Positive half: WebFlux's FUNCTIONAL router is WebFlux's own API surface
// (the annotated controller model is shared with MVC, so the router is the
// unambiguous evidence). Nested path() prefixes compose like Ktor's route.
// kosi:want endpoint framework=spring-webflux path=/orders fn=~orderRoutes mode=resolved method=GET
// kosi:want endpoint framework=spring-webflux path=/api/orders fn=~orderRoutes mode=resolved method=GET
// kosi:want endpoint framework=spring-webflux path=/api/orders fn=~orderRoutes mode=resolved method=POST
// kosi:want-not endpoint framework=spring-webflux fn=~AuditHelper mode=resolved
// kosi:want-not endpoint framework=spring-webflux path=~/audit-route mode=resolved
package fixtures.webflux

import org.springframework.web.reactive.function.server.RouterFunctionDsl
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.coRouter

fun orderRoutes(): Unit = coRouter {
    GET("/orders") { _: ServerRequest -> ServerResponse() }
    path("/api") {
        GET("/orders") { _: ServerRequest -> ServerResponse() }
        POST("/orders") { _: ServerRequest -> ServerResponse() }
    }
}

// A helper whose METHOD is named like a handler and whose route lives only
// in a comment: nothing here is an endpoint.
// GET("/audit-route")
class AuditHelper {
    fun getAuditRoute(): String = "not-a-route"
}
