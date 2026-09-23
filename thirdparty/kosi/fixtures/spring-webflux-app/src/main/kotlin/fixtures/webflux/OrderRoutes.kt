// WebFlux's FUNCTIONAL routers, in the real API's shapes. `router { }` and
// `coRouter { }` build different DSL classes; nesting is `"/api".nest { }`
// or `path("/api").nest { }`; `accept(..).nest { }` adds no segment;
// `path(pattern, h)` and `"/x" { }` serve any method.
// kosi:want endpoint framework=spring-webflux path=/orders fn=~orderRoutes mode=resolved method=GET
// kosi:want endpoint framework=spring-webflux path=/api/orders fn=~orderRoutes mode=resolved method=POST
// kosi:want endpoint framework=spring-webflux path=/api/orders/{id} fn=~orderRoutes mode=resolved method=PATCH
// kosi:want endpoint framework=spring-webflux path=/v2/orders/{id} fn=~orderRoutes mode=resolved method=DELETE
// kosi:want endpoint framework=spring-webflux path=/health fn=~orderRoutes mode=resolved anymethod=true
// kosi:want endpoint framework=spring-webflux path=/status fn=~orderRoutes mode=resolved anymethod=true
// kosi:want endpoint framework=spring-webflux path=/co/items fn=~itemRoutes mode=resolved method=GET
// kosi:want endpoint framework=spring-webflux path=/co/json/items fn=~itemRoutes mode=resolved method=PUT
//
// Negative half: a predicate is not a path segment, and nothing in a
// comment is a route.
// kosi:want-not endpoint framework=spring-webflux path=~/APPLICATION_JSON
// kosi:want-not endpoint framework=spring-webflux fn=~AuditHelper mode=resolved
// kosi:want-not endpoint framework=spring-webflux path=~/audit-route mode=resolved
package fixtures.webflux

import org.springframework.web.reactive.function.server.MediaType
import org.springframework.web.reactive.function.server.RequestPredicate
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.router

fun orderRoutes(): Unit = router {
    GET("/orders") { _: ServerRequest -> ServerResponse() }
    "/api".nest {
        POST("/orders") { _: ServerRequest -> ServerResponse() }
        accept(MediaType.APPLICATION_JSON).nest {
            PATCH("/orders/{id}") { _: ServerRequest -> ServerResponse() }
        }
    }
    path("/v2").nest {
        DELETE("/orders/{id}", RequestPredicate()) { _: ServerRequest -> ServerResponse() }
    }
    path("/health") { _: ServerRequest -> ServerResponse() }
    "/status" { _: ServerRequest -> ServerResponse() }
}

fun itemRoutes(): Unit = coRouter {
    "/co".nest {
        GET("/items") { _: ServerRequest -> ServerResponse() }
        accept(MediaType.APPLICATION_JSON).nest {
            "/json".nest {
                PUT("/items") { _: ServerRequest -> ServerResponse() }
            }
        }
    }
}

// A helper whose METHOD is named like a handler and whose route lives only
// in a comment: nothing here is an endpoint.
// GET("/audit-route")
class AuditHelper {
    fun getAuditRoute(): String = "not-a-route"
}
