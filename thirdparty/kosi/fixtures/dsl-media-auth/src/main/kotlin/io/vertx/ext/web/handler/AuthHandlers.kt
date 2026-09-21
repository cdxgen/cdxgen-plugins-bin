// Minimal Vert.x auth-handler surface, shaped as io.vertx:vertx-web:5.1.7
// declares it (class files read from the cached jar):
//
//   io/vertx/ext/web/handler/AuthenticationHandler.class -
//     `interface AuthenticationHandler extends Handler<RoutingContext>` -
//     an auth handler IS a handler, so it attaches through the SAME
//     Route.handler call a real handler does.
//   BasicAuthHandler.create(AuthenticationProvider[, realm]),
//   JWTAuthHandler.create(JWTAuth[, issuer]) - interface statics naming the
//     scheme.
package io.vertx.ext.web.handler

import io.vertx.core.Handler
import io.vertx.ext.auth.authentication.AuthenticationProvider
import io.vertx.ext.web.RoutingContext

interface AuthenticationHandler : Handler<RoutingContext>

// Each handler IMPLEMENTS `handle`, because the real ones do: an auth
// handler runs per request like any other. A stub that leaves the member
// abstract does not typecheck, and a fixture that does not typecheck cannot
// claim the framework's shape (the own rule, applied to the stub).
class BasicAuthHandler private constructor() : AuthenticationHandler {
    override fun handle(event: RoutingContext) {}

    companion object {
        fun create(authProvider: AuthenticationProvider): BasicAuthHandler = BasicAuthHandler()
    }
}

class JWTAuthHandler private constructor() : AuthenticationHandler {
    override fun handle(event: RoutingContext) {}

    companion object {
        fun create(jwtAuth: AuthenticationProvider): JWTAuthHandler = JWTAuthHandler()
    }
}
