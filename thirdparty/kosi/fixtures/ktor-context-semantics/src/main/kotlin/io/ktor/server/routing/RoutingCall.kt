// ktor 3's handler receiver carries the ROUTE's own path parameters
// separately from the merged map (api.ktor.io, io.ktor.server.routing.
// RoutingCall.pathParameters — "The context of a RoutingHandler that is
// used to handle a RoutingCall").
package io.ktor.server.routing

import io.ktor.http.Parameters

class RoutingCall {
    val pathParameters: Parameters get() = throw UnsupportedOperationException()
}
