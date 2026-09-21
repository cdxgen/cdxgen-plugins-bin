// The sample's inbound route: one endpoint, a real verb and a
// handler, so the e2e's inbound-route assertions run over a non-empty list
// and the OpenAPI-naming convergence the cdxgen join exists for is GATED:
// the kosi row must arrive as `service-users-get`, the name cdxgen's own
// OpenAPI detector would give the same route — not a duplicate beside it.
package com.example.audit

import io.ktor.server.routing.Route
import io.ktor.server.routing.get


fun buildRouter(): Route {
    val audit = AuditService()
    val route = Route()
    route.get("/users") {
        audit.audit("list users")
    }
    return route
}
