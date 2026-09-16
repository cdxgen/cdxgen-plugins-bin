// Minimal http4k CONTRACT DSL surface, shaped exactly as the pinned corpus
// clone declares it (github.com/http4k/http4k at b051f89d, release 6.59.0.0):
//
//   ContractBuilder.security (extensions.kt:33) - the block-wide requirement
//   RouteMetaDsl.security (routeMeta.kt:52) -> RouteMeta.security (:228) -
//     the per-route requirement, attached with String.meta (extensions.kt:63)
//   String.bindContract (extensions.kt:61) - `"/x" meta {} bindContract GET to h`
//
// Runtime precedence is the matcher's own elvis (ContractRouteMatcher.kt:121):
// `it.meta.security?.filter ?: security?.filter ?: Filter.NoOp` - a route's
// meta overrides the block, and neither present means no requirement.
package org.http4k.contract

import org.http4k.core.Method
import org.http4k.security.Security

class RouteMeta(val security: Security? = null)

class RouteMetaDsl {
    var security: Security? = null
}

class ContractRouteSpec0(val path: String, val meta: RouteMeta)

class ContractBuilder {
    var security: Security? = null
    val routes = mutableListOf<Pair<ContractRouteSpec0, (org.http4k.core.Request) -> org.http4k.core.Response>>()
}

fun contract(fn: ContractBuilder.() -> Unit): ContractBuilder = ContractBuilder().apply(fn)

infix fun String.meta(new: RouteMetaDsl.() -> Unit): ContractRouteSpec0 =
    ContractRouteSpec0(this, RouteMeta(RouteMetaDsl().apply(new).security))

infix fun ContractRouteSpec0.bindContract(method: Method): ContractRouteSpec0 = this

// The spelling `"/outside" bindContract GET to handler` — a contract route
// declared with NO meta and outside any contract block. Real http4k declares
// this overload on String (extensions.kt:61); without it the fixture's
// honest-empty negative would rest on a receiver that does not resolve.
infix fun String.bindContract(method: Method): ContractRouteSpec0 =
    ContractRouteSpec0(this, RouteMeta())
