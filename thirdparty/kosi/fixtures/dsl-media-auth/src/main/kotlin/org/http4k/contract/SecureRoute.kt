// P16 §4: http4k-contract's SecureRoute — the one per-route auth declaration
// http4k has. P15's pack comment said auth was "a Filter, not a declaration
// attributable to one route"; contract mode disagrees, and the pack now
// carries secureRouteConstructors for exactly this shape: the scheme is the
// construction's first argument, the handler its last.
package org.http4k.contract

class SecureRoute(val security: Any, val handler: (org.http4k.core.Request) -> org.http4k.core.Response)
