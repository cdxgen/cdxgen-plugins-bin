// http4k's routed-request path read (http4k.org, nestable routes:
// `"/book/{title}" bind GET to { req -> req.path("title") }` — the segment
// arrives through the ROUTING layer, org.http4k.routing). P28 §2: this
// reader was endpoints evidence but not a taint source.
package org.http4k.routing

import org.http4k.core.Request

fun Request.path(name: String): String? = null
