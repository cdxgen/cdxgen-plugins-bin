package org.http4k.contract

import org.http4k.core.Method

class Route(val path: String, val method: String)

infix fun String.bind(method: Method): Route = Route(this, method.name)
