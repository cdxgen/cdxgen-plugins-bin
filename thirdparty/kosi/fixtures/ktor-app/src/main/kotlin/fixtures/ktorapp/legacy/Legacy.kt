// Negative half: a homonym `get` in a different package resolves HERE, and
// the suffix-segment rule must refuse it: its fqn does not end in the
// framework's package segments.
// kosi:want-not endpoint framework=ktor path=~/legacy-report mode=resolved
package fixtures.ktorapp.legacy

class Route

fun Route.get(path: String, body: Route.() -> Unit): Unit = Unit

fun registerLegacy(): Route {
    val route = Route()
    route.get("/legacy-report") { }
    return route
}
