// a route whose framework cannot be evidenced SAYS SO.
//
// the production failure: a Ktor 1.x app's `route(...)` calls fell
// through to name-only attribution and were reported as Vert.x. The fix
// then preferred a framework whose package is demonstrably present; this
// fixture pins the remaining half — when NO framework's package is
// present anywhere in the module, the route is published under the
// reserved pseudo-framework `unattributed` with no verb list, and is never
// handed to whichever framework happens to own a `get`.
//
// Nothing in this file resolves to a framework: `get` and `post` are
// undeclared (they lower as dynamic calls that keep only their names), and
// the only resolved callees are this workspace's own functions.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The route SHAPE is real, so the routes are published — under
// `unattributed`, with no method (a verb would name a framework's verb
// builder, which is exactly the claim that cannot be made).
// kosi:want endpoint framework=unattributed path=/legacy mode=resolved
// kosi:want endpoint framework=unattributed path=/api/data mode=resolved
//
// The wrong answers a name-only matcher used to give: this module names
// none of these frameworks, so none of them may claim its routes.
// kosi:want-not endpoint framework=ktor path=/legacy
// kosi:want-not endpoint framework=vertx path=/legacy
// kosi:want-not endpoint framework=javalin path=/legacy
// kosi:want-not endpoint framework=sparkjava path=/legacy
// kosi:want-not endpoint framework=spring-webflux path=/legacy
package fixtures.unattributed

fun routes(report: (String) -> Unit) {
    get("/legacy") {
        report(readTarget())
    }
    post("/api/data") {
        report(readTarget())
    }
}

fun readTarget(): String = "constant"
