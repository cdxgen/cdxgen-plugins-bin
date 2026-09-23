// Verbs the pack did not name, measured on docs: Vert.x's patch/head/
// options/trace/connect and route(HttpMethod, path); Spark's and Javalin's
// remaining builders; Micronaut @Head/@Options/@Trace/@CustomHttpMethod;
// the servlet's doTrace. A *WithRegex route names a regex, not a template:
// it is kept, unmounted, with the regex.
//
// kosi:want endpoint framework=vertx path=/v/patch method=PATCH mode=resolved
// kosi:want endpoint framework=vertx path=/v/head method=HEAD mode=resolved
// kosi:want endpoint framework=vertx path=/v/options method=OPTIONS mode=resolved
// kosi:want endpoint framework=vertx path=/v/trace method=TRACE mode=resolved
// kosi:want endpoint framework=vertx path=/v/connect method=CONNECT mode=resolved
// kosi:want endpoint framework=vertx path=/v/routed method=POST mode=resolved
// kosi:want endpoint framework=vertx pathunresolved=~regex method=GET mode=resolved
// kosi:want endpoint framework=sparkjava path=/s/patch method=PATCH mode=resolved
// kosi:want endpoint framework=sparkjava path=/s/head method=HEAD mode=resolved
// kosi:want endpoint framework=sparkjava path=/s/options method=OPTIONS mode=resolved
// kosi:want endpoint framework=sparkjava path=/s/trace method=TRACE mode=resolved
// kosi:want endpoint framework=sparkjava path=/s/connect method=CONNECT mode=resolved
// kosi:want endpoint framework=javalin path=/j/head method=HEAD mode=resolved
// kosi:want endpoint framework=javalin path=/j/options method=OPTIONS mode=resolved
// kosi:want endpoint framework=micronaut path=/m/h method=HEAD mode=resolved
// kosi:want endpoint framework=micronaut path=/m/o method=OPTIONS mode=resolved
// kosi:want endpoint framework=micronaut path=/m/t method=TRACE mode=resolved
// kosi:want endpoint framework=micronaut path=/m/lock method=LOCK mode=resolved
// kosi:want endpoint framework=servlet path=/trace method=TRACE mode=resolved
//
// kosi:want-not endpoint framework=vertx path=~^/
// kosi:want-not endpoint framework=vertx path=/v/routed method=GET
package fixtures.verbs

import io.javalin.Javalin
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.CustomHttpMethod
import io.micronaut.http.annotation.Head
import io.micronaut.http.annotation.Options
import io.micronaut.http.annotation.Trace
import io.vertx.core.http.HttpMethod
import io.vertx.ext.web.Router
import javax.servlet.annotation.WebServlet
import spark.Spark

fun vertx(router: Router) {
    router.patch("/v/patch").handler { }
    router.head("/v/head").handler { }
    router.options("/v/options").handler { }
    router.trace("/v/trace").handler { }
    router.connect("/v/connect").handler { }
    router.route(HttpMethod.POST, "/v/routed").handler { }
    router.getWithRegex("^/v/files/.*").handler { }
}

fun spark() {
    Spark.patch("/s/patch") { _, _ -> "p" }
    Spark.head("/s/head") { _, _ -> "h" }
    Spark.options("/s/options") { _, _ -> "o" }
    Spark.trace("/s/trace") { _, _ -> "t" }
    Spark.connect("/s/connect") { _, _ -> "c" }
}

fun javalin(app: Javalin) {
    app.head("/j/head") { }
    app.options("/j/options") { }
}

@Controller("/m")
class MicronautVerbs {
    @Head("/h") fun h(): String = ""
    @Options("/o") fun o(): String = ""
    @Trace("/t") fun t(): String = ""
    @CustomHttpMethod(method = "LOCK", value = "/lock") fun lock(): String = ""
}

@WebServlet("/trace")
class TraceServlet {
    fun doTrace(request: Any, response: Any) {}
}
