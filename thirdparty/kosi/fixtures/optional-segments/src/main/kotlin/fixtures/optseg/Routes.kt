// Optional path segments serve two URLs each (ktor.io routing: "{param?}
// an optional path parameter"; Azure Functions routes take ASP.NET-style
// `{id:int?}`), and a Ktor tailcard `{...}` or `{rest...}` matches the rest
// of the path. OpenAPI has no optional path parameter, so each URL is its
// own route.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=ktor path=/user/{login} method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/user method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/files/** method=GET mode=resolved
// kosi:want endpoint framework=ktor path=/assets/** method=GET mode=resolved
// kosi:want endpoint framework=azure-functions path=/api/products/{category}/{id} method=GET mode=resolved
// kosi:want endpoint framework=azure-functions path=/api/products/{category} method=GET mode=resolved
//
// Negative half: no `?` survives into a template; a REQUIRED segment is
// never dropped; the tailcard is never an RFC 6570 label.
// kosi:want-not endpoint framework=ktor path=~?}
// kosi:want-not endpoint framework=azure-functions path=~?}
// kosi:want-not endpoint framework=azure-functions path=/api/products
// kosi:want-not endpoint framework=ktor path=/files
// kosi:want-not endpoint framework=ktor path=~.{
package fixtures.optseg

import com.microsoft.azure.functions.HttpMethod
import com.microsoft.azure.functions.annotation.FunctionName
import com.microsoft.azure.functions.annotation.HttpTrigger
import io.ktor.server.application.Application
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.module() {
    routing {
        get("/user/{login?}") { }
        get("/files/{...}") { }
        get("/assets/{path...}") { }
    }
}

class Functions {
    @FunctionName("products")
    fun products(@HttpTrigger(name = "req", route = "products/{category:alpha}/{id:int?}", methods = [HttpMethod.GET]) req: String): String = req
}
