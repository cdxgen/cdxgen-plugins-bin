// The SAME route is spelled four ways on the JVM: Spring's `{id:[0-9]+}`,
// JAX-RS's `{id: \d+}`, Vert.x's and Spark's `:id`, Ktor's `{id?}` and
// `{...}`. Reported verbatim, a consumer cannot match two frameworks'
// routes against each other, against traffic, or against an allowlist
// without re-implementing every framework's path syntax.
//
// kosi is the thing that should know this, so it reports ONE normal form:
// `{name}` for a variable, `*` and `**` for wildcards. The regex constraint
// is dropped from the TEMPLATE — it constrains values, not identity — and
// `pathParameters` names the variable either way.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want endpoint framework=spring-mvc path=/items/{id} mode=resolved
// kosi:want endpoint framework=spring-mvc path=/files/** mode=resolved
// kosi:want endpoint framework=spring-mvc path=/tenants/{tenant}/users/{user} mode=resolved
//
// The raw spellings must NOT survive into the report.
// kosi:want-not endpoint framework=spring-mvc path=~{id:
// kosi:want-not endpoint framework=spring-mvc path=~{tenant:
package fixtures.pathnormalisation

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ItemApi {
    /** A regex-constrained variable. */
    @GetMapping("/items/{id:[0-9]+}")
    fun item(): String = "item"

    /** A Spring wildcard tail. */
    @GetMapping("/files/**")
    fun files(): String = "files"

    /** Two variables, one constrained, one not. */
    @GetMapping("/tenants/{tenant:[a-z]+}/users/{user}")
    fun tenantUser(): String = "user"
}
