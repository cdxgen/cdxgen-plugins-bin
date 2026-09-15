// P14 §5: `consumes`, `produces` and `authentication` were `emptyList()`
// on every endpoint kosi had ever emitted, for every framework. All three
// are sitting in annotations the detector already reads — and, for Ktor,
// in the ENCLOSING call. This fixture pins all three mechanisms:
//
//   - NAMED annotation arguments (Spring: consumes=/produces= on
//     @RequestMapping and the composed mappings)
//   - POSITIONAL value arguments (JAX-RS and Micronaut: @Consumes/@Produces)
//   - AUTH annotations on the handler (Spring @PreAuthorize, JSR-250
//     @RolesAllowed, Micronaut @Secured)
//   - AUTH from the enclosing DSL (Ktor `authenticate("basic") { }`)
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// A class-level @RequestMapping(consumes, produces) is the DEFAULT for its
// handlers; a method-level declaration replaces it for its own kind.
// kosi:want endpoint framework=spring-mvc path=/reports mode=resolved consumes=application/json produces=application/xml
// kosi:want-not endpoint framework=spring-mvc path=/reports produces=text/csv
// A method-level produces replaces the class default for its kind.
// kosi:want endpoint framework=spring-mvc path=/audit mode=resolved produces=text/csv
// kosi:want-not endpoint framework=spring-mvc path=/audit produces=application/xml
// kosi:want endpoint framework=spring-mvc path=/audit mode=resolved consumes=application/json
//
// @PreAuthorize travels with its value.
// kosi:want endpoint framework=spring-mvc path=/audit mode=resolved authentication=~PreAuthorize
// kosi:want endpoint framework=spring-mvc path=/audit mode=resolved authentication=~hasRole
// kosi:want-not endpoint framework=spring-mvc path=/reports authentication=~PreAuthorize
//
// JAX-RS: the media types are the annotation's positional values.
// kosi:want endpoint framework=quarkus path=/orders mode=resolved consumes=application/json produces=application/json
// kosi:want endpoint framework=quarkus path=/orders mode=resolved authentication=~RolesAllowed
// kosi:want-not endpoint framework=quarkus path=/orders authentication=~PreAuthorize
//
// Micronaut, same run.
// kosi:want endpoint framework=micronaut path=/items mode=resolved consumes=application/json produces=text/csv
// kosi:want endpoint framework=micronaut path=/items mode=resolved authentication=~Secured
//
// Ktor: the requirement is the ENCLOSING authenticate wrapper, its provider
// named; a sibling route outside the wrapper authenticates nothing.
// kosi:want endpoint framework=ktor path=/secure mode=resolved authentication=authenticate(basic)
// kosi:want endpoint framework=ktor path=/open mode=resolved
// kosi:want-not endpoint framework=ktor path=/open authentication=~authenticate
package fixtures.media

import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.ktor.server.auth.authenticate
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import jakarta.annotation.security.RolesAllowed
import jakarta.ws.rs.Consumes as RsConsumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces as RsProduces
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(consumes = ["application/json"], produces = ["application/xml"])
class ReportingController {
    @RequestMapping("/reports")
    fun reports(): String = ""

    /**
     * A method-level produces replaces the class default for its kind —
     * text/csv here, never the class's application/xml.
     */
    @GetMapping("/audit", produces = ["text/csv"])
    @PreAuthorize("hasRole('AUDITOR')")
    fun audit(): String = ""
}

@Path("/orders")
class OrderResource {
    @GET
    @RsConsumes(["application/json"])
    @RsProduces(["application/json"])
    @RolesAllowed(["admin"])
    fun orders(): String = ""
}

@Controller("/items")
class ItemController {
    @Get
    @Consumes(["application/json"])
    @Produces(["text/csv"])
    @Secured(["inventory"])
    fun items(): String = ""
}

fun ktor(root: Route) {
    root.authenticate("basic") {
        get("/secure") {
        }
    }
    root.get("/open") {
    }
}
