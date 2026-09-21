// Framework SEMANTICS, not framework syntax: which parameters of a handler
// carry attacker input.
//
// `--endpoint-sources` used to seed EVERY value parameter of a detected
// handler, because the KIR carried no parameter annotations. A Spring
// controller method takes its injected collaborator in the same signature
// as the query string, so the injected one was tainted too — and a report
// could not say whether a finding arrived through the path, the query or
// the body. The framework registry now states this per annotation, and only
// annotated parameters are seeded when the framework said something.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The positives: the annotated parameters ARE sources, in three transports.
// kosi:want flow source=untrusted-input sink=process-exec fn=~searchByQuery mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~fetchByPath mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~submitBody mode=endpoint
//
// The near-miss that only parameter semantics can get right: the SAME
// handler shape, the same sink, but the value comes from the INJECTED
// collaborator, which no annotation marks. Seeding every parameter reports
// this; seeding what the framework named does not.
// Corrected. The near-miss below used to be an UNANNOTATED
// handler parameter of a collaborator type, on the premise that "unannotated
// means injected". Spring MVC does not do that: it never injects arbitrary
// beans into handler parameters, it BINDS them, and a collaborator arrives
// through the CONSTRUCTOR — which is how Spring's own petclinic is written.
// The fixture was asserting a behaviour the framework does not have, and the
// rule it locked in cost eight of spring-petclinic's eleven real flows.
//
// The near-misses that are real, and what each one rules out:
// kosi:want-not flow source=~ sink=~ fn=~constructorInjectedIsNotInput
// kosi:want-not flow source=~ sink=~ fn=~contextParameterIsNotInput
// kosi:want-not flow source=~ sink=~ fn=~authenticationPrincipalIsNotInput
//
// And the positive the correction ADDS: a command object, validated, with
// its data on its FIELDS.
// kosi:want flow source=untrusted-input sink=process-exec fn=~commandObjectIsInput mode=endpoint
package fixtures.endpointparams

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

/** A collaborator the CONSTRUCTOR injects: trusted. */
class Catalog(private val root: String) {
    fun defaultCommand(): String = root
}

/** A command object: Spring binds this from the form, field by field. */
class SearchForm {
    var term: String = ""
    var page: Int = 0
}

@RestController
class SearchApi(private val catalog: Catalog) {

    @GetMapping("/search")
    fun searchByQuery(@RequestParam("q") query: String): Process =
        ProcessBuilder(query).start()

    @GetMapping("/items/{id}")
    fun fetchByPath(@PathVariable("id") id: String): Process =
        ProcessBuilder(id).start()

    @GetMapping("/submit")
    fun submitBody(@RequestBody payload: String): Process =
        ProcessBuilder(payload).start()

    /**
     * The near-miss, spelled the way Spring actually supplies a
     * collaborator: through the CONSTRUCTOR. Nothing in the handler's
     * signature is attacker input, so the command must not be reported.
     */
    @GetMapping("/catalog")
    fun constructorInjectedIsNotInput(): Process =
        ProcessBuilder(catalog.defaultCommand()).start()

    /**
     * The second near-miss: a parameter the FRAMEWORK hands the handler.
     * `Model` is in spring-mvc's `contextParameterTypes`, so it is not
     * bound from the request — a rule that seeded every unannotated
     * parameter would report this.
     */
    @GetMapping("/model")
    fun contextParameterIsNotInput(model: org.springframework.ui.Model): Process =
        ProcessBuilder(model.toString()).start()

    /**
     * The third: an annotation that says the framework SUPPLIES the value.
     * `@AuthenticationPrincipal` is in `nonInputAnnotations`; the principal
     * is authenticated, not submitted.
     */
    @GetMapping("/me")
    fun authenticationPrincipalIsNotInput(
        @org.springframework.security.core.annotation.AuthenticationPrincipal user: String,
    ): Process = ProcessBuilder(user).start()

    /**
     * The positive the old premise hid: an unannotated, non-context
     * parameter IS the submitted form, and `@Valid` beside it asks for
     * validation, not injection. The data is on the object's FIELDS —
     * `form.term`, never `form` — which is why the seed is field-bearing.
     */
    @PostMapping("/search")
    fun commandObjectIsInput(@jakarta.validation.Valid form: SearchForm): Process =
        ProcessBuilder(form.term).start()
}
