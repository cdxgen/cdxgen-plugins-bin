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
// kosi:want-not flow source=~ sink=~ fn=~injectedCollaboratorIsNotInput
package fixtures.endpointparams

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/** A collaborator a container injects: trusted, and never annotated. */
class Catalog(private val root: String) {
    fun defaultCommand(): String = root
}

@RestController
class SearchApi {

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
     * The near-miss. `catalog` is a dependency, not a transport: nothing
     * the framework names makes it attacker input, so the command it
     * produces must not be reported.
     */
    @GetMapping("/catalog")
    fun injectedCollaboratorIsNotInput(catalog: Catalog): Process =
        ProcessBuilder(catalog.defaultCommand()).start()
}
