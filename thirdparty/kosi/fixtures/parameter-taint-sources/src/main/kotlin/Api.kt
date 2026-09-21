// the taint source is a PARAMETER, not a function.
//
// Until this change an endpoint-rooted slice could say "this handler is
// reachable from untrusted input" and nothing more: every seeded parameter
// of a handler produced the SAME fact (same site, same category), so the
// report could not say WHICH parameter was untrusted, what transport it
// arrived on, or that a second parameter was trusted and contributed
// nothing. The pack's `kind` and `category` per parameter annotation had no
// consumer that changed a verdict — the defect this fixture pins.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Two annotated transports, both tainted, BOTH flowing to sinks: two
// distinct flows now, each naming its parameter and transport. Before §1
// these were one indistinguishable slice shape (per parameter, the same
// fact identity).
// kosi:want flow source=untrusted-input sink=process-exec fn=~fromQuery sourceparam=#0 sourcetransport=query mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~fromHeader sourceparam=#0 sourcetransport=header mode=endpoint
//
// The trusted parameter: one the FRAMEWORK supplies, in the same signature
// as the tainted one, with its own path to the SAME sink. Seeding at
// function granularity reports it; parameter granularity does not.
//
// Corrected later: this used to be an UNANNOTATED parameter of a
// collaborator type, on the premise that "unannotated means injected".
// Spring's own table says the opposite — "if a method argument is not
// matched to any of the earlier values in this table and it is a simple
// type it is resolved as a @RequestParam, otherwise as a @ModelAttribute" —
// so that parameter was a command object, and the want-not below was
// asserting that kosi must MISS it. `Model` is a framework-supplied row of
// that same table, which is what "trusted" actually looks like here.
// kosi:want flow source=untrusted-input sink=process-exec fn=~onlyQueryIsTainted sourceparam=#0 sourcetransport=query mode=endpoint
// kosi:want-not flow source=~ sink=~ fn=~onlyQueryIsTainted count=2 mode=endpoint
package fixtures.parametertaint

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/**
 * A collaborator the CONSTRUCTOR injects — which is how Spring supplies one
 * to a controller. Nothing in a handler signature makes it input.
 */
class Audit(private val tag: String) {
    fun label(): String = tag
}

@RestController
class ParamsApi(private val audit: Audit) {

    @GetMapping("/params/query")
    fun fromQuery(@RequestParam("q") query: String): Process =
        ProcessBuilder(query).start()

    @GetMapping("/params/header")
    fun fromHeader(@RequestHeader("X-Cmd") header: String): Process =
        ProcessBuilder(header).start()

    /**
     * The near-miss the whole phase is about. `q` is the transport the
     * framework named; `view` is a framework-SUPPLIED parameter sitting in
     * the same signature, reaching the same sink through its own path — it
     * must not be reported, and the flow that IS reported must name `#0`
     * and `query`.
     */
    @GetMapping("/params/mixed")
    fun onlyQueryIsTainted(
        @RequestParam("q") query: String,
        view: org.springframework.ui.Model,
    ): Process? {
        if (query.isEmpty()) {
            ProcessBuilder(view.render() + audit.label()).start()
        }
        return ProcessBuilder(query).start()
    }
}
