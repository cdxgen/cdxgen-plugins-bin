// P20 §1: the taint source is a PARAMETER, not a function.
//
// Until this phase an endpoint-rooted slice could say "this handler is
// reachable from untrusted input" and nothing more: every seeded parameter
// of a handler produced the SAME fact (same site, same category), so the
// report could not say WHICH parameter was untrusted, what transport it
// arrived on, or that a second parameter was trusted and contributed
// nothing. The pack's `kind` and `category` per parameter annotation had no
// consumer that changed a verdict (R128) — the defect this fixture pins.
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
// The trusted parameter: an unannotated collaborator in the SAME signature
// as the tainted one, with its own path to the SAME sink. Seeding at
// function granularity reports it; parameter granularity does not.
// kosi:want flow source=untrusted-input sink=process-exec fn=~onlyQueryIsTainted sourceparam=#0 sourcetransport=query mode=endpoint
// kosi:want-not flow source=~ sink=~ fn=~onlyQueryIsTainted count=2 mode=endpoint
package fixtures.parametertaint

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/** A collaborator a container injects: trusted, and never annotated. */
class Audit(private val tag: String) {
    fun label(): String = tag
}

@RestController
class ParamsApi {

    @GetMapping("/params/query")
    fun fromQuery(@RequestParam("q") query: String): Process =
        ProcessBuilder(query).start()

    @GetMapping("/params/header")
    fun fromHeader(@RequestHeader("X-Cmd") header: String): Process =
        ProcessBuilder(header).start()

    /**
     * The near-miss the whole phase is about. `q` is the transport the
     * framework named; `audit` sits in the same signature and reaches the
     * same sink through its own path — it must not be reported, and the
     * flow that IS reported must name `#0` and `query`.
     */
    @GetMapping("/params/mixed")
    fun onlyQueryIsTainted(@RequestParam("q") query: String, audit: Audit): Process? {
        if (query.isEmpty()) {
            ProcessBuilder(audit.label()).start()
        }
        return ProcessBuilder(query).start()
    }
}
