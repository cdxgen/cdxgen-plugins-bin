// P27 — the corpus's first fixture that is an APPLICATION rather than a
// feature.
//
// One request crosses, in order: a Spring MVC entry point (the source), a
// Jackson deserialization boundary (the DTO's FIELDS carry the input, P26
// §1.3), a container-bound service seam with an unbound sibling (P25/P26
// §2), a `by`-delegation DECORATOR (P27 §1 — a generated forwarder with no
// PSI), a mapper that moves the value between two objects (P24's object
// identity), a GETTER that returns a field of its receiver (P27 §1), a
// collection hop, and a Spring Data repository interface as the sink (P26
// §1.1).
//
// Every one of those capabilities was proven by a fixture that exercised it
// ALONE. This one makes them compose, which is where P27 found its three
// defects: each appeared only when two layers stacked.
//
// Positive halves:
// kosi:want flow source=untrusted-input sink=sql-query fn=~placeFromBody mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=~placeFromQuery mode=endpoint
// kosi:want flow source=untrusted-input sink=deserialization fn=~placeFromBody mode=endpoint
//
// Negative halves. The sanitized one is the load-bearing negative: it is the
// SAME eleven-frame path with `Pattern.quote` (a real pack sanitizer, not a
// workspace function that merely looks like one) in front of the query.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~placeSanitizedBody
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~healthCheck
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~LoggingOrderService
// kosi:want-not diagnostic code=parse-error
package com.acme.web

import com.acme.dto.OrderRequest
import com.acme.dto.OrderRow
import com.acme.service.OrderService
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/orders")
class OrderController(
    private val service: OrderService,
    private val mapper: ObjectMapper,
) {

    /**
     * The full path: body -> DTO field -> command -> getter -> collection ->
     * derived query. Six frames, three objects, one decorator.
     */
    @PostMapping("/place")
    fun placeFromBody(@RequestBody payload: String): List<OrderRow> {
        val request = mapper.readValue(payload, OrderRequest::class.java)
        return service.place(request)
    }

    /** The same sink reached from a query parameter instead of a body. */
    @PostMapping("/place-param")
    fun placeFromQuery(@RequestParam("name") name: String): List<OrderRow> =
        service.place(OrderRequest(name, "from-param"))

    /** The sanitized path: the same six frames, cleaned before the query. */
    @PostMapping("/place-safe")
    fun placeSanitizedBody(@RequestBody payload: String): List<OrderRow> {
        val request = mapper.readValue(payload, OrderRequest::class.java)
        return service.placeSafely(request)
    }

    /** No untrusted input reaches anything. */
    @GetMapping("/health")
    fun healthCheck(): String = "ok"
}
