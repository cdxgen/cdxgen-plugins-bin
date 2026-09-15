// The annotation TYPES the positive half uses, declared at the fully
// qualified names the framework ships them at, so resolution resolves them
// to the framework FQNs and the handlers root matches type-resolved — the
// fixture needs no binary dependency to prove the mechanism.
package org.springframework.web.bind.annotation

annotation class RestController(val value: String = "")

annotation class GetMapping(val value: String = "")
