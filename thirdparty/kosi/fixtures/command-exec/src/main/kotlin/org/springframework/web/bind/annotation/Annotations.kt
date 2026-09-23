// Declared at the framework's real package path so the annotations resolve
// offline and the handler is detected by TYPE identity (the rule), not
// by name similarity.
package org.springframework.web.bind.annotation

annotation class RestController
annotation class GetMapping(vararg val value: String)
annotation class RequestParam
