// Declared at the framework's real package path so the annotations resolve
// offline and the handler is detected by TYPE identity (the P7 rule), not
// by name similarity.
package org.springframework.web.bind.annotation

annotation class RestController
annotation class GetMapping(val value: String = "")
annotation class RequestParam
