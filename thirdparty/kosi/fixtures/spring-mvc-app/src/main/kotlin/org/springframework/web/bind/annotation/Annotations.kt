// The framework annotations kosi resolves offline: declared at the real
// package path so type identity, not name similarity, decides the match.
package org.springframework.web.bind.annotation

annotation class RestController
annotation class Controller
annotation class GetMapping(val value: String = "")
annotation class PostMapping(val value: String = "")
annotation class PutMapping(val value: String = "")
annotation class DeleteMapping(val value: String = "")
annotation class RequestMapping(val value: String = "")
