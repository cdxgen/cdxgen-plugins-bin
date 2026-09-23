// The framework annotations kosi resolves offline: declared at the real
// package path so type identity, not name similarity, decides the match.
// @Controller is NOT here: Spring declares it in org.springframework
// .stereotype (see the sibling stub), and the pack carried the wrong FQN
// until the symbol-kind check caught it.
package org.springframework.web.bind.annotation

annotation class RestController
annotation class GetMapping(vararg val value: String)
annotation class PostMapping(vararg val value: String)
annotation class PutMapping(vararg val value: String)
annotation class DeleteMapping(vararg val value: String)
annotation class RequestMapping(vararg val value: String)
