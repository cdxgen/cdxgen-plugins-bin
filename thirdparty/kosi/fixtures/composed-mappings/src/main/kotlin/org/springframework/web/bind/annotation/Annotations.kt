// Faithful to spring-web's declared SHAPES, not just its names: `value` and
// `path` are `String[]` in Java (a vararg `value` from Kotlin), `method` is
// a `RequestMethod[]`. Stubs that declared `value: String` hid atom-tools#92
// for thirty phases — against the real jar every path is an array constant.
package org.springframework.web.bind.annotation

enum class RequestMethod { GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE }

annotation class RestController(val value: String = "")

annotation class RequestMapping(
    vararg val value: String = [],
    val path: Array<String> = [],
    val method: Array<RequestMethod> = [],
    val consumes: Array<String> = [],
    val produces: Array<String> = [],
)

annotation class GetMapping(
    vararg val value: String = [],
    val path: Array<String> = [],
    val consumes: Array<String> = [],
    val produces: Array<String> = [],
)

annotation class PostMapping(
    vararg val value: String = [],
    val path: Array<String> = [],
    val consumes: Array<String> = [],
    val produces: Array<String> = [],
)

annotation class PathVariable(val value: String = "", val name: String = "", val required: Boolean = true)
