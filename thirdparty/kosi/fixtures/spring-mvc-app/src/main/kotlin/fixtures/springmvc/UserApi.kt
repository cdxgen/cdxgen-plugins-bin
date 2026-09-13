// Positive half: the annotation endpoints, including a class-level path
// prefix. Negative half at the bottom of this file and in Dto.kt.
// kosi:want endpoint framework=spring-mvc path=/admin/users fn=~UserApi.users method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/admin/users/me fn=~UserApi.me method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/admin/users fn=~UserApi.createUser method=POST mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/users/me mode=resolved
package fixtures.springmvc

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/admin")
class UserApi {
    @GetMapping("/users")
    fun users(): List<String> = listOf("ada", "grace")

    @GetMapping("/users/me")
    fun me(): String = "self"

    @PostMapping("/users")
    fun createUser(name: String): String = name
}
