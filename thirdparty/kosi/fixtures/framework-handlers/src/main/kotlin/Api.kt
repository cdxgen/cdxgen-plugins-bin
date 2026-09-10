// Positive half: framework registration roots. UserApi carries the resolved
// framework annotations, so its handlers are roots and reached under
// `--roots exported` even though nothing else calls them.
// kosi:want reachable symbol=~UserApi.users mode=exported
// kosi:want reachable symbol=~UserApi.me mode=exported
// kosi:want-not diagnostic code=parse-error
package fixtures.api

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class UserApi {
    @GetMapping("/users")
    fun users(): List<String> = listOf("ada", "grace")

    @GetMapping("/users/me")
    fun me(): String = "self"
}
