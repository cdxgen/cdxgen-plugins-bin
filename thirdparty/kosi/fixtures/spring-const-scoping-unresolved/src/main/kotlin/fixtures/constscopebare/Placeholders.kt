// Spring property placeholders in mapping paths resolve from the config a
// default run serves (atom-tools#95 review): published as `/${api.base}/..`
// with spring-web typed, and silently dropped (`/x`) without it.
//
// kosi:want endpoint framework=spring-mvc path=/v1/users/x method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/gen/y method=GET pathunresolved=none mode=resolved
//
// Negative half: an unset key with no default is unresolved; the
// placeholder is never a path segment, and never dropped.
// kosi:want endpoint framework=spring-mvc fn=~Unset.z pathunresolved=~no.such.key mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/x
// kosi:want-not endpoint framework=spring-mvc path=/z
package fixtures.constscopebare

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController @RequestMapping("\${api.base}/users")
class FromConfig { @GetMapping("/x") fun x() = "ok" }

@RestController @RequestMapping("\${openapi.missing:}/gen")
class WithDefault { @GetMapping("/y") fun y() = "ok" }

@RestController @RequestMapping("\${no.such.key}")
class Unset { @GetMapping("/z") fun z() = "ok" }
