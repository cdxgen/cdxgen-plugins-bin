// Mapping paths held in constants, resolved the way the COMPILER scopes a
// name (atom-tools#95 review). kosi keyed constants by bare name and fell
// back to it: `@GetMapping(LibPaths.USERS)`, from a library the run cannot
// see, published the workspace's unrelated `Local.USERS`; an imported
// `IMPORTED` published `Local.IMPORTED`; a templated class prefix
// (`"${API}/monitors"`, kuvasz's layout) was dropped and every route under
// it published as `/{id}`. A reference resolves through the enclosing
// classes, the file's imports, its package and its star imports, or it is
// unresolved; templates and concatenations fold the same way.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=spring-mvc path=/local-users method=GET fn=~CC.pathArg pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/local-users/m method=POST fn=~CC.verb pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/own-k1 method=GET fn=~K1Controller.own pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/own-k2 method=GET fn=~K2Controller.own pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/java-iface method=GET fn=~CC.javaIface pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/jbase/composed method=GET fn=~CC.javaComposed pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/jb/tpl method=GET fn=~CC.tpl pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/jb/cat method=GET fn=~CC.cat pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/lit method=GET fn=~CC.mixed pathunresolved=none mode=resolved
// kosi:want endpoint framework=micronaut path=/api/v2/monitors/{id} method=GET fn=~Monitors.one pathunresolved=none mode=resolved
// kosi:want endpoint framework=micronaut path=/api/v2/monitors method=GET fn=~Monitors.all pathunresolved=none mode=resolved
// kosi:want endpoint framework=micronaut path=/api/v2/plain/p method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=micronaut path=/api/v2/concat/c method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/api/v2/spring/s method=GET pathunresolved=none mode=resolved
//
// Negative half: a qualified name whose owner is not in the sources, an
// imported name, and a template over either are UNRESOLVED — never the
// same-named workspace constant, never the identifier, never a route with
// its prefix dropped. An enum argument (`method = [RequestMethod.POST]`)
// is not a constant to fold.
// kosi:want endpoint framework=spring-mvc fn=~CC.ext pathunresolved=~LibPaths.USERS mode=resolved
// kosi:want endpoint framework=spring-mvc fn=~CC.imp pathunresolved=~IMPORTED mode=resolved
// kosi:want endpoint framework=spring-mvc fn=~CC.mixed pathunresolved=~LibPaths.X mode=resolved
// kosi:want endpoint framework=micronaut fn=~ExternalPrefix.e pathunresolved=~LibPaths.BASE mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/local-users fn=~CC.ext
// kosi:want-not endpoint framework=spring-mvc path=/local-imported
// kosi:want-not endpoint framework=spring-mvc path=/IMPORTED
// kosi:want-not endpoint framework=spring-mvc path=/LibPaths.USERS
// kosi:want-not endpoint framework=spring-mvc path=/OWN
// kosi:want-not endpoint framework=micronaut path=/{id}
// kosi:want-not endpoint framework=micronaut path=/p
// kosi:want-not endpoint framework=micronaut path=/c
// kosi:want-not endpoint framework=micronaut path=/e
// kosi:want-not endpoint framework=spring-mvc path=/s
package fixtures.constscope

import com.external.lib.LibPaths
import com.external.lib.LibPaths.IMPORTED
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

const val API = "/api/v2"

object Local { const val USERS = "/local-users"; const val IMPORTED = "/local-imported"; const val X = "/local-x" }

object J { const val BASE = "/jb" }

@RestController
class CC {
    @GetMapping(LibPaths.USERS) fun ext() = "ok"
    @GetMapping(IMPORTED) fun imp() = "ok"
    @GetMapping(path = [Local.USERS]) fun pathArg() = "ok"
    @RequestMapping(value = [Local.USERS + "/m"], method = [RequestMethod.POST]) fun verb() = "ok"
    @GetMapping("${J.BASE}/tpl") fun tpl() = "ok"
    @GetMapping(J.BASE + "/cat") fun cat() = "ok"
    @GetMapping(value = [LibPaths.X, "/lit"]) fun mixed() = "ok"
    @GetMapping(JavaPaths.JI) fun javaIface() = "ok"
    @GetMapping(JavaPaths2.JC) fun javaComposed() = "ok"
}

// The same name in two companions: each controller's own, by its class.
@RestController
class K1Controller(val unused: String = "default") {
    companion object { const val OWN = "/own-k1" }
    @GetMapping(OWN) fun own() = "ok"
}

@RestController
class K2Controller {
    companion object { const val OWN = "/own-k2" }
    @GetMapping(OWN) fun own() = "ok"
}

// kuvasz's layout: the class prefix is a template over a constant.
@Controller("${API}/monitors")
class Monitors {
    @Get("/{id}") fun one(id: String) = id
    @Get fun all() = "all"
}

@Controller("$API/plain")
class Plain { @Get("/p") fun p() = "p" }

@Controller(API + "/concat")
class Concat { @Get("/c") fun c() = "c" }

@RestController @RequestMapping("${API}/spring")
class SpringPrefixed { @GetMapping("/s") fun s() = "s" }

@Controller("${LibPaths.BASE}/ext")
class ExternalPrefix { @Get("/e") fun e() = "e" }
