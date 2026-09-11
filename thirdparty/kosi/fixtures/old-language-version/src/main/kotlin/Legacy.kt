// Negative half: UserRepo.save is a near-miss of the annotated findUser the
// file does contain; an engine that invents flow through same-class names
// would trip it. The flow is parameter-shaped as of P7: the handler's id
// parameter is the untrusted input (endpoint sources), so the readLine()
// P4 patched in is gone, and the expectation lives on the endpoint slot.
// It must evaluate identically at every clamped language version, which is
// what FlowFoundAcrossLanguageVersionRange asserts per version; the syntax
// tier still has no flow engine (docs/KOSI.md defect 1).
// kosi:want-not declaration name=save kind=method
// kosi:want-not usage name=~prepareStatement
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the clamp diagnostic plus the same facts the file would
// yield at any accepted language version.
// kosi:want diagnostic code=kotlin-language-version
// kosi:want declaration name=findUser kind=method
// kosi:want declaration name=UserRepo kind=class
// kosi:want usage name=~executeQuery
// kosi:want endpoint framework=spring-mvc path=/legacy/user fn=~UserRepo.findUser mode=resolved
// kosi:want flow source=untrusted-input sink=sql-query mode=endpoint
package fixtures.legacy

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.sql.DriverManager

@RestController
class UserRepo {
    @GetMapping("/legacy/user")
    fun findUser(@RequestParam id: String): String? {
        val conn = DriverManager.getConnection("jdbc:h2:mem:legacy")
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT name FROM users WHERE id = '$id'")
        return if (rs.next()) rs.getString(1) else null
    }
}
// `save` is deliberately absent: it is the near-miss of findUser that a
// flow engine matching same-class method names would invent.
