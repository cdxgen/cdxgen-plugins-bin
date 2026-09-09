// Negative half: UserRepo.save is a near-miss of the annotated findUser the
// file does contain; an engine that invents flow through same-class names
// would trip it. The flow expectation itself is known-fail=1: no flow engine
// exists at the resolved front end tier yet (docs/KOSI.md defect 1) — and it
// must evaluate identically at the clamped version, which is what
// FlowFoundAcrossLanguageVersionRange asserts per language version.
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
// kosi:want flow source=untrusted-input sink=sql-query known-fail=1
package fixtures.legacy

import java.sql.DriverManager

class UserRepo {
    fun findUser(id: String): String? {
        val conn = DriverManager.getConnection("jdbc:h2:mem:legacy")
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT name FROM users WHERE id = '$id'")
        return if (rs.next()) rs.getString(1) else null
    }

}
// `save` is deliberately absent: it is the near-miss of findUser that a
// flow engine matching same-class method names would invent.
