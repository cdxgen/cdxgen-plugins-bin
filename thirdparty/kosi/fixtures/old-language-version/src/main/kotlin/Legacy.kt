// Negative half: UserRepo.save is a near-miss of the annotated findUser the
// file does contain; an engine that invents flow through same-class names
// would trip it. The flow reads untrusted input through the shipped pack
// source (kotlin.io.readLine) and concatenates it into the query. It became
// real at the resolved tier in P4 and must evaluate identically at every
// clamped language version, which is what
// FlowFoundAcrossLanguageVersionRange asserts per language version; the
// marker stays scoped to the syntax tier, which still has no flow engine
// (docs/KOSI.md defect 1).
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
// kosi:want flow source=untrusted-input sink=sql-query known-fail=syntax:1
package fixtures.legacy

import java.sql.DriverManager

class UserRepo {
    fun findUser(): String? {
        val id = readLine() ?: return null
        val conn = DriverManager.getConnection("jdbc:h2:mem:legacy")
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT name FROM users WHERE id = '$id'")
        return if (rs.next()) rs.getString(1) else null
    }

}
// `save` is deliberately absent: it is the near-miss of findUser that a
// flow engine matching same-class method names would invent.
