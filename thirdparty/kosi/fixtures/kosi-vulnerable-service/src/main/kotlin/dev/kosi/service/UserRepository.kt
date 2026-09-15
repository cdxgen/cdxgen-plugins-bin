// The vuln-tier fixture's workspace-side half: the same service's JDBC
// repository. The flows here stay INSIDE the workspace (the sinks are
// java.sql calls the service makes itself), which is exactly the contrast
// the tier needs: a slice the plain `resolved` slot already finds and the
// `deps` slot must not change (rusi's rule — enabling the tier never
// changes workspace-only findings), next to AuditService's flow that only
// the `deps` slot can see.
//
// The DriverManager connection doubles as the service's outbound
// `services[]` evidence (the endpoints pack models it as a JDBC client).
//
// kosi:want-not flow source=untrusted-input sink=~ fn=~countUsers known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~findUser known-fail=syntax:1
// kosi:want service name=~jdbc:h2:mem/auditdb resolution=literal mode=resolved
package dev.kosi.service

import java.sql.Connection
import java.sql.DriverManager

/**
 * Reads users by name. The queries are concatenated strings — the service
 * is deliberately vulnerable, which is what makes it an honest population
 * for the cross-dependency gate.
 */
class UserRepository(private val connection: Connection) {

    fun findUser(): String? {
        val name = readLine() ?: ""
        val statement = connection.createStatement()
        statement.executeQuery("SELECT * FROM users WHERE name = '$name'")
        return name
    }

    /** The clean sibling: a fixed aggregate query, no concatenation. */
    fun countUsers(): Int {
        val statement = connection.createStatement()
        val rs = statement.executeQuery("SELECT count(*) FROM users")
        rs.close()
        return 1
    }

    companion object {
        /** The service's one outbound dependency, stated as a literal. */
        fun connect(): UserRepository =
            UserRepository(DriverManager.getConnection("jdbc:h2:mem/auditdb"))
    }
}
