// The sample's persistence layer: a workspace-side SQL flow (the sink call
// stays in this repository), clean-sibling negative, crypto material and an
// outbound services[] row.
package com.example.audit

import java.sql.Connection
import java.sql.DriverManager
import javax.crypto.spec.PBEKeySpec

/**
 * Reads users by name. Deliberately vulnerable: the query is concatenated
 * so the resolved tier reports a sql-query slice with a full callstack.
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

    /** Crypto material: a PBKDF2 key derivation over a hardcoded secret —
        the literal named `secret` births a material fact, so the derivation
        reports as a crypto-flow slice. */
    fun tokenFor(user: String): ByteArray {
        val secret = "hunter2-sample"
        val spec = PBEKeySpec(secret.toCharArray(), "kosi-sample".toByteArray(), 12_345, 128)
        spec.clearPassword()
        return user.toByteArray()
    }

    companion object {
        /**
         * The service's outbound dependency, stated as a literal: this is
         * the services[] row the end-to-end gate asserts.
         */
        fun connect(): UserRepository =
            UserRepository(DriverManager.getConnection("jdbc:h2:mem/auditdb"))
    }
}
