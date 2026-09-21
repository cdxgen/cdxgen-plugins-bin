package dev.kosi.helper

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Statement

/**
 * The published-jar helper for `dep-taint-through-lib`: compiled ONCE into
 * `libs/dep-helper.jar` by `helper-src/build.sh` (which drives the Kotlin
 * compiler already on kosi's own build classpath), and COMMITTED so the
 * fixture never executes a build and never touches the network. The
 * workspace calls into this jar; the `--deps` tier lowers these very class
 * files to the KIR and summarises them.
 *
 * The shapes are deliberate:
 *  - `Db.runQuery` / `Db.runUpdate` sink their `sql` parameter THROUGH pack
 *    sinks (`Statement.executeQuery`/`executeUpdate`) that live INSIDE the
 *    jar — the cross-dependency flow exists to find;
 *  - `Db.hashOf` sinks nothing — the clean-method negative;
 *  - `AuditLog.record` is an INTERFACE method and `Provider.provide` an
 *    abstract one — body-less records that must be ignored ENTIRELY, never
 *    summarised as "no flow" (which would invent a sanitiser or launder a
 *    flow);
 *  - `Console.readSetting` is a source INSIDE the jar (it calls
 *    `readLine()`), returned to the caller — the `sourceReturns` arm.
 */
class Db(private val connection: Connection) {

    fun runQuery(sql: String): ResultSet? {
        if (sql.isEmpty()) return null
        val statement: Statement = connection.createStatement()
        return statement.executeQuery(sql)
    }

    fun runUpdate(sql: String): Int {
        val statement = connection.createStatement()
        return statement.executeUpdate(sql)
    }

    fun hashOf(input: String): Int = input.length * 31
}

interface AuditLog {
    fun record(event: String)
}

abstract class Provider {
    abstract fun provide(key: String): String
}

object Console {
    fun readSetting(): String? {
        val line = readLine() ?: return null
        return "setting:$line"
    }
}
