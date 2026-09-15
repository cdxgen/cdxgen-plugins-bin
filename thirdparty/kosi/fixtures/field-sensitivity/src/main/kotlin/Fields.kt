// Negative half FIRST — golem's most valuable single negative test: an
// engine that marks every field of a tainted aggregate tainted passes every
// positive test and buries a real repo in false positives. Here the source
// taints `query` only; the SIBLING field `column` stays clean, and the sink
// that reads `column` must report NOTHING. A field-insensitive engine
// reports this as untrusted-input -> sql-query and fails the corpus; the
// engine-level proof that this annotation has teeth is
// TaintEngineTest.aFieldInsensitiveEngineReportsTheCleanSibling, which runs
// the same shape with access paths collapsed and asserts the slice appears.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~sinkCleanSibling
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the tainted field itself reaches the sink. The marker is
// scoped to the syntax tier, which still has no flow engine (docs/KOSI.md
// defect 1); at the resolved slots the expectation is live.
// kosi:want flow source=untrusted-input sink=sql-query count=1 known-fail=syntax:1
package fixtures.fields

import java.sql.DriverManager

class UserQuery {
    var query: String = ""
    var column: String = "name"
}

private fun connect(): java.sql.Statement {
    val conn = DriverManager.getConnection("jdbc:h2:mem:fields")
    return conn.createStatement()
}

fun sinkTaintedField() {
    val stmt = connect()
    val input = readLine() ?: return
    stmt.executeQuery("SELECT " + input + " FROM t")
}

fun sinkCleanSibling() {
    val req = UserQuery()
    req.query = readLine() ?: return
    val stmt = connect()
    // `query` is tainted; `column` never is. Sinking the clean sibling must
    // stay silent — and sinking the WHOLE OBJECT here would be the defect.
    stmt.executeQuery("SELECT * FROM t ORDER BY " + req.column)
}
