package com.acme.infra

object Escaping {
    /**
     * A REAL pack sanitizer (`java.util.regex.Pattern.quote` clears
     * `sql-query`), not a workspace function that merely looks like one.
     *
     * The first version of this fixture used a hand-written `escapeSql`, and
     * the want-not below it passed — because the flow it was meant to stop
     * was not arriving at all for an unrelated reason. A negative that holds
     * while the positive beside it is broken is not evidence (R63); it was
     * the engine's silence, borrowed.
     */
    fun escapeSql(raw: String): String = java.util.regex.Pattern.quote(raw)
}
