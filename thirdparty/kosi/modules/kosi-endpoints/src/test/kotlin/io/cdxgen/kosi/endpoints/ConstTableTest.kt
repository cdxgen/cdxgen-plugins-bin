package io.cdxgen.kosi.endpoints

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Workspace constants the way Kotlin folds them (atom-tools#95 follow-up). */
class ConstTableTest {

    private fun table(vararg files: String) =
        ConstTable.fromSources(files.withIndex().associate { (i, text) -> "f$i.kt" to text })

    @Test
    fun `literals, templates, concatenation and qualified references fold`() {
        val t = table(
            """
            object Paths {
                const val API = "/api"
                const val V2 = "${'$'}API/v2"
                const val USERS = V2 + "/users"
                const val ORDERS = "${'$'}{Paths.V2}/orders"
            }
            object One { const val X = "/x" }
            """.trimIndent(),
        )
        assertEquals("/api/v2", t["V2"])
        assertEquals("/api/v2/users", t["USERS"])
        assertEquals("/api/v2/orders", t["ORDERS"])
        assertEquals("/x", t["One.X"])
    }

    @Test
    fun `an ambiguous bare name is refused but its owners stay exact`() {
        val t = table("object A { const val P = \"/a\" }", "object B { const val P = \"/b\" }")
        assertNull(t["P"])
        assertEquals("/a", t["A.P"])
        assertEquals("/b", t["B.P"])
    }

    @Test
    fun `a literal head of a longer expression is not the value`() {
        val t = table("const val BASE = \"/base\"\nconst val X = \"/a\" + BASE")
        assertEquals("/a/base", t["X"])
    }

    @Test
    fun `an unknown reference never folds`() {
        assertNull(table("const val X = MISSING + \"/x\"")["X"])
    }

    @Test
    fun `a companion constant is owned by its class`() {
        val t = table("class C1 {\n    companion object { const val IN = \"/c\" }\n}")
        assertEquals("/c", t["C1.IN"])
        assertEquals("/c", t["IN"])
    }
}
