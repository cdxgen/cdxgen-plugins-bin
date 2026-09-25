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

/**
 * The SCOPED view: a reference resolves the way the compiler scopes it, and
 * never falls back to a same-named constant elsewhere (atom-tools#95
 * review).
 */
class ScopedConstTableTest {

    private fun scope(vararg files: Pair<String, String>) = ConstTable.scoped(files.toMap())

    private val local = "p/Local.kt" to """
        package p
        object Local { const val USERS = "/local-users"; const val IMPORTED = "/local-imported" }
    """.trimIndent()

    @Test
    fun `an owner outside the sources never falls back to a same-named constant`() {
        val s = scope(local, "p/C.kt" to "package p\nimport lib.LibPaths\nclass C")
        assertNull(s.resolve("LibPaths.USERS", "p/C.kt", "p.C.f"))
        assertEquals("/local-users", s.resolve("Local.USERS", "p/C.kt", "p.C.f"))
    }

    @Test
    fun `an explicit import names the library, not the package's constant`() {
        val s = scope(local, "p/C.kt" to "package p\nimport lib.LibPaths.IMPORTED\nclass C")
        assertNull(s.resolve("IMPORTED", "p/C.kt", "p.C.f"))
    }

    @Test
    fun `each class's companion constant is its own`() {
        val s = scope(
            "p/K.kt" to """
                package p
                class K1(val a: String = "x") { companion object { const val OWN = "/k1" } }
                class K2 { companion object { const val OWN = "/k2" } }
            """.trimIndent(),
        )
        assertEquals("/k1", s.resolve("OWN", "p/K.kt", "p.K1.own"))
        assertEquals("/k2", s.resolve("OWN", "p/K.kt", "p.K2.own"))
        assertEquals("/k1", s.resolve("K1.Companion.OWN", "p/K.kt", "p.Other.f"))
        assertNull(s.resolve("OWN", "p/K.kt", "p.Other.f"), "ambiguous outside both classes")
    }

    @Test
    fun `templates and concatenation fold in the reader's scope`() {
        val s = scope(
            "p/Paths.kt" to "package p\nconst val API = \"/api/v2\"\nobject J { const val BASE = \"/jb\" }",
            "q/C.kt" to "package q\nimport p.API\nimport p.J\nclass C",
        )
        assertEquals("/api/v2/monitors", s.evaluate("\"\${API}/monitors\"", "q/C.kt", "q.C"))
        assertEquals("/jb/cat", s.evaluate("J.BASE + \"/cat\"", "q/C.kt", "q.C.f"))
        assertNull(s.evaluate("\"\${LibPaths.X}/x\"", "q/C.kt", "q.C"))
    }

    @Test
    fun `java interface and composed constants fold, and a java dollar is text`() {
        val s = scope(
            "p/JavaPaths.java" to "package p;\npublic interface JavaPaths { String JI = \"/java-iface\"; }",
            "p/JavaPaths2.java" to """
                package p;
                public class JavaPaths2 {
                    public static final String B = "/jbase";
                    public static final String JC = B + "/composed";
                    public static final String DOLLAR = "/price${'$'}x";
                    void m() { String local = "/not-a-field"; }
                }
            """.trimIndent(),
            "p/C.kt" to "package p\nclass C",
        )
        assertEquals("/java-iface", s.resolve("JavaPaths.JI", "p/C.kt", "p.C.f"))
        assertEquals("/jbase/composed", s.resolve("JavaPaths2.JC", "p/C.kt", "p.C.f"))
        assertEquals("/price${'$'}x", s.resolve("JavaPaths2.DOLLAR", "p/C.kt", "p.C.f"))
        assertNull(s.resolve("JavaPaths2.local", "p/C.kt", "p.C.f"), "a method local is not a field")
    }

    @Test
    fun `an ambiguous inner scope does not fall through to an outer one`() {
        val s = scope(
            "p/A.kt" to "package p\nconst val P = \"/top\"\nclass C { companion object { const val P = \"/c\" } }",
            "p/B.kt" to "package p\nclass C { companion object { const val P = \"/other-c\" } }",
        )
        assertNull(s.resolve("P", "p/A.kt", "p.C.f"), "C.P is ambiguous; never the top-level P")
    }

    @Test
    fun `a star import holds it only when exactly one star package does`() {
        val one = scope("a/X.kt" to "package a\nconst val S = \"/a\"", "q/C.kt" to "package q\nimport a.*\nclass C")
        assertEquals("/a", one.resolve("S", "q/C.kt", "q.C"))
        val two = scope(
            "a/X.kt" to "package a\nconst val S = \"/a\"", "b/X.kt" to "package b\nconst val S = \"/b\"",
            "q/C.kt" to "package q\nimport a.*\nimport b.*\nclass C",
        )
        assertNull(two.resolve("S", "q/C.kt", "q.C"))
    }
}
