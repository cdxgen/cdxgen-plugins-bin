package io.cdxgen.kosi.flow

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The summary engine's path bounding (atom-tools#95). Opt-in or size
 * triggered only, because a widened path can miss an exact deeper reader;
 * these pin what each rule does to a path, not when it runs.
 */
class SummaryPathsTest {

    @Test
    fun `a repeated segment ends the path at star`() {
        assertEquals("buffer.*", collapseCycle("buffer.buffer.x"))
        assertEquals("next.value.*", collapseCycle("next.value.next.value"))
        assertEquals("a.b.c", collapseCycle("a.b.c"))
        assertEquals("single", collapseCycle("single"))
    }

    @Test
    fun `nothing extends a star`() {
        assertEquals("a.*", collapseCycle("a.*.b.*"))
        assertEquals("a.*", collapseCycle("a.*"))
    }

    @Test
    fun `exact joins never collapse`() {
        assertEquals("inner.inner.raw", joinPath("inner.inner", "raw"))
        assertEquals("inner.*", joinPath("inner", "inner.raw", collapseCycles = true))
    }

    @Test
    fun `a star path subsumes its extensions and nothing else`() {
        val set = java.util.TreeSet(
            listOf("p.*", "p.x", "p.x.*", "q.y", "").map { SummaryFact(0, null, "c", it) },
        )
        SummaryPaths.normalize(set)
        assertEquals(setOf("", "p.*", "q.y"), set.mapTo(HashSet()) { it.path })
    }

    @Test
    fun `groups past the budget widen and are counted`() {
        val paths = (0 until SummaryPaths.WIDEN_AT + 10).map { "f$it.g" }
        val set = java.util.TreeSet(paths.map { SummaryFact(1, null, "c", it) })
        val widened = SummaryPaths.normalize(set)
        assertTrue(widened > 0)
        assertTrue(set.all { it.path.endsWith(".*") || it.path == "*" }, set.map { it.path }.toString())
    }

    @Test
    fun `groups under the budget are left exact`() {
        val set = java.util.TreeSet((0 until 10).map { SummaryFact(1, null, "c", "f$it.g") })
        assertEquals(0, SummaryPaths.normalize(set))
        assertEquals(10, set.size)
    }
}
