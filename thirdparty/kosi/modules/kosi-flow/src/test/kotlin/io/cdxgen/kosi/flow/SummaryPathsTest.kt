package io.cdxgen.kosi.flow

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The summary engine's path bounding (atom-tools#95). Opt-in or size
 * triggered only, for precision: a widened path matches every deeper reader
 * (FlowState.factsOf, pinned below), so it can add a flow and never drops
 * one. These pin what each rule does to a path, not when it runs.
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
    fun `subsumed paths are counted as widened`() {
        val set = java.util.TreeSet(listOf("p.*", "p.x", "p.x.y").map { SummaryFact(0, null, "c", it) })
        assertEquals(2, SummaryPaths.normalize(set))
    }

    /** A widened KEY covers every deeper read of it (atom-tools#95 review). */
    @Test
    fun `a widened key is read by every deeper path`() {
        val state = FlowState<String>()
        state.addFacts(TaintKey("m", "g5.*"), listOf("tainted"))
        assertEquals(setOf("tainted"), state.factsOf(TaintKey("m", "g5.f0")))
        assertEquals(setOf("tainted"), state.factsOf(TaintKey("m", "g5.f0.x")))
        assertEquals(emptySet(), state.factsOf(TaintKey("m", "g6.f0")), "a sibling is not covered")
        assertEquals(emptySet(), state.factsOf(TaintKey("m", "")), "nor the object itself")
    }

    /** A widened READ sees every key under its root. */
    @Test
    fun `a widened read sees every deeper key`() {
        val state = FlowState<String>()
        state.addFacts(TaintKey("m", "g5.f0"), listOf("a"))
        state.addFacts(TaintKey("m", "g6"), listOf("b"))
        state.addFacts(TaintKey("n", "g5.f0"), listOf("other register"))
        assertEquals(setOf("a"), state.factsOf(TaintKey("m", "g5.*")))
        assertEquals(setOf("a", "b"), state.factsOf(TaintKey("m", "*")))
    }

    @Test
    fun `exact states stay exact`() {
        val state = FlowState<String>()
        state.addFacts(TaintKey("m", "g5.f0"), listOf("a"))
        assertEquals(setOf("a"), state.factsOf(TaintKey("m", "g5.f0")))
        assertEquals(emptySet(), state.factsOf(TaintKey("m", "g5")))
        assertTrue(state.factsOf(TaintKey("m", "g5.f0")) === state.map[TaintKey("m", "g5.f0")], "no copy when nothing is widened")
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
