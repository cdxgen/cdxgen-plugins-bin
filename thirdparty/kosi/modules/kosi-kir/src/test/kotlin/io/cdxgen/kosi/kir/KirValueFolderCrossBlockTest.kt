package io.cdxgen.kosi.kir

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The fold that stops at the block boundary was the ceiling — a URL
 * built in an `if`, a path assigned before a loop, a config value read at
 * the top and used at the bottom all stayed unresolved. The extension walks
 * the DOMINATOR CHAIN with the conservative join: a phi whose arms fold to
 * the SAME value folds to it; arms that disagree are unresolved (not a
 * guess, not the first arm); a back edge is unresolved; and a register
 * defined anywhere OFF the use block's dominator chain never folds
 * cross-block, because its value at the use is path-dependent. Each rule is
 * pinned both ways: with the fold enabled it holds, and with `crossBlock =
 * false` — the earlier block-local scan, the restored-defect leg — the same
 * fixture stays unresolved.
 */
class KirValueFolderCrossBlockTest {

    private fun block(id: String, vararg instructions: KirIns): KirBlock =
        KirBlock(id, entry = false, instructions = instructions.toList())

    private fun entryBlock(id: String, vararg instructions: KirIns): KirBlock =
        KirBlock(id, entry = true, instructions = instructions.toList())

    private fun function(vararg blocks: KirBlock, params: List<KirParam> = listOf()): KirFunction = KirFunction(
        canonicalName = "f",
        jvmDescriptor = null,
        purl = "",
        file = "f.kt",
        line = 1,
        column = 1,
        params = params,
        returnType = null,
        modifiers = setOf(),
        visibility = "public",
        enclosingClass = null,
        overrides = listOf(),
        overriddenBy = listOf(),
        annotations = listOf(),
        syntheticCause = null,
        body = KirBody(blocks.toList()),
    )

    private fun call(result: String, fqn: String, vararg args: String) =
        KirCall(result, KirCallee(fqn, null, CallKind.STATIC), null, args.toList())

    private fun folder(fn: KirFunction, crossBlock: Boolean = true): KirValueFolder =
        KirValueFolder(KirModule(listOf(fn)), crossBlock = crossBlock)

    private fun lastBlock(fn: KirFunction) = fn.body!!.blocks.last()

    @Test
    fun aDefinitionInADominatorBlockFoldsAcrossTheBoundary() {
        // b0 defines, falls through to b1, which uses: the earlier scan
        // stopped at the boundary and gave up.
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\""))),
            block("b1", call("t1", "java.lang.String.<init>", "t0")),
        )
        val folded = folder(fn).valueAt(fn, lastBlock(fn), 0, "t0")!!
        assertEquals("v", folded.value)
        assertTrue(folded.resolved)
    }

    @Test
    fun theSameFixtureStaysUnresolvedWithTheFoldDisabled() {
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\""))),
            block("b1", call("t1", "java.lang.String.<init>", "t0")),
        )
        val stats = KirValueFolder.FoldStats()
        val f = KirValueFolder(KirModule(listOf(fn)), crossBlock = false, statsSink = stats)
        val folded = f.valueAt(fn, lastBlock(fn), 0, "t0")!!
        assertFalse(
            folded.resolved,
            "the earlier block-local scan resolves nothing for a cross-block register",
        )
        assertEquals(KirValueFolder.FoldFailure.CROSS_BLOCK, folded.failure)
        assertEquals(1, stats.crossBlock, "the disabled fold still NAMES its refusal — the baseline column counts it")
    }

    @Test
    fun aPhiWhoseArmsAgreeFoldsToThatValue() {
        val fn = function(
            entryBlock("b0", KirBranch("c", "b1", "b2")),
            block("b1", KirLoad("t1", KirConstant.Str("\"v\"")), KirBranch("c", "b3", "b3")),
            block("b2", KirLoad("t2", KirConstant.Str("\"v\"")), KirBranch("c", "b3", "b3")),
            block("b3", KirPhi("t3", mapOf("b1" to "t1", "b2" to "t2")), call("t4", "sink", "t3")),
        )
        val b3 = lastBlock(fn)
        val folded = folder(fn).valueAt(fn, b3, 1, "t3")!!
        assertEquals("v", folded.value)
        assertTrue(folded.resolved)
    }

    @Test
    fun aPhiWhoseArmsDisagreeIsUnresolvedNotAGuess() {
        val fn = function(
            entryBlock("b0", KirBranch("c", "b1", "b2")),
            block("b1", KirLoad("t1", KirConstant.Str("\"a\"")), KirBranch("c", "b3", "b3")),
            block("b2", KirLoad("t2", KirConstant.Str("\"b\"")), KirBranch("c", "b3", "b3")),
            block("b3", KirPhi("t3", mapOf("b1" to "t1", "b2" to "t2")), call("t4", "sink", "t3")),
        )
        val b3 = lastBlock(fn)
        val folded = folder(fn).valueAt(fn, b3, 1, "t3")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.CROSS_BLOCK, folded.failure, "arms that disagree refuse to fold")
    }

    @Test
    fun aBackEdgeIsUnresolved() {
        // b2 is the loop header: its phi has an input from b1, a block the
        // header dominates (b1's only predecessor is b2) — loop-carried.
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\"")), KirBranch("c", "b2", "b2")),
            block("b1", KirLoad("t1", KirConstant.Str("\"w\"")), KirBranch("c", "b2", "b2")),
            block(
                "b2",
                KirPhi("t2", mapOf("b0" to "t0", "b1" to "t1")),
                KirBranch("c", "b1", "b3"),
            ),
            block("b3", call("t4", "sink", "t2")),
        )
        val b3 = lastBlock(fn)
        val folded = folder(fn).valueAt(fn, b3, 0, "t2")!!
        assertFalse(folded.resolved, "a loop-carried value has no single provenance")
        assertEquals(KirValueFolder.FoldFailure.CROSS_BLOCK, folded.failure)
    }

    @Test
    fun aDefinitionOffTheDominatorsRefusesTheFold() {
        // Two definitions: one in the entry (dominating), one in an if-arm
        // (off the chain). The value at the join is path-dependent, so even
        // the dominating definition must not fold.
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"top\"")), KirBranch("c", "b1", "b3")),
            block("b1", KirLoad("t0", KirConstant.Str("\"arm\"")), KirBranch("c", "b3", "b3")),
            block("b3", call("t4", "sink", "t0")),
        )
        val b3 = lastBlock(fn)
        val folded = folder(fn).valueAt(fn, b3, 0, "t0")!!
        assertFalse(folded.resolved, "an off-chain definition makes the value path-dependent")
        assertEquals(KirValueFolder.FoldFailure.CROSS_BLOCK, folded.failure)
    }

    @Test
    fun aConfigValueReadAtTheTopFoldsAtTheBottom() {
        val fn = function(
            entryBlock(
                "b0",
                KirLoad("t9", KirConstant.Str("\"base.url\"")),
                call("t0", "org.springframework.core.env.Environment.getProperty", "t9"),
                KirBranch("c", "b1", "b1"),
            ),
            block("b1", call("t2", "java.lang.String.<init>", "t0")),
        )
        val f = KirValueFolder(
            KirModule(listOf(fn)),
            configReaders = listOf("org.springframework.core.env.Environment.getProperty" to 0),
            configTable = mapOf("base.url" to "https://example.internal"),
        )
        // The config read lives in the entry block; the use sits a block
        // later. Pre-the boundary killed it.
        val b0 = fn.body!!.blocks[0]
        assertEquals("base.url", f.valueAt(fn, b0, 2, "t9")!!.value)
        val folded = f.valueAt(fn, lastBlock(fn), 0, "t0")!!
        assertTrue(folded.resolved)
        assertEquals("https://example.internal", folded.value)
        assertEquals(KirValueFolder.ValueStatus.CONFIG, folded.status)
    }

    @Test
    fun aParameterStaysAParameterAndTheStatsNameIt() {
        val fn = function(
            entryBlock("b0", call("t1", "sink", "%0")),
            block("b1", call("t2", "sink2", "%0")),
            params = listOf(KirParam("%0", "p", "kotlin.String", receiver = false)),
        )
        val stats = KirValueFolder.FoldStats()
        val f = KirValueFolder(KirModule(listOf(fn)), statsSink = stats)
        val folded = f.valueAt(fn, lastBlock(fn), 0, "%0")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.PARAMETER, folded.failure)
        assertEquals(1, stats.asked)
        assertEquals(0, stats.folded)
        assertEquals(1, stats.parameter)
        assertEquals(0, stats.crossBlock, "a parameter is not a cross-block miss")
    }

    @Test
    fun theDepthBudgetBindsAndIsCounted() {
        // A chain of assignments deeper than MAX_DEPTH: every hop is a
        // block boundary, so the dominator walk's budget binds.
        val blocks = mutableListOf(entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\""))))
        for (i in 1..12) {
            blocks.add(block("b$i", KirAssign("t$i", "t${i - 1}")))
        }
        val fn = function(*blocks.toTypedArray())
        val stats = KirValueFolder.FoldStats()
        val f = KirValueFolder(KirModule(listOf(fn)), statsSink = stats)
        val folded = f.valueAt(fn, lastBlock(fn), 0, "t12")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.DEPTH_CAP, folded.failure)
        assertEquals(1, stats.depthCap)
    }

    @Test
    fun aConcatOverACrossBlockPartFoldsNow() {
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\""))),
            block(
                "b1",
                KirStringConcat("t1", listOf("\"x\"", "t0")),
                call("t2", "sink", "t1"),
            ),
        )
        val folded = folder(fn).valueAt(fn, lastBlock(fn), 1, "t1")!!
        assertEquals("\"x\"v", folded.value)
        assertTrue(folded.resolved)
    }

    @Test
    fun theStatsSinkCountsFoldAndFailureByReason() {
        val fn = function(
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\""))),
            block(
                "b1",
                KirNew("t1", "java.lang.Object", listOf()),
                call("t2", "java.lang.String.<init>", "t0"),
                call("t3", "unknown.producer", "t1"),
            ),
        )
        val stats = KirValueFolder.FoldStats()
        val f = KirValueFolder(KirModule(listOf(fn)), statsSink = stats)
        f.valueAt(fn, lastBlock(fn), 1, "t0") // folds cross-block
        f.valueAt(fn, lastBlock(fn), 2, "t1") // a producer the folder cannot see through
        assertEquals(2, stats.asked)
        assertEquals(1, stats.folded)
        assertEquals(1, stats.producer)
        assertEquals(1, stats.crossBlockResolved)
    }
}
