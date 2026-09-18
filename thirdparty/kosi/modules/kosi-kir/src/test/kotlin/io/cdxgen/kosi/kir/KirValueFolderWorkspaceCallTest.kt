package io.cdxgen.kosi.kir

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * P21 §1: the fold's producer bucket — a register defined by a call — now
 * folds when the callee is in the workspace and every return site of every
 * candidate body folds to the same constant. The conservative arms are the
 * point of the design, so each is pinned here: disagreeing returns, an open
 * virtual target, a recursive cycle and a parameter-returning body all stay
 * PRODUCER; the depth budget binds THROUGH a call chain and names itself;
 * and the published status is FOLDED_CONST — the site names a call, not a
 * literal, and the resolution a consumer reads must say which shape the use
 * site carried.
 */
class KirValueFolderWorkspaceCallTest {

    private fun block(id: String, vararg instructions: KirIns): KirBlock =
        KirBlock(id, entry = false, instructions = instructions.toList())

    private fun entryBlock(id: String, vararg instructions: KirIns): KirBlock =
        KirBlock(id, entry = true, instructions = instructions.toList())

    private fun fn(
        canonicalName: String,
        vararg blocks: KirBlock,
        params: List<KirParam> = listOf(),
        enclosingClass: String? = null,
        modifiers: Set<String> = setOf(),
        visibility: String = "public",
        ownerFlags: Set<String> = setOf(),
        descriptor: String? = null,
    ): KirFunction = KirFunction(
        canonicalName = canonicalName,
        jvmDescriptor = descriptor,
        purl = "",
        file = "f.kt",
        line = 1,
        column = 1,
        params = params,
        returnType = null,
        modifiers = modifiers,
        visibility = visibility,
        enclosingClass = enclosingClass,
        overrides = listOf(),
        overriddenBy = listOf(),
        annotations = listOf(),
        syntheticCause = null,
        body = KirBody(blocks.toList()),
        ownerFlags = ownerFlags,
    )

    private fun call(
        result: String,
        fqn: String,
        vararg args: String,
        kind: CallKind = CallKind.STATIC,
        descriptor: String? = null,
    ) = KirCall(result, KirCallee(fqn, descriptor, kind), null, args.toList())

    private fun folder(vararg functions: KirFunction, constValues: Map<String, String> = emptyMap()): KirValueFolder =
        KirValueFolder(KirModule(functions.toList()), constValues = constValues)

    @Test
    fun aWorkspaceCallWhoseBodyReturnsALiteralFolds() {
        val callee = fn("probe.baseUrl", entryBlock("b0", KirLoad("t0", KirConstant.Str("\"https://base.example.com\"")), KirReturn("t0")))
        val caller = fn(
            "probe.use",
            entryBlock("b0", call("t1", "probe.baseUrl"), call("t2", "sink", "t1")),
        )
        val f = folder(caller, callee)
        val folded = f.valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertEquals("https://base.example.com", folded.value)
        assertTrue(folded.resolved)
        assertEquals(
            KirValueFolder.ValueStatus.FOLDED_CONST,
            folded.status,
            "the site names a CALL — publishing LITERAL would claim the value stood at the use site",
        )
    }

    /** The restored-defect leg: no workspace arm, the call is an opaque producer again. */
    @Test
    fun aCallToAFunctionOutsideTheModuleStaysAProducer() {
        val caller = fn(
            "probe.use",
            entryBlock("b0", call("t1", "elsewhere.baseUrl"), call("t2", "sink", "t1")),
        )
        val stats = KirValueFolder.FoldStats()
        val f = KirValueFolder(KirModule(listOf(caller)), statsSink = stats)
        val folded = f.valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
        assertEquals(1, stats.producer)
        assertEquals(0, stats.folded)
    }

    @Test
    fun returnSitesThatDisagreeRefuseTheFold() {
        val callee = fn(
            "probe.picky",
            entryBlock("b0", KirBranch("c", "b1", "b2")),
            block("b1", KirLoad("t1", KirConstant.Str("\"a\"")), KirReturn("t1")),
            block("b2", KirLoad("t2", KirConstant.Str("\"b\"")), KirReturn("t2")),
        )
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.picky"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved, "disagreeing returns are unresolved — not a guess, not the first arm")
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
    }

    @Test
    fun recursionIsUnresolved() {
        val callee = fn(
            "probe.loop",
            entryBlock("b0", call("t1", "probe.loop"), KirReturn("t1")),
        )
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.loop"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved, "a recursive cycle has no single provenance")
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
    }

    @Test
    fun aFunctionReturningItsParameterIsNotAConstantFunction() {
        val callee = fn(
            "probe.echo",
            entryBlock("b0", KirReturn("%0")),
            params = listOf(KirParam("%0", "x", "kotlin.String", receiver = false)),
        )
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.echo"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved, "the fold never folds THROUGH a callee's parameters")
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
    }

    @Test
    fun anOpenVirtualTargetRefusesEvenWithAConstantBody() {
        // An open member of an open class: a dependency jar's override could
        // return anything, so a constant body proves nothing.
        val callee = fn(
            "probe.Impl.name",
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\"")), KirReturn("t0")),
            enclosingClass = "probe.Impl",
            modifiers = setOf("open"),
            visibility = "public",
        )
        val caller = fn(
            "probe.use",
            entryBlock("b0", call("t1", "probe.Impl.name", kind = CallKind.VIRTUAL), call("t2", "sink", "t1")),
        )
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved, "an open virtual dispatch can hide an override outside the workspace")
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
    }

    @Test
    fun aFinalMemberFoldsAndSoDoesAnObjectOwner() {
        val finalMember = fn(
            "probe.Impl.name",
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\"")), KirReturn("t0")),
            enclosingClass = "probe.Impl",
            modifiers = setOf("final"),
        )
        val objectMember = fn(
            "probe.Config.host",
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"h\"")), KirReturn("t0")),
            enclosingClass = "probe.Config",
            ownerFlags = setOf("object"),
        )
        val caller = fn(
            "probe.use",
            entryBlock(
                "b0",
                call("t1", "probe.Impl.name", kind = CallKind.VIRTUAL),
                call("t2", "probe.Config.host", kind = CallKind.VIRTUAL),
                call("t3", "sink", "t1"),
                call("t4", "sink", "t2"),
            ),
        )
        val f = folder(caller, finalMember, objectMember)
        val b0 = caller.body!!.blocks.first()
        assertEquals("v", f.valueAt(caller, b0, 2, "t1")!!.value, "final member: no override can hide")
        assertEquals(
            KirValueFolder.ValueStatus.FOLDED_CONST,
            f.valueAt(caller, b0, 2, "t1")!!.status,
        )
        assertEquals("h", f.valueAt(caller, b0, 3, "t2")!!.value, "an object owner cannot be overridden either")
    }

    @Test
    fun aConstReadInsideTheCalleeFoldsThroughIt() {
        val callee = fn(
            "probe.versioned",
            entryBlock(
                "b0",
                KirFieldGet("t0", "vthis", AccessPath.of("vthis", listOf(AccessPath.Element.Field("VERSION")))),
                KirReturn("t0"),
            ),
        )
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.versioned"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee, constValues = mapOf("VERSION" to "2.4"))
            .valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertEquals("2.4", folded.value)
        assertEquals(KirValueFolder.ValueStatus.FOLDED_CONST, folded.status)
    }

    @Test
    fun theDepthBudgetBindsThroughACallChainAndNamesItself() {
        // caller -> c1 -> c2 -> ... -> c9, each returning the next call's
        // result, the last returning a literal: eleven hops, one past the
        // budget of eight. The failure must be DEPTH_CAP, never a silent
        // PRODUCER — the depth report's budget row is the measurement.
        val functions = mutableListOf(
            fn(
                "probe.use",
                entryBlock("b0", call("t1", "probe.c1"), call("t2", "sink", "t1")),
            ),
        )
        for (i in 1..8) {
            functions.add(fn("probe.c$i", entryBlock("b0", call("t1", "probe.c${i + 1}"), KirReturn("t1"))))
        }
        functions.add(fn("probe.c9", entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\"")), KirReturn("t0"))))
        val f = folder(*functions.toTypedArray())
        val stats = KirValueFolder.FoldStats()
        val counted = KirValueFolder(KirModule(functions.toList()), statsSink = stats)
        val caller = functions.first()
        val folded = counted.valueAt(caller, caller.body!!.blocks.first(), 0, "t1")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.DEPTH_CAP, folded.failure)
        assertEquals(1, stats.depthCap, "the budget's bind is COUNTED — never a silent stop")
    }

    @Test
    fun anOverloadSetFoldsOnlyWhenEveryOverloadAgrees() {
        // Two same-name overloads with DIFFERENT bodies: the site-known
        // descriptor must pick ITS overload's sites (a name-keyed site cache
        // would fold the wrong body here), and an un-narrowed site must see
        // the disagreement and refuse.
        val a = fn(
            "probe.load",
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"v\"")), KirReturn("t0")),
            descriptor = "()V",
        )
        val b = fn(
            "probe.load",
            entryBlock("b0", KirLoad("t0", KirConstant.Str("\"other\"")), KirReturn("t0")),
            descriptor = "(I)V",
        )
        val caller = fn(
            "probe.use",
            entryBlock(
                "b0",
                call("t1", "probe.load", descriptor = "()V"),
                call("t2", "sink", "t1"),
            ),
        )
        val b0 = caller.body!!.blocks.first()
        assertEquals(
            "v",
            folder(caller, a, b).valueAt(caller, b0, 1, "t1")!!.value,
            "a site-known descriptor narrows to its overload's own body",
        )
        val unNarrowed = fn(
            "probe.use",
            entryBlock("b0", call("t1", "probe.load"), call("t2", "sink", "t1")),
        )
        val noDescriptor = folder(unNarrowed, a, b).valueAt(unNarrowed, unNarrowed.body!!.blocks.first(), 1, "t1")!!
        assertFalse(noDescriptor.resolved, "un-narrowed overloads that disagree refuse — never the first arm")
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, noDescriptor.failure)
    }

    @Test
    fun aUnitReturnIsNotAValue() {
        val callee = fn("probe.unit", entryBlock("b0", KirReturn(null)))
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.unit"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved)
        assertEquals(KirValueFolder.FoldFailure.PRODUCER, folded.failure)
    }

    @Test
    fun aProvableNullReturnKeepsItsStatus() {
        val callee = fn("probe.nullary", entryBlock("b0", KirLoad("t0", KirConstant.Null), KirReturn("t0")))
        val caller = fn("probe.use", entryBlock("b0", call("t1", "probe.nullary"), call("t2", "sink", "t1")))
        val folded = folder(caller, callee).valueAt(caller, caller.body!!.blocks.first(), 1, "t1")!!
        assertFalse(folded.resolved, "null is the absence of a value, not a resolved string")
        assertEquals(KirValueFolder.ValueStatus.NULL, folded.status)
        assertEquals(null, folded.failure, "found-null is a fact, not a failure")
    }
}
