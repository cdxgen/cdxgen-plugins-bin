package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirSuspendPoint
import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.models.ModelPacks
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The P5/P6 engine rules the fixtures pin end to end, pinned HERE at unit
 * level too — including the proofs that the corpus negatives FAIL when the
 * rule they pin is switched off (the P4 discipline: an annotation has teeth
 * only if an engine-level knob can break it).
 */
class InterproceduralEngineTest {

    private val pack = ModelPacks.loadBuiltin()

    private val attribution = TaintEngine.Attribution(
        byAbsoluteFilePath = mapOf("/a.kt" to ("a.kt" to "module-a"), "/b.kt" to ("b.kt" to "module-b")),
        purlByModulePath = mapOf("module-a" to "pkg:maven/test/a", "module-b" to "pkg:maven/test/b"),
    )

    private fun options(accessPathDepth: Int = 5, dispatchMode: String = "cha") = TaintEngine.Options(
        mode = "security",
        accessPathDepth = accessPathDepth,
        maxSlices = 100,
        maxTraceNodes = 64,
        maxFunctionInstructions = 20000,
        unknownCallPropagate = true,
        skipGenerated = true,
        dispatchMode = dispatchMode,
    )

    private fun fn(
        canonical: String,
        vararg instructions: KirIns,
        file: String = "/a.kt",
        params: List<KirParam> = emptyList(),
        overrides: List<String> = emptyList(),
        enclosingClass: String? = null,
    ) = KirFunction(
        canonicalName = canonical,
        jvmDescriptor = null,
        purl = "",
        file = file,
        line = 1,
        column = 1,
        params = params,
        returnType = null,
        modifiers = setOf("final"),
        visibility = "public",
        enclosingClass = enclosingClass,
        overrides = overrides,
        overriddenBy = emptyList(),
        annotations = emptyList(),
        syntheticCause = null,
        body = KirBody(listOf(KirBlock("b0", true, instructions.toList()))),
    )

    private fun analyze(vararg functions: KirFunction, options: TaintEngine.Options = options()) =
        TaintEngine.analyze(KirModule(functions.toList()), pack, attribution, options)

    private fun source(reg: String, line: Int) = KirCall(reg, KirCallee("kotlin.io.readLine", null, CallKind.STATIC), null, emptyList(), line)

    private fun sink(reg: String, line: Int) = KirCall(
        null,
        KirCallee("java.lang.ProcessBuilder", "(Ljava/lang/String;)Ljava/lang/ProcessBuilder;", CallKind.CONSTRUCTOR),
        null,
        listOf(reg),
        line,
    )

    // ---- THE boundary negative, at engine level -----------------------------

    @Test
    fun anInterproceduralCleanSiblingStaysClean() {
        // The caller taints job.command; the callee sinks job.label. Field
        // sensitivity at the BOUNDARY is what keeps this silent: the
        // callee's effect records the path `label`, and the caller's taint
        // sits on `command`.
        val job = fn(
            "test.sinkLabel",
            KirStore("vjob", "%0"),
            KirFieldGet("t0", "vjob", AccessPath.field("vjob", "label")),
            sink("t0", 3),
            KirReturn(null),
            params = listOf(KirParam("%0", "job", "Job", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            KirNew("j0", "test.Job", emptyList(), 10),
            KirStore("vjob", "j0"),
            source("t1", 11),
            KirFieldSet("vjob", AccessPath.field("vjob", "command"), "t1"),
            KirCall(null, KirCallee("test.sinkLabel", null, CallKind.STATIC), null, listOf("vjob"), 12),
            KirReturn(null),
        )
        val result = analyze(caller, job)
        assertEquals(0, result.evidence.slices.size, "the clean sibling must not report")
    }

    @Test
    fun theInterproceduralTaintedFieldReportsAndCollapsingThePathsBreaksTheNegative() {
        // Positive half: the callee sinks the TAINTED field -> the slice
        // crosses the boundary. Then the corpus negative's teeth: with
        // access paths collapsed (the field-INsensitive engine), the
        // clean-sibling negative REPORTS — proving the boundary precision
        // above comes from field sensitivity, not luck.
        val sinkCommand = fn(
            "test.sinkCommand",
            KirStore("vjob", "%0"),
            KirFieldGet("t0", "vjob", AccessPath.field("vjob", "command")),
            sink("t0", 3),
            KirReturn(null),
            params = listOf(KirParam("%0", "job", "Job", receiver = false)),
        )
        val sinkLabel = fn(
            "test.sinkLabel",
            KirStore("vjob", "%0"),
            KirFieldGet("t0", "vjob", AccessPath.field("vjob", "label")),
            sink("t0", 3),
            KirReturn(null),
            params = listOf(KirParam("%0", "job", "Job", receiver = false)),
        )
        fun caller(sink: String) = fn(
            "test.caller",
            KirNew("j0", "test.Job", emptyList(), 10),
            KirStore("vjob", "j0"),
            source("t1", 11),
            KirFieldSet("vjob", AccessPath.field("vjob", "command"), "t1"),
            KirCall(null, KirCallee(sink, null, CallKind.STATIC), null, listOf("vjob"), 12),
            KirReturn(null),
        )
        val positive = analyze(caller("test.sinkCommand"), sinkCommand)
        assertEquals(1, positive.evidence.slices.size, "the tainted field must report across the boundary")
        assertEquals("test.caller", positive.evidence.slices[0].sourceFunction)
        assertEquals("test.sinkCommand", positive.evidence.slices[0].sinkFunction)

        val fieldInsensitive = analyze(
            caller("test.sinkLabel"),
            sinkLabel,
            options = options(accessPathDepth = 0),
        )
        assertEquals(
            1,
            fieldInsensitive.evidence.slices.size,
            "collapsing access paths must BREAK the clean-sibling negative (that is what gives it teeth)",
        )
    }

    // ---- application order: pack, then summary, then default -----------------

    @Test
    fun packEntriesBeatSummariesAtTheCallSite() {
        // The callee returns its parameter, AND the call site matches a pack
        // passthrough. The pack must win: the applied effect is the passthrough's
        // receiver->result, with origin=pack on the boundary move.
        val callee = fn(
            "test.wrap",
            KirStore("vraw", "%0"),
            KirReturn("vraw"),
            params = listOf(KirParam("%0", "raw", "String", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            source("t0", 10),
            KirStore("vraw", "t0"),
            // `plus` is a pack passthrough ([[0,-1],[1,-1]]): it matches FIRST,
            // so the callee's summary must not also apply.
            KirCall("t1", KirCallee("kotlin.text.plus", null, CallKind.OPERATOR), "vraw", listOf("t0"), 11),
            sink("t1", 12),
            KirReturn(null),
        )
        val result = analyze(caller, callee)
        val slice = result.evidence.slices.single()
        assertEquals(listOf("pack"), slice.origins)
    }

    @Test
    fun anUnresolvableCallIsLabelledDefaultAndCountsTowardTheDefaultOriginShare() {
        val callee = fn(
            "test.wrap",
            KirStore("vraw", "%0"),
            KirReturn("vraw"),
            params = listOf(KirParam("%0", "raw", "String", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            source("t0", 10),
            KirStore("vraw", "t0"),
            // Unresolved name: no pack entry, no summary -> the default.
            KirCall("t1", KirCallee("test.mystery", null, CallKind.STATIC), null, listOf("vraw"), 11),
            sink("t1", 12),
            KirReturn(null),
        )
        val result = analyze(caller, callee)
        val slice = result.evidence.slices.single()
        // `pack` is the source birth's provenance; the BOUNDARY origin is
        // `default` — and the default-only count is computed over boundary
        // origins, not over the birth's.
        assertEquals(listOf("default", "pack"), slice.origins)
        assertEquals(1, result.evidence.stats.defaultOriginSlices)
        assertEquals(1, result.evidence.stats.summaryCrossingSlices)
    }

    // ---- dispatch joins --------------------------------------------------------

    @Test
    fun vtaNarrowsTheJoinByTheReceiverTypeWhileChaJoinsBoth() {
        // LogTask does NOT sink (its log call moves nothing); ExecTask does.
        val logRun = fn(
            "test.LogTask.run",
            KirStore("vc", "%1"),
            // NOT a pack sink: println is a log-injection sink, and a clean
            // override must not secretly carry one.
            KirCall("t0", KirCallee("kotlin.text.plus", null, CallKind.OPERATOR), "vc", listOf("vc"), 5),
            KirReturn("t0"),
            overrides = listOf("test.Task.run"),
            enclosingClass = "LogTask",
            params = listOf(KirParam("%0", "this", "Task", receiver = true), KirParam("%1", "c", "String", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            KirNew("t0", "test.LogTask", emptyList(), 10),
            KirStore("vtask", "t0"),
            source("t1", 11),
            KirStore("vc", "t1"),
            KirCall(null, KirCallee("test.Task.run", null, CallKind.VIRTUAL), "vtask", listOf("vc"), 12),
            KirReturn(null),
        )
        val cha = analyze(caller, logRun, options = options(dispatchMode = "cha"))
        assertEquals(0, cha.evidence.slices.size, "the only override is clean: no slice under either mode")
        val vtaSingle = analyze(caller, logRun, options = options(dispatchMode = "vta"))
        assertEquals(0, vtaSingle.evidence.slices.size)

        // Now the SINKING override is joined by cha but not by vta, because
        // the receiver's construction type says LogTask only.
        val execRun = fn(
            "test.ExecTask.run",
            KirStore("vc", "%1"),
            sink("vc", 8),
            KirReturn(null),
            overrides = listOf("test.Task.run"),
            enclosingClass = "ExecTask",
            params = listOf(KirParam("%0", "this", "Task", receiver = true), KirParam("%1", "c", "String", receiver = false)),
        )
        val logOnlyCaller = fn(
            "test.logCaller",
            KirNew("t0", "test.LogTask", emptyList(), 20),
            KirStore("vtask", "t0"),
            source("t1", 21),
            KirStore("vc", "t1"),
            KirCall(null, KirCallee("test.Task.run", null, CallKind.VIRTUAL), "vtask", listOf("vc"), 22),
            KirReturn(null),
        )
        val vta = analyze(logOnlyCaller, logRun, execRun, options = options(dispatchMode = "vta"))
        assertEquals(
            0,
            vta.evidence.slices.size,
            "vta narrows by the receiver's construction type: the ExecTask summary never applies",
        )
        val chaBoth = analyze(logOnlyCaller, logRun, execRun, options = options(dispatchMode = "cha"))
        assertEquals(1, chaBoth.evidence.slices.size, "cha keeps both targets in the join and over-reports")
    }

    // ---- recursion ----------------------------------------------------------------

    @Test
    fun aMutuallyRecursivePairConvergesWithoutHittingTheCap() {
        val ping = fn(
            "test.ping",
            KirStore("vraw", "%1"),
            KirCall(null, KirCallee("test.pong", null, CallKind.STATIC), null, listOf("%0", "vraw"), 4),
            sink("vraw", 5),
            KirReturn(null),
            params = listOf(KirParam("%0", "n", "Int", receiver = false), KirParam("%1", "raw", "String", receiver = false)),
        )
        val pong = fn(
            "test.pong",
            KirStore("vraw", "%1"),
            KirCall(null, KirCallee("test.ping", null, CallKind.STATIC), null, listOf("%0", "vraw"), 8),
            KirReturn(null),
            params = listOf(KirParam("%0", "n", "Int", receiver = false), KirParam("%1", "raw", "String", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            source("t0", 20),
            KirCall(null, KirCallee("test.ping", null, CallKind.STATIC), null, listOf("t9", "t0"), 21),
            KirReturn(null),
        )
        val result = analyze(caller, ping, pong)
        assertEquals(0, result.sccIterationCapHits, "recursion is convergence, not a bail-out")
        assertEquals(0, result.fixpointCapHits)
        assertEquals(1, result.evidence.slices.size)
    }

    // ---- higher-order ----------------------------------------------------------------

    @Test
    fun aLambdaCaptureReachesTheSinkInsideTheExtractedBody() {
        // withBlock(block) { block("x") }, the lambda sinks its CAPTURE.
        val lambda = fn(
            "test.caller\$lambda0",
            KirStore("vmarker", "%p0"),
            KirCall("t0", KirCallee("kotlin.text.plus", null, CallKind.OPERATOR), "vmarker", listOf("%c0"), 12),
            sink("t0", 13),
            KirReturn("t0"),
            params = listOf(KirParam("%c0", "capture vraw", "String", receiver = false), KirParam("%p0", "marker", "String", receiver = false)),
        )
        val withBlock = fn(
            "test.withBlock",
            KirStore("vblock", "%0"),
            KirLoad("t0", KirConstant.Str("x")),
            KirCall("t1", KirCallee("kotlin.Function1.invoke", null, CallKind.OPERATOR), "vblock", listOf("t0"), 3),
            KirReturn(null),
            params = listOf(KirParam("%0", "block", "(String) -> Unit", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            source("t0", 11),
            KirStore("vraw", "t0"),
            KirLambda("t1", "test.caller\$lambda0", listOf("vraw")),
            KirCall(null, KirCallee("test.withBlock", null, CallKind.STATIC), null, listOf("t1"), 14),
            KirReturn(null),
        )
        val result = analyze(caller, withBlock, lambda)
        val slice = result.evidence.slices.singleOrNull()
        assertEquals("test.caller\$lambda0", slice?.sinkFunction, "the sink lives inside the extracted body")
        assertEquals("test.caller", slice?.sourceFunction)
    }

    // ---- suspend boundaries (P6) ---------------------------------------------------

    @Test
    fun aSuspendBoundaryIsTransparentToTaintAndCounted() {
        // emit(x) -> assign into the flow value; the flow value reaches a
        // sink with the suspend boundary the lowering emits after emit on
        // the trace.
        val caller = fn(
            "test.caller",
            source("t0", 10),
            KirStore("vraw", "t0"),
            KirCall("e0", KirCallee("kotlinx.coroutines.flow.FlowCollector.emit", null, CallKind.VIRTUAL), null, listOf("vraw"), 11),
            KirSuspendPoint("e0"),
            KirAssign("tflow", "vraw"),
            sink("tflow", 13),
            KirReturn(null),
        )
        val result = analyze(caller)
        val slice = result.evidence.slices.single()
        assertEquals(1, result.suspendCrossingSlices)
        val nodesById = result.evidence.nodes.associateBy { it.id }
        assertTrue(
            slice.nodeIds.any { nodesById.getValue(it).kind == "suspend" },
            "the suspend boundary is a visible node on the trace it crosses",
        )
    }

    // ---- summaries published ---------------------------------------------------------

    @Test
    fun summariesArePublishedWithOriginProvenance() {
        val callee = fn(
            "test.wrap",
            KirStore("vraw", "%0"),
            KirReturn("vraw"),
            params = listOf(KirParam("%0", "raw", "String", receiver = false)),
        )
        val caller = fn(
            "test.caller",
            source("t0", 10),
            KirStore("vraw", "t0"),
            KirCall("t1", KirCallee("test.wrap", null, CallKind.STATIC), null, listOf("vraw"), 11),
            sink("t1", 12),
            KirReturn(null),
        )
        val result = analyze(caller, callee)
        val byOrigin = result.summaries.groupBy { it.origin }
        assertTrue(byOrigin.containsKey("computed"), "computed summaries published")
        assertTrue(byOrigin.containsKey("pack"), "pack-derived summaries published")
        val wrap = result.summaries.first { it.functionId == "test.wrap" }
        assertEquals(listOf("p0"), wrap.paramToReturn)
    }
}
