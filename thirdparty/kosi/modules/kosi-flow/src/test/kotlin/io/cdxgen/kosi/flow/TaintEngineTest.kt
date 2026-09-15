package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.JsonWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The taint engine's corpus of one: every rule the fixtures pin end to end is
 * pinned here at unit level, including the proof that the corpus's most
 * valuable negative (field-sensitivity's clean sibling) FAILS when access
 * paths are collapsed — an engine without field sensitivity cannot pass the
 * corpus, which is the whole point of that fixture.
 */
class TaintEngineTest {

    private val pack = ModelPacks.parse(
        """
        {
          "sources": [
            {"pattern": "test.Source.read", "category": "untrusted-input"}
          ],
          "sinks": [
            {"pattern": "test.Sink.exec", "category": "process-exec", "relevantArguments": [0], "severity": "critical"},
            {"pattern": "test.Sink.query", "category": "sql-query", "relevantArguments": [1], "receiverType": "test.Sink"}
          ],
          "passthroughs": [
            {"pattern": "test.Adapter.listOf", "category": "iterator-adapter", "flows": [[0, -1]]}
          ],
          "sanitizers": [
            {"pattern": "test.Clean.digest", "clears": ["untrusted-input"]}
          ],
          "effects": [
            {"pattern": "test.Effect.add", "writesToArguments": [1]}
          ]
        }
        """.trimIndent(),
        "test-pack",
    )

    private val options = TaintEngine.Options(
        mode = "security",
        accessPathDepth = 5,
        maxSlices = 1000,
        maxTraceNodes = 64,
        maxFunctionInstructions = 20000,
        unknownCallPropagate = true,
        skipGenerated = true,
    )

    private val attribution = TaintEngine.Attribution(
        byAbsoluteFilePath = mapOf("/test/f.kt" to ("f.kt" to "module-main")),
        purlByModulePath = mapOf("module-main" to "pkg:maven/test/module"),
    )

    private fun fn(vararg blocks: KirBlock): KirFunction = KirFunction(
        canonicalName = "test.Fn",
        jvmDescriptor = null,
        purl = "",
        file = "/test/f.kt",
        line = 1,
        column = 1,
        params = emptyList(),
        returnType = null,
        modifiers = emptySet(),
        visibility = "public",
        enclosingClass = null,
        overrides = emptyList(),
        overriddenBy = emptyList(),
        annotations = emptyList(),
        syntheticCause = null,
        body = KirBody(blocks.toList()),
    )

    private fun block(id: String, vararg instructions: io.cdxgen.kosi.kir.KirIns, entry: Boolean = false) =
        KirBlock(id, entry, instructions.toList())

    private fun run(function: KirFunction, options: TaintEngine.Options = this.options): TaintEngine.Result =
        TaintEngine.analyze(KirModule(listOf(function)), pack, attribution, options)

    private fun evidenceJson(result: TaintEngine.Result): String {
        val w = JsonWriter()
        result.evidence.writeJson(w)
        return w.render()
    }

    // ---- THE corpus negative, at engine level ------------------------------

    @Test
    fun aCleanSiblingFieldStaysClean() {
        // write query <- source; read column -> sink. Field sensitivity is
        // what keeps this silent.
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirFieldSet("v this", AccessPath.field("v this", "query"), "t1"),
                KirFieldGet("t2", "v this", AccessPath.field("v this", "column")),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(0, result.evidence.slices.size, "the clean sibling must not report")
    }

    @Test
    fun aFieldInsensitiveEngineReportsTheCleanSibling() {
        // THE gate: the same shape with access paths collapsed (the
        // field-insensitive engine) DOES report — proving the corpus negative
        // has teeth. If this ever stops holding, the fixture's want-not is
        // passing vacuously.
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirFieldSet("v this", AccessPath.field("v this", "query"), "t1"),
                KirFieldGet("t2", "v this", AccessPath.field("v this", "column")),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function, options.copy(accessPathDepth = 0))
        assertEquals(1, result.evidence.slices.size, "collapsing paths must lose the distinction the negative pins")
    }

    @Test
    fun theTaintedFieldItselfReports() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirFieldSet("v this", AccessPath.field("v this", "query"), "t1"),
                KirFieldGet("t2", "v this", AccessPath.field("v this", "query")),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(1, result.evidence.slices.size)
        val slice = result.evidence.slices.single()
        assertEquals("untrusted-input", slice.sourceCategory)
        assertEquals("process-exec", slice.sinkCategory)
        assertEquals("critical", slice.severity)
        assertEquals("9.0", slice.riskScore)
        assertEquals(0, slice.sinkArgumentIndex)
    }

    // ---- the worklist to fixpoint ---------------------------------------------

    @Test
    fun aLoopCarriedFlowNeedsTheSecondRotation() {
        // The sink reads `v carried` BEFORE the store that taints it; only a
        // second pass over the body from the back-edge join can see it.
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirStore("v line", "t1"),
                KirLoad("t0", KirConstant.Null),
                KirStore("v carried", "t0"),
                io.cdxgen.kosi.kir.KirBranch("t1", "b1", "b1"),
                entry = true,
            ),
            block(
                "b1",
                io.cdxgen.kosi.kir.KirBranch("t1", "b2", "b3"),
            ),
            block(
                "b2",
                KirCall("t9", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("v carried"), 7),
                KirStore("v carried", "v line"),
                io.cdxgen.kosi.kir.KirBranch("t1", "b1", "b1"),
            ),
            block(
                "b3",
                io.cdxgen.kosi.kir.KirReturn(null),
            ),
        )
        val result = run(function)
        assertEquals(1, result.evidence.slices.size, "the back-edge join must carry the taint into a second pass")
        assertEquals(1.0, result.evidence.stats.connectivity)
        assertEquals(0, result.evidence.stats.integrityViolations)
        assertEquals(0, result.fixpointCapHits)
        assertEquals(1, result.functionsAnalysed)
    }

    // ---- pack-driven classification ---------------------------------------------

    @Test
    fun aSanitizerClearsOnlyItsNamedCategories() {
        val sanitized = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Clean.digest", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), null, listOf("t1"), 2),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        assertEquals(0, run(sanitized).evidence.slices.size, "digest clears untrusted-input on its result")

        // The taint that stayed behind (the argument) is NOT hidden.
        val raw = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Clean.digest", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), null, listOf("t1"), 2),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        assertEquals(1, run(raw).evidence.slices.size)
    }

    @Test
    fun aPassthroughFlowsAccordingToThePack() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Adapter.listOf", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1"), 2),
                KirIndexGet("t3", "t2", "t-i"),
                KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t3"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(1, result.evidence.slices.size)
        assertEquals(3, result.evidence.slices.single().pathLength)
    }

    @Test
    fun anEffectWritesArgumentTaintIntoTheReceiver() {
        val function = fn(
            block(
                "b0",
                KirNew("t0", "test.List", emptyList(), 1),
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 2),
                KirCall("t2", KirCallee("test.Effect.add", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), "t0", listOf("t1"), 3),
                KirIndexGet("t3", "t0", "t-i"),
                KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t3"), 5),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        assertEquals(1, run(function).evidence.slices.size, "xs.add(tainted) must taint xs's element state")
    }

    @Test
    fun aSinkArgumentConventionFollowsThePack() {
        // Index 1 with a receiver means the FIRST ARGUMENT (0 is the receiver).
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Sink.query", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), "t-recv", listOf("t1", "t-clean"), 2),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(1, result.evidence.slices.size)
        assertEquals(1, result.evidence.slices.single().sinkArgumentIndex)
    }

    @Test
    fun unknownCallsPropagateOnlyWhenTaintActuallyMoves() {
        val propagating = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Unknown.call", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), null, listOf("t1"), 2),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(propagating)
        assertEquals(1, result.evidence.slices.size)
        assertEquals(1, result.unknownCallPropagations)

        val clean = fn(
            block(
                "b0",
                KirCall("t2", KirCallee("test.Unknown.call", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), null, emptyList(), 2),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        assertEquals(0, run(clean).unknownCallPropagations, "no taint moved, so nothing to count")
    }

    @Test
    fun theDropDefaultKillsUnknownCallResults() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Unknown.call", null, io.cdxgen.kosi.kir.CallKind.VIRTUAL), null, listOf("t1"), 2),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function, options.copy(unknownCallPropagate = false))
        assertEquals(0, result.evidence.slices.size, "--unknown-call drop must not carry taint through unknowns")
        assertEquals(0, result.unknownCallPropagations)
    }

    @Test
    fun dynamicCallsPropagateAndAreCounted() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirDynamicCall("t2", "frobnicate", null, listOf("t1"), 2),
                KirCall("t3", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t2"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(1, result.evidence.slices.size)
        assertEquals(1, result.unknownCallPropagations)
    }

    @Test
    fun theFunctionInstructionCapSkipsAndCounts() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1"), 2),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function, options.copy(maxFunctionInstructions = 1))
        assertEquals(0, result.functionsAnalysed, "the function exceeded the cap and was skipped")
        assertEquals(0, result.evidence.slices.size)
        // The oversized function is skipped from BOTH analyses: the main
        // worklist (function-instructions) and the P5 summarizer.
        assertEquals(mapOf("function-instructions" to 1, "summary-oversized-function" to 1), result.truncations)
        assertTrue(result.diagnostics.any { it.code == DiagnosticCodes.DATAFLOW_TRUNCATED })
    }

    @Test
    fun generatedFunctionsAreSkippedWhenAsked() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1"), 2),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        ).copy(syntheticCause = "data-class")
        val skipped = run(function, options.copy(skipGenerated = true))
        assertEquals(0, skipped.functionsAnalysed)
        val analysed = run(function, options.copy(skipGenerated = false))
        assertEquals(1, analysed.functionsAnalysed)
        assertEquals(1, analysed.evidence.slices.size)
    }

    @Test
    fun twoRunsAreByteIdentical() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirStore("v a", "t1"),
                KirCall("t2", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("v a"), 3),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        assertEquals(evidenceJson(run(function)), evidenceJson(run(function)))
    }

    @Test
    fun everySliceSatisfiesTheTraceInvariants() {
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Adapter.listOf", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1"), 2),
                KirStore("v a", "t2"),
                KirIndexGet("t3", "t2", "t-i"),
                KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t3"), 5),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertTrue(result.evidence.slices.isNotEmpty())
        assertEndpointsAreReal(result)
        assertEquals(1.0, result.evidence.stats.connectivity)
        assertEquals(0, result.evidence.stats.integrityViolations)
        assertEquals(1, result.sourceSites)
        assertEquals(1, result.sinkSites)
    }

    // ---- R54: the endpoints a trace claims must be the endpoints it has ----

    /**
     * `sourceId in nodeIds` is trivially true — `materialise` assigns it from
     * `nodeIds.first()`. The property that actually matters, and the one that
     * was broken, is that the node it points AT is a source node. Checking a
     * list against itself is how three of eleven fixture slices reported a
     * trace beginning at a field write while the run published connectivity
     * 1.000 and 0 integrity violations.
     */
    private fun assertEndpointsAreReal(result: TaintEngine.Result) {
        val nodes = result.evidence.nodes.associateBy { it.id }
        for (slice in result.evidence.slices) {
            assertEquals("source", nodes[slice.sourceId]?.kind, "trace does not start at a source: ${slice.id}")
            assertEquals("sink", nodes[slice.sinkId]?.kind, "trace does not end at a sink: ${slice.id}")
            assertTrue(slice.flowKey.isNotBlank() && slice.ruleId.isNotBlank())
            assertTrue(slice.severity.isNotBlank() && slice.confidence.isNotBlank() && slice.riskScore.isNotBlank())
        }
    }

    private fun elvisFlow() = fn(
        block(
            "b0",
            KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
            KirLoad("t2", KirConstant.Str("")),
            io.cdxgen.kosi.kir.KirElvis("t3", "t1", "t2"),
            KirStore("v input", "t3"),
            KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("v input"), 5),
            io.cdxgen.kosi.kir.KirReturn(null),
            entry = true,
        ),
    )

    @Test
    fun anElvisOnTheTaintPathKeepsTheSourceEndpoint() {
        // `readLine() ?: ""` is in four fixtures. Elvis merged the facts and
        // recorded no provenance move, so the backward walk dead-ended and
        // the emitted trace began at the store — unmarked, and invisible to
        // an integrity check that validated the emitted list against itself.
        val result = run(elvisFlow())
        assertEquals(1, result.evidence.slices.size)
        assertEndpointsAreReal(result)
        val slice = result.evidence.slices.single()
        assertEquals(null, slice.elided, "a complete walk must not be marked elided")
        assertEquals(
            listOf("source", "elvis", "assign", "sink"),
            slice.nodeIds.map { id -> result.evidence.nodes.first { it.id == id }.kind },
        )
    }

    @Test
    fun aTraceTruncatedByTheCapKeepsItsSourceAndSaysSo() {
        // The cap must cut the MIDDLE. Before, it cut from the source end
        // and left the slice claiming a complete trace that started
        // wherever the walk happened to stop.
        val result = run(elvisFlow(), options.copy(maxTraceNodes = 1))
        val slice = result.evidence.slices.single()
        assertEquals(true, slice.elided, "a cut walk must be marked elided")
        assertEndpointsAreReal(result)
        assertEquals(
            "elided",
            result.evidence.edges.first { it.id == slice.edgeIds.first() }.kind,
            "the gap belongs on the first edge, not hidden",
        )
    }

    @Test
    fun aJoinAttributesEachFactToTheOperandThatCarriedIt() {
        // Two sources into one concat-shaped join: blaming the first
        // non-empty operand for every fact sends one of the two walks into a
        // register that never held it, and the walk then dead-ends.
        val function = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 2),
                io.cdxgen.kosi.kir.KirStringConcat("t3", listOf("t1", "t2")),
                KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t3"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val result = run(function)
        assertEquals(2, result.evidence.slices.size, "each source is its own flow")
        assertEndpointsAreReal(result)
        assertTrue(result.evidence.slices.none { it.elided == true }, "neither walk should have been cut")
    }

    @Test
    fun crossDependencyIsCountedFromTheSlicesNotAsserted() {
        // The gate reads `stats.crossDependencySlices`; writing it as a
        // literal made the check unable to fail for a reason unrelated to
        // the engine. It is now a count over the slices themselves.
        val result = run(elvisFlow())
        assertEquals(
            result.evidence.slices.count { it.crossesDependency },
            result.evidence.stats.crossDependencySlices,
        )
    }

    @Test
    fun everyMergeAttributesPerFactNotJustTheJoins() {
        // R54 was fixed at the concat/phi/elvis join and nowhere else. The
        // OTHER two merges — an element read, and the blanket propagation an
        // unresolvable call performs by default — still blamed the first
        // non-empty operand for every fact they merged. Two sources into
        // one unknown call is the shape that exposes it: the fact that
        // arrived on the second argument gets a move pointing at the first,
        // the backward walk dead-ends in a register that never held it, and
        // the endpoint net silently marks the slice elided.
        val unknownCall = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 2),
                KirCall("t3", KirCallee("test.Nowhere.mix", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t1", "t2"), 3),
                KirCall("t4", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t3"), 4),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val propagated = run(unknownCall)
        assertEquals(2, propagated.evidence.slices.size, "both sources reach the sink through the unknown call")
        assertEndpointsAreReal(propagated)
        assertTrue(propagated.evidence.slices.none { it.elided == true }, "neither walk should dead-end")

        // The element read merges the collection's element state with the
        // collection value itself — the same two-operand merge.
        val indexRead = fn(
            block(
                "b0",
                KirCall("t1", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 1),
                KirCall("t2", KirCallee("test.Source.read", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, emptyList(), 2),
                KirLoad("t3", KirConstant.IntConst(0)),
                // t2 is the collection VALUE; t1 lands in its element state.
                io.cdxgen.kosi.kir.KirIndexSet("t2", "t3", "t1"),
                io.cdxgen.kosi.kir.KirIndexGet("t4", "t2", "t3"),
                KirCall("t5", KirCallee("test.Sink.exec", null, io.cdxgen.kosi.kir.CallKind.STATIC), null, listOf("t4"), 5),
                io.cdxgen.kosi.kir.KirReturn(null),
                entry = true,
            ),
        )
        val indexed = run(indexRead)
        assertEquals(2, indexed.evidence.slices.size, "the element and the collection each carry their own fact")
        assertEndpointsAreReal(indexed)
        assertTrue(indexed.evidence.slices.none { it.elided == true }, "neither walk should dead-end")
    }
}
