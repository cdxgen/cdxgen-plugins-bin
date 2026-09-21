package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.schema.PathKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The `pathKind` vocabulary is the reachability fact a consumer can
 * act on, published instead of the two fields that never varied
 * (`reachableFromRoots` was false in every shipped slot, `rootWitness` was
 * null everywhere). This pins the vocabulary the way `RootsVocabularyTest`
 * pins the roots: exactly three values, every published slice carries one,
 * and the engine's classification rule is the same one the depth report's
 * reachability table reads — the elided slice at the trace cap is PARTIAL,
 * not COMPLETE with a quiet asterisk.
 */
class SlicePathKindVocabularyTest {

    private val pack = ModelPacks.loadBuiltin()

    private val attribution = TaintEngine.Attribution(
        byAbsoluteFilePath = mapOf("/a.kt" to ("a.kt" to "module-a")),
        purlByModulePath = mapOf("module-a" to "pkg:maven/test/a"),
    )

    private fun options(maxTraceNodes: Int) = TaintEngine.Options(
        mode = "security",
        accessPathDepth = 5,
        maxSlices = 100,
        maxTraceNodes = maxTraceNodes,
        maxFunctionInstructions = 20000,
        unknownCallPropagate = true,
        skipGenerated = true,
        dispatchMode = "cha",
    )

    private fun fn(
        canonical: String,
        vararg instructions: io.cdxgen.kosi.kir.KirIns,
        params: List<KirParam> = emptyList(),
    ) = KirFunction(
        canonicalName = canonical,
        jvmDescriptor = null,
        purl = "",
        file = "/a.kt",
        line = 1,
        column = 1,
        params = params,
        returnType = null,
        modifiers = setOf("final"),
        visibility = "public",
        enclosingClass = null,
        overrides = emptyList(),
        overriddenBy = emptyList(),
        annotations = emptyList(),
        syntheticCause = null,
        body = KirBody(listOf(KirBlock("b0", true, instructions.toList()))),
    )

    private fun source(reg: String, line: Int) =
        KirCall(reg, KirCallee("kotlin.io.readLine", null, CallKind.STATIC), null, emptyList(), line)

    private fun sink(reg: String, line: Int) = KirCall(
        null,
        KirCallee("java.lang.ProcessBuilder", "(Ljava/lang/String;)Ljava/lang/ProcessBuilder;", CallKind.CONSTRUCTOR),
        null,
        listOf(reg),
        line,
    )

    @Test
    fun theVocabularyIsClosedAtThreeValues() {
        assertEquals(
            sortedSetOf(PathKind.COMPLETE, PathKind.PARTIAL, PathKind.SYMBOL_ONLY),
            PathKind.ALL,
        )
        assertEquals(PathKind.ALL.size, 3, "a fourth pathKind does not ship — give it a fixture that drives it first")
    }

    @Test
    fun aFullWalkPublishesCompleteAndAnElidedOnePublishesPartial() {
        // A four-move chain (birth -> three copies -> sink): fully walkable
        // under the default cap, over it under a cap of two.
        val full = fn(
            "test.flow",
            KirStore("v", "%0"),
            source("t1", 2),
            io.cdxgen.kosi.kir.KirAssign("a1", "t1"),
            io.cdxgen.kosi.kir.KirAssign("a2", "a1"),
            io.cdxgen.kosi.kir.KirAssign("a3", "a2"),
            sink("a3", 6),
            KirReturn(null),
            params = listOf(KirParam("%0", "any", null, receiver = false)),
        )
        val complete = TaintEngine.analyze(KirModule(listOf(full)), pack, attribution, options(maxTraceNodes = 64))
        assertTrue(complete.evidence.slices.isNotEmpty(), "the module must publish a slice for the test to mean anything")
        assertTrue(
            complete.evidence.slices.all { it.pathKind == PathKind.COMPLETE },
            "an unelided source→sink walk is COMPLETE, got ${complete.evidence.slices.map { it.pathKind }}",
        )

        // The same flow under a trace cap of two: the walk is cut, the
        // endpoints are kept, the slice is PARTIAL — the corpus's
        // elided-trace fixture pins the same shape end to end.
        val capped = TaintEngine.analyze(KirModule(listOf(full)), pack, attribution, options(maxTraceNodes = 2))
        assertTrue(capped.evidence.slices.isNotEmpty(), "the capped run still publishes (endpoints guaranteed)")
        assertTrue(
            capped.evidence.slices.any { it.pathKind == PathKind.PARTIAL },
            "an elided walk must publish PARTIAL, got ${capped.evidence.slices.map { it.pathKind }}",
        )
        assertTrue(
            capped.evidence.slices.none { it.pathKind == PathKind.COMPLETE },
            "a cut walk must not publish COMPLETE",
        )
    }
}
