package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.models.ModelPacks
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The shape at the SUMMARY layer: two real overloads share one
 * canonical name and differ in body. The call sites carry descriptors, so
 * each must meet its OWN overload's summary — until the summary table
 * was keyed by name alone, `associateBy` kept the overload whose descriptor
 * sorts last (here the constant one), and the tainted overload's call site
 * applied the namesake's empty summary: a MISSED flow, the unsound
 * direction. The test also pins the projection the depth report's
 * agreement gate reads: per overload, whether a summary exists and whether
 * it claims taint can reach the return value.
 */
class SummaryOverloadTest {

    private val pack = ModelPacks.loadBuiltin()

    private val attribution = TaintEngine.Attribution(
        byAbsoluteFilePath = mapOf("/a.kt" to ("a.kt" to "module-a")),
        purlByModulePath = mapOf("module-a" to "pkg:maven/test/a"),
    )

    private fun options() = TaintEngine.Options(
        mode = "security",
        accessPathDepth = 5,
        maxSlices = 100,
        maxTraceNodes = 64,
        maxFunctionInstructions = 20000,
        unknownCallPropagate = true,
        skipGenerated = true,
        dispatchMode = "cha",
    )

    private val userDescriptor = "(Lfixtures/Msg\$User;)Ljava/lang/String;"
    private val stringDescriptor = "(Ljava/lang/String;)Ljava/lang/String;"

    /** One `fixtures.Msg.send` overload with its own descriptor and body. */
    private fun overload(descriptor: String, vararg instructions: KirIns) = KirFunction(
        canonicalName = "fixtures.Msg.send",
        jvmDescriptor = descriptor,
        purl = "",
        file = "/a.kt",
        line = 1,
        column = 1,
        params = listOf(KirParam("%0", "value", null, receiver = false)),
        returnType = null,
        modifiers = emptySet(),
        visibility = "public",
        enclosingClass = "fixtures.Msg",
        overrides = emptyList(),
        overriddenBy = emptyList(),
        annotations = emptyList(),
        syntheticCause = null,
        body = KirBody(listOf(KirBlock("b0", true, instructions.toList()))),
    )

    /** The tainted overload: returns its parameter, so paramToReturn = {0}. */
    private fun userOverload() = overload(userDescriptor, KirReturn("%0"))

    /** The constant overload: no taint crosses its return, ever. */
    private fun stringOverload() = overload(
        stringDescriptor,
        KirLoad("t0", KirConstant.Str("\"static\"")),
        KirReturn("t0"),
    )

    private fun caller(withConstantSite: Boolean) = KirFunction(
        canonicalName = "test.caller",
        jvmDescriptor = null,
        purl = "",
        file = "/a.kt",
        line = 20,
        column = 1,
        params = emptyList(),
        returnType = null,
        modifiers = setOf("final"),
        visibility = "public",
        enclosingClass = null,
        overrides = emptyList(),
        overriddenBy = emptyList(),
        annotations = emptyList(),
        syntheticCause = null,
        body = KirBody(
            listOf(
                KirBlock(
                    "b0",
                    true,
                    buildList {
                        add(source("t1", 21))
                        // The TAINTED overload's site: must meet the User summary.
                        add(
                            KirCall(
                                "r1",
                                KirCallee("fixtures.Msg.send", userDescriptor, CallKind.STATIC),
                                null,
                                listOf("t1"),
                                22,
                            ),
                        )
                        add(sink("r1", 23))
                        if (withConstantSite) {
                            // The constant overload's site, SAME tainted
                            // argument: its (empty) summary must not move
                            // the taint.
                            add(
                                KirCall(
                                    "r2",
                                    KirCallee("fixtures.Msg.send", stringDescriptor, CallKind.STATIC),
                                    null,
                                    listOf("t1"),
                                    24,
                                ),
                            )
                            add(sink("r2", 25))
                        }
                        add(KirReturn(null))
                    },
                ),
            ),
        ),
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

    private fun analyze(vararg functions: KirFunction) =
        TaintEngine.analyze(KirModule(functions.toList()), pack, attribution, options())

    @Test
    fun anOverloadAppliesItsOwnSummaryNotItsNamesakes() {
        val result = analyze(caller(withConstantSite = true), userOverload(), stringOverload())
        assertEquals(
            1,
            result.evidence.slices.size,
            "the tainted overload's boundary flow must report — and exactly once: the constant " +
                "overload's site carries the same taint but its summary must not move it",
        )
        val slice = result.evidence.slices[0]
        assertEquals("test.caller", slice.sourceFunction)

        // The assertion shape: the verdict for one overload must not
        // depend on the presence of the namesake. (The alone-run drops the
        // constant-overload SITE too: with it gone and the overload gone,
        // the site's descriptor would match nothing and dispatch would
        // widen to the remaining declared body — a resolution rule, not the
        // summary table's business.)
        val alone = analyze(caller(withConstantSite = false), userOverload())
        assertEquals(
            1,
            alone.evidence.slices.size,
            "removing the namesake must not change the tainted overload's verdict",
        )
    }

    @Test
    fun returnOpinionsAnswerPerOverloadAndRefuseUnknownNames() {
        val result = analyze(caller(withConstantSite = true), userOverload(), stringOverload())
        val opinions = result.returnOpinions
        assertEquals(
            true to true,
            opinions.opinion("fixtures.Msg.send", userDescriptor),
            "the tainted overload claims taint on its return",
        )
        assertEquals(
            true to false,
            opinions.opinion("fixtures.Msg.send", stringDescriptor),
            "the constant overload has a summary that claims nothing",
        )
        assertEquals(false to false, opinions.opinion("fixtures.Msg.absent", null), "no workspace body: no opinion")
    }

    /**
     * A later review. The deps tier answers a name-keyed lookup with
     * the JOIN of every overload of that name, and the join is a may-union
     * — sound for every field that is a SET of effects. `sourceReturns` is
     * not one: its value is a witness PATH, which `recordSourceReturn`
     * prepends verbatim to the published slice's trace. Unioning two paths
     * (`(a + b).distinct().sorted()`, as the join shipped) fabricates a
     * walk out of sites interleaved from two different bodies and orders it
     * by site id — evidence for an execution that cannot happen.
     *
     * A witness can only be CHOSEN, by the rule the summariser already uses
     * when one body offers several: shortest, lexicographic tie-break. So
     * the joined path must be, exactly, one of the two inputs.
     */
    @Test
    fun joiningTwoOverloadsChoosesAWitnessPathAndNeverInventsOne() {
        val a = summaryWithSourceReturn(stringDescriptor, listOf(11, 12, 13))
        val b = summaryWithSourceReturn(userDescriptor, listOf(20, 21))
        for ((left, right) in listOf(a to b, b to a)) {
            val joined = left.join(right).sourceReturns.getValue("untrusted-input")
            assertTrue(
                joined == listOf(11, 12, 13) || joined == listOf(20, 21),
                "the joined witness must BE one of the two real paths, not a blend of both: $joined",
            )
            assertEquals(listOf(20, 21), joined, "and the choice is the shortest, deterministically")
        }
    }

    /**
     * `join` must be IDEMPOTENT: the summariser joins each member's previous
     * summary every round once an SCC is slow to settle, and a join that
     * appended its sink effects instead of uniting them published one flow
     * 30 times (layered-app) and kept `sameAs` false forever (atom-tools#95).
     */
    @Test
    fun `join is idempotent on sink effects`() {
        val effect = SummarySinkEffect(
            paramIndex = 0, paramPath = "", sinkSite = 7, sinkCalleeFqn = "java.lang.Runtime.exec",
            sinkCategory = "process-exec", sinkSeverity = "high", sinkArgumentIndex = 0, sinkAccessPath = "",
            path = listOf(1, 7), elided = false,
        )
        val longer = effect.copy(path = listOf(1, 3, 7))
        val s = FunctionSummary(
            function = overload("(Ljava/lang/String;)V", KirReturn("%0")),
            paramToReturn = emptySet(), paramToParam = emptyMap(), paramFieldWrites = emptyMap(),
            receiverWrites = emptyMap(), sinkEffects = listOf(effect), sourceReturns = emptyMap(),
            sanitizes = emptySet(), invokedParams = emptySet(), origin = SummaryOrigin.COMPUTED,
        )
        val again = s.join(s).join(s)
        assertEquals(listOf(effect), again.sinkEffects)
        assertTrue(again.sameAs(s))
        val withLonger = FunctionSummary(
            function = s.function, paramToReturn = emptySet(), paramToParam = emptyMap(), paramFieldWrites = emptyMap(),
            receiverWrites = emptyMap(), sinkEffects = listOf(longer), sourceReturns = emptyMap(),
            sanitizes = emptySet(), invokedParams = emptySet(), origin = SummaryOrigin.COMPUTED,
        )
        assertEquals(listOf(effect), s.join(withLonger).sinkEffects, "one effect, the shortest witness")
    }

    private fun summaryWithSourceReturn(descriptor: String, path: List<Int>) = FunctionSummary(
        function = overload(descriptor, KirReturn("%0")),
        paramToReturn = emptySet(),
        paramToParam = emptyMap(),
        paramFieldWrites = emptyMap(),
        receiverWrites = emptyMap(),
        sinkEffects = emptyList(),
        sourceReturns = mapOf("untrusted-input" to path),
        sanitizes = emptySet(),
        invokedParams = emptySet(),
        origin = SummaryOrigin.BYTECODE,
    )
}
