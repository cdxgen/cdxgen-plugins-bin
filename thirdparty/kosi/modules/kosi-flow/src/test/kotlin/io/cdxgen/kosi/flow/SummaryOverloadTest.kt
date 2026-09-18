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

/**
 * P22 §1, the R133 shape at the SUMMARY layer: two real overloads share one
 * canonical name and differ in body. The call sites carry descriptors, so
 * each must meet its OWN overload's summary — until P22 the summary table
 * was keyed by name alone, `associateBy` kept the overload whose descriptor
 * sorts last (here the constant one), and the tainted overload's call site
 * applied the namesake's empty summary: a MISSED flow, the unsound
 * direction. The test also pins the P22 §0 projection the depth report's
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

        // R133's assertion shape: the verdict for one overload must not
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
}
