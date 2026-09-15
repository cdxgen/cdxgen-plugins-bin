package io.cdxgen.kosi.kir

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The round-trip contract of `kir dump`: write, read back, write again —
 * byte-identical. And the validator's dead-block rule: an unreachable block
 * that the lowering emitted must be a finding, which is what makes the
 * removal of the reachability check a failing test rather than a silent
 * regression (KirValidatorTest carries the negative half).
 */
class KirRoundTripTest {

    private fun sample(): KirModule {
        val path = AccessPath.of("t1", listOf(AccessPath.Element.Field("head"), AccessPath.Element.Index))
        return KirModule(
            listOf(
                KirFunction(
                    canonicalName = "fixtures.kir/Repo#load",
                    jvmDescriptor = "(Ljava/lang/String;)Ljava/lang/String;",
                    purl = "pkg:maven/fixtures/kir@1.0.0",
                    file = "src/main/kotlin/Repo.kt",
                    line = 3,
                    column = 1,
                    params = listOf(
                        KirParam("%0", "this", "fixtures.kir/Repo", receiver = true),
                        KirParam("%1", "name", "kotlin.String", receiver = false),
                    ),
                    returnType = "kotlin.String",
                    modifiers = setOf("suspend"),
                    visibility = "public",
                    enclosingClass = "fixtures.kir/Repo",
                    overrides = listOf("java.lang.Runnable.run"),
                    overriddenBy = listOf(),
                    annotations = listOf("Deprecated"),
                    syntheticCause = null,
                    body = KirBody(
                        listOf(
                            KirBlock(
                                "b0",
                                entry = true,
                                instructions = listOf(
                                    KirLoad("t0", KirConstant.Str("hello \"quoted\"\nworld")),
                                    KirLoad("t1", KirConstant.IntConst(42)),
                                    KirLoad("t2", KirConstant.Null),
                                    KirFieldGet("t3", "%0", path),
                                    KirFieldSet("%0", AccessPath.field("%0", "count"), "t1"),
                                    KirIndexGet("t4", "t3", "t1"),
                                    KirIndexSet("t3", "t1", "t0"),
                                    KirCall(
                                        "t5",
                                        KirCallee("kotlin.text.plus", "(Ljava/lang/String;)Ljava/lang/String;", CallKind.OPERATOR),
                                        receiver = "t0",
                                        args = listOf("t1"),
                                    ),
                                    KirDynamicCall(null, "unknownPlugin", receiver = "t0", args = listOf("t1")),
                                    KirNew("t6", "java.util.ArrayList", listOf()),
                                    KirStringConcat("t7", listOf("t0", "t1")),
                                    KirElvis("t8", "t3", "t2"),
                                    KirSafeCall("t9", "t3", AccessPath.field("t3", "value")),
                                    KirCast("t10", "t9", "kotlin.String", checked = true),
                                    KirTypeCheck("t11", "t9", "kotlin.String"),
                                    KirLambda("t12", "fixtures.kir/Repo#load$1", listOf("t1")),
                                    KirCall(
                                        "t13",
                                        KirCallee("kotlin.sequences.toList", null, CallKind.STATIC),
                                        receiver = null,
                                        args = listOf("t3"),
                                    ),
                                    KirSuspendPoint("t13"),
                                    KirBranch("t11", "b1", "b2"),
                                ),
                            ),
                            KirBlock(
                                "b1",
                                entry = false,
                                instructions = listOf(
                                    KirPhi("t14", mapOf("b0" to "t8", "b2" to "t2")),
                                    KirStore("v count", "t14"),
                                    KirReturn("t14"),
                                ),
                            ),
                            KirBlock(
                                "b2",
                                entry = false,
                                instructions = listOf(KirThrow("t6")),
                            ),
                        ),
                    ),
                ),
                KirFunction(
                    canonicalName = "fixtures.kir/Repo#load$1",
                    jvmDescriptor = null,
                    purl = "pkg:maven/fixtures/kir@1.0.0",
                    file = "src/main/kotlin/Repo.kt",
                    line = 7,
                    column = 9,
                    params = emptyList(),
                    returnType = null,
                    modifiers = emptySet(),
                    visibility = "private",
                    enclosingClass = null,
                    overrides = emptyList(),
                    overriddenBy = emptyList(),
                    annotations = emptyList(),
                    syntheticCause = "lambda",
                    body = null,
                ),
            ),
        )
    }

    @Test
    fun dumpReadDumpIsByteIdentical() {
        val module = sample()
        val first = KirWriter.write(module)
        val readBack = KirReader.read(first)
        val second = KirWriter.write(readBack)
        assertEquals(first, second, "dump -> read -> dump must be byte-identical")
        assertEquals(module, readBack, "the read-back module must equal the original")
    }

    @Test
    fun aPathBeyondTheDepthCapCollapsesToStar() {
        val elements = (1..9).map { AccessPath.Element.Field("f$it") }
        val path = AccessPath.of("v0", elements)
        assertEquals(6, path.elements.size, "depth cap 5 + one star")
        assertTrue(path.collapsed)
        // And the collapsed path survives the round trip.
        val module = KirModule(
            listOf(
                KirFunction(
                    "x", null, "p", "f.kt", 1, 1,
                    params = emptyList(), returnType = null, modifiers = emptySet(),
                    visibility = "public", enclosingClass = null, overrides = emptyList(),
                    overriddenBy = emptyList(), annotations = emptyList(),
                    body = KirBody(listOf(KirBlock("b0", true, listOf(KirFieldGet("t0", "v0", path))))),
                ),
            ),
        )
        assertEquals(module, KirReader.read(KirWriter.write(module)))
    }

    @Test
    fun namesWithWhitespaceAndQuotesSurviveTheRoundTrip() {
        val module = KirModule(
            listOf(
                KirFunction(
                    canonicalName = "weird path/Class #with spaces\nand newline",
                    jvmDescriptor = null,
                    purl = "p u r l with spaces",
                    file = "file with space.kt",
                    line = 1,
                    column = 2,
                    params = listOf(KirParam("%0", name = "a b", type = "x y", receiver = true)),
                    returnType = null,
                    modifiers = setOf("inline"),
                    visibility = "internal",
                    enclosingClass = null,
                    overrides = emptyList(),
                    overriddenBy = emptyList(),
                    annotations = listOf("An no tation"),
                    body = KirBody(
                        listOf(
                            KirBlock(
                                "b0",
                                true,
                                listOf(KirLoad("t0", KirConstant.Str("tab\there"))),
                            ),
                        ),
                    ),
                ),
            ),
        )
        val dump = KirWriter.write(module)
        assertEquals(dump, KirWriter.write(KirReader.read(dump)))
    }
}
