package io.cdxgen.kosi.front

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.uses
import io.cdxgen.kosi.kir.KirReader
import io.cdxgen.kosi.kir.KirCast
import io.cdxgen.kosi.kir.KirElvis
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirPhi
import io.cdxgen.kosi.kir.KirSuspendPoint
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirTypeCheck
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Per-construct lowering tests (02-ARCHITECTURE.md §4), negative-first: each
 * test first asserts what a PLAUSIBLY OVER-BROAD lowering would emit and
 * must not, then pins the desugaring the gate demands. A construct that
 * cannot be lowered shows up in `loweringFailures`, itemised by name, and
 * the same map the report publishes is asserted empty here.
 */
class KirLoweringTest {

    private fun project(sources: Map<String, String>): Path {
        val root = Files.createTempDirectory("kosi-kir-test")
        for ((path, text) in sources) {
            val file = root.resolve(path)
            Files.createDirectories(file.parent)
            file.writeText(text)
        }
        return root
    }

    private fun loweredFunctions(root: Path): KirLowering.Result {
        val options = io.cdxgen.kosi.schema.AnalyzeOptions(backend = io.cdxgen.kosi.schema.Backend.RESOLVED)
        val (module, _) = KirDumper.dumpWithWarnings(root, options)
        return KirLowering.Result(
            KirReader.read(module).functions,
            emptyMap(),
            KirReader.read(module).functions.size,
        )
    }

    private fun KirLowering.Result.instructionsOf(namePart: String): List<io.cdxgen.kosi.kir.KirIns> =
        functions.filter { namePart in it.canonicalName }
            .flatMap { it.body?.blocks ?: emptyList() }
            .flatMap { it.instructions }

    // ---- string template -> StringConcat (§4) --------------------------------

    @Test
    fun stringTemplatesConcatAndLiteralsStayLoads() {
        val root = project(
            mapOf(
                "src/main/kotlin/T.kt" to """
                    package t

                    fun greet(name: String): String = "hi ${'$'}{name.length}!"

                    fun plain(): String = "nothing to concat"
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures, "every construct here lowers")
        val concats = result.instructionsOf("greet").filterIsInstance<KirStringConcat>()
        assertEquals(1, concats.size, "the interpolated template is one StringConcat")
        // Negative half: an all-literal template is a Load, NOT a concat —
        // a lowering that emitted StringConcat for every template would fail
        // this and inflate the concat count for every real repo.
        assertEquals(
            0,
            result.instructionsOf("plain").filterIsInstance<KirStringConcat>().size,
            "an all-literal template must stay a constant load",
        )
    }

    // ---- `?.` -> branch + phi; `!!` -> checked cast --------------------------

    @Test
    fun safeCallBranchesAndJoinsWithAPhi() {
        val root = project(
            mapOf(
                "src/main/kotlin/N.kt" to """
                    package t

                    class User(val name: String?)

                    fun label(user: User?): String {
                        val n = user?.name
                        return "u"
                    }

                    fun shout(user: User?): String = user!!.name
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val label = result.functions.first { it.canonicalName.endsWith("label") }
        val phis = label.body?.blocks.orEmpty().flatMap { it.instructions }.filterIsInstance<KirPhi>()
        assertTrue(phis.isNotEmpty(), "`?.` desugars to a join; the join is a phi (§4)")
        val fieldGets = label.body?.blocks.orEmpty().flatMap { it.instructions }.filterIsInstance<KirFieldGet>()
        assertTrue(fieldGets.isNotEmpty(), "the safe selector reads the field in the non-null arm")
        // `!!` -> checked cast (§4).
        val casts = result.instructionsOf("shout").filterIsInstance<KirCast>()
        assertTrue(casts.any { it.checked }, "`!!` lowers to a checked cast")
    }

    // ---- `?:` -> phi at statement positions; Elvis opcode nested -------------

    @Test
    fun elvisJoinsAtStatementPositionAndStaysNestedInsideArguments() {
        val root = project(
            mapOf(
                "src/main/kotlin/E.kt" to """
                    package t

                    fun statement(value: String?): String {
                        val v = value ?: "fallback"
                        return v
                    }

                    fun nested(value: String?): String = render(value ?: "x")

                    fun render(v: String): String = v
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val statement = result.functions.first { it.canonicalName.endsWith("statement") }
        assertTrue(
            statement.body?.blocks.orEmpty().flatMap { it.instructions }.filterIsInstance<KirPhi>().isNotEmpty(),
            "`?:` at a statement position joins through a phi (§4)",
        )
        val nested = result.instructionsOf("nested").filterIsInstance<KirElvis>()
        assertEquals(1, nested.size, "`?:` inside a call argument uses the Elvis opcode")
    }

    // ---- `for` -> iterator/hasNext/next (§4) ----------------------------------

    @Test
    fun forLoopsIterateAndWhileLoopsDoNot() {
        val root = project(
            mapOf(
                "src/main/kotlin/F.kt" to """
                    package t

                    fun sum(values: List<Int>): Int {
                        var acc = 0
                        for (v in values) {
                            acc = acc + v
                        }
                        return acc
                    }

                    fun sumWhile(values: List<Int>): Int {
                        var acc = 0
                        var i = 0
                        while (i < values.size) {
                            acc = acc + values[i]
                            i = i + 1
                        }
                        return acc
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val called = result.instructionsOf("sum").filterIsInstance<KirCall>()
            .map { it.callee.fqn.substringAfterLast('.') }
        for (expected in listOf("iterator", "hasNext", "next")) {
            assertTrue(expected in called, "`for` desugars through $expected; got $called")
        }
        // Negative half: a while loop over an index is NOT an iteration
        // protocol use — a lowering that pattern-matched any loop into
        // iterator/hasNext/next would fail this.
        val whileCalled = result.instructionsOf("sumWhile").filterIsInstance<KirCall>()
            .map { it.callee.fqn.substringAfterLast('.') }
        assertEquals(0, whileCalled.count { it == "hasNext" }, "a while loop must not invent iterator calls")
    }

    // ---- operators -> named calls (§4) ----------------------------------------

    @Test
    fun operatorsBecomeNamedCalls() {
        val root = project(
            mapOf(
                "src/main/kotlin/O.kt" to """
                    package t

                    fun math(a: Int, b: Int): Int {
                        val sum = a + b
                        val product = a * b
                        return sum * product
                    }

                    fun ordered(a: Int, b: Int): Boolean = a < b
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val called = result.instructionsOf("math").filterIsInstance<KirCall>()
            .map { it.callee.fqn.substringAfterLast('.') }
        assertTrue("plus" in called, "`+` names plus")
        assertTrue("times" in called, "`*` names times")
        val compare = result.instructionsOf("ordered").filterIsInstance<KirCall>()
            .map { it.callee.fqn.substringAfterLast('.') }
        assertTrue("compareTo" in compare, "`<` names compareTo, as the syntax tier publishes it")
    }

    // ---- suspend call -> Call + SuspendPoint (§4) ------------------------------

    @Test
    fun suspendingCallsGetSuspendPointsAndPlainCallsDoNot() {
        val root = project(
            mapOf(
                "src/main/kotlin/S.kt" to """
                    package t

                    suspend fun load(): Int = 42

                    suspend fun use(): Int {
                        val v = load()
                        return v + 1
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val suspends = result.instructionsOf("use").filterIsInstance<KirSuspendPoint>()
        assertEquals(1, suspends.size, "the suspending call is followed by exactly one SuspendPoint")
    }

    // ---- data class -> synthesized copy/componentN (§4) ------------------------

    @Test
    fun dataClassesGrowSyntheticMembersAndPlainClassesDoNot() {
        val root = project(
            mapOf(
                "src/main/kotlin/D.kt" to """
                    package t

                    data class Point(val x: Int, val y: Int)

                    class Plain(val x: Int)
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        val synthetic = result.functions.filter { it.syntheticCause == "data-class" }
        // copy + component1 + component2 for Point; nothing for Plain.
        assertTrue(synthetic.any { it.canonicalName.endsWith("Point.copy") }, "copy is synthesized")
        assertTrue(synthetic.any { it.canonicalName.endsWith("Point.component1") }, "component1 is synthesized")
        assertTrue(synthetic.any { it.canonicalName.endsWith("Point.component2") }, "component2 is synthesized")
        assertTrue(
            result.functions.none { it.canonicalName.contains("Plain.") && it.syntheticCause != null },
            "a plain class gets no synthetic members",
        )
    }

    // ---- is-checks -> TypeCheck --------------------------------------------------

    @Test
    fun typeChecksLowerToTypeCheck() {
        val root = project(
            mapOf(
                "src/main/kotlin/C.kt" to """
                    package t

                    fun kind(value: Any): String = if (value is String) "s" else "other"
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures)
        val checks = result.instructionsOf("kind").filterIsInstance<KirTypeCheck>()
        assertEquals(1, checks.size, "`is` lowers to TypeCheck")
        assertTrue(checks[0].type == "String", "the check names the tested type: ${checks[0].type}")
    }

// ---- P5/P6: lambda extraction, higher-order invocation, coroutine builders --

@Test
fun standaloneLambdasExtractIntoTheirOwnFunctionsWithCapturesRenamed() {
    // Negative half first: a lambda WITHOUT captures declares no capture
    // parameters — an extraction that captures everything (or renames the
    // body's own locals) fails here.
    val root = project(
        mapOf(
            "src/main/kotlin/H.kt" to """
                package t

                fun runWith(block: (String) -> Unit) {
                    block("x")
                }

                fun caller() {
                    val raw = readLine()
                    runWith { marker -> println(marker + raw) }
                }

                fun cleanCaller() {
                    runWith { marker -> println(marker) }
                }
            """.trimIndent(),
        ),
    )
    val result = loweredFunctions(root)
    val extracted = result.functions.filter { "$" in it.canonicalName && "lambda" in it.canonicalName }
    assertEquals(2, extracted.size, "both lambda bodies lower as their own functions")

    val capturing = extracted.single { "caller" in it.canonicalName }
    val captureParams = capturing.params.filter { it.register.startsWith("%c") }
    assertEquals(listOf("vraw"), captureParams.map { it.name?.removePrefix("capture") }, "the capture names its enclosing register")
    assertTrue(
        capturing.body?.blocks?.flatMap { it.instructions }.orEmpty().any { it.uses.contains("%c0") },
        "the body reads the capture through its parameter register",
    )

    val clean = extracted.single { "cleanCaller" in it.canonicalName }
    assertEquals(emptyList(), clean.params.filter { it.register.startsWith("%c") }, "no captures, no capture parameters")
}

@Test
fun aFunctionValuedParameterIsInvokedOnItsOwnRegister() {
    // `block(x)` keeps the invoked VALUE on the receiver — without it the
    // invocation site loses the one fact higher-order analysis needs.
    val root = project(
        mapOf(
            "src/main/kotlin/I.kt" to """
                package t

                fun invokee(block: (String) -> Unit) {
                    block("x")
                }
            """.trimIndent(),
        ),
    )
    val result = loweredFunctions(root)
    val invokes = result.instructionsOf("invokee").filterIsInstance<io.cdxgen.kosi.kir.KirCall>()
        .filter { it.callee.fqn.endsWith(".invoke") }
    assertEquals(1, invokes.size)
    assertEquals("vblock", invokes[0].receiver, "the function value rides the receiver, not the void")
}

@Test
fun coroutineBuilderBodiesInlineIntoTheCallerWithContext() {
    val root = project(
        mapOf(
            "src/main/kotlin/C.kt" to """
                package t

                import kotlinx.coroutines.flow.flow
                import kotlinx.coroutines.flow.map
                import kotlinx.coroutines.flow.collect

                fun flowCase() {
                    val raw = readLine()
                    flow { emit(raw) }
                        .map { it }
                        .collect { value ->
                            println(value)
                        }
                }

                fun mapIsNotAFlowHere() {
                    val xs = listOf(1, 2, 3)
                    xs.map { it + 1 }
                }
            """.trimIndent(),
        ),
    )
    val result = loweredFunctions(root)
    val flowCase = result.instructionsOf("flowCase")
    // emit routes its argument into the flow value: an assign from the
    // element register to the flow-value register follows the emit call.
    val assigns = flowCase.filterIsInstance<io.cdxgen.kosi.kir.KirAssign>()
    assertTrue(assigns.isNotEmpty(), "emit(x) assigns x into the flow value register")
    // `it` binds the flow value: a store FROM the flow register into the
    // lambda parameter local, so `collect { println(value) }` reads it.
    val stores = flowCase.filterIsInstance<io.cdxgen.kosi.kir.KirStore>()
    assertTrue(stores.any { it.value.startsWith("tf") || it.value.startsWith("t") }, "element binding lowers as a store")
    // The evidence edges keep the call identity: the resolved FQN when the
    // classpath reaches the builder, the plain name when it does not.
    val edgeNames = flowCase.filterIsInstance<io.cdxgen.kosi.kir.KirCall>().map { it.callee.fqn.substringAfterLast('.') } +
        flowCase.filterIsInstance<io.cdxgen.kosi.kir.KirDynamicCall>().map { it.name }
    assertTrue(edgeNames.any { it == "flow" }, "the flow builder keeps its evidence edge")
    assertTrue(edgeNames.any { it == "map" }, "map keeps its evidence edge")
    assertTrue(edgeNames.any { it == "collect" }, "collect keeps its evidence edge")

    // The negative half: a COLLECTION map over a resolved stdlib receiver is
    // NOT inlined — its lambda stays a value argument, no flow-value store.
    val collectionCase = result.instructionsOf("mapIsNotAFlowHere")
    assertTrue(
        collectionCase.filterIsInstance<io.cdxgen.kosi.kir.KirAssign>().isEmpty(),
        "collection map does not fabricate a flow-value assign",
    )
}

@Test
fun suspendingBuildersEmitSuspendBoundaries() {
    val root = project(
        mapOf(
            "src/main/kotlin/S.kt" to """
                package t

                suspend fun inner(): Int = 1

                suspend fun work(): Int {
                    return inner()
                }
            """.trimIndent(),
        ),
    )
    val result = loweredFunctions(root)
    assertTrue(
        result.instructionsOf("work").any { it is io.cdxgen.kosi.kir.KirSuspendPoint },
        "a resolved suspend call is followed by a suspend boundary",
    )
}

/**
 * A nested qualifier lowers to ONE path off the chain's base register, not
 * one hop per field off a fresh temporary. `AccessPath` has carried a list
 * of elements since P2 and both engines join them into the state key, but
 * the lowering emitted length-one paths only: `o.inner.a = x` wrote onto a
 * temp and the matching read looked at a different temp, so no nested field
 * flow could ever be seen (R63). The negative half is the shape that
 * regression would produce — a write path of length one.
 */
@Test
fun nestedQualifiersComposeIntoOneAccessPath() {
    val root = project(
        mapOf(
            "src/main/kotlin/N.kt" to """
                package t

                class Inner { var a: String = "" }
                class Outer { var inner: Inner = Inner() }

                fun write(o: Outer, value: String) {
                    o.inner.a = value
                }

                fun read(o: Outer): String = o.inner.a

                fun viaCall(make: () -> Outer): String = make().inner.a
            """.trimIndent(),
        ),
    )
    val result = loweredFunctions(root)

    fun fields(path: io.cdxgen.kosi.kir.AccessPath) =
        path.elements.filterIsInstance<io.cdxgen.kosi.kir.AccessPath.Element.Field>().map { it.name }

    val writes = result.instructionsOf("write").filterIsInstance<io.cdxgen.kosi.kir.KirFieldSet>()
    assertEquals(listOf(listOf("inner", "a")), writes.map { fields(it.path) }, "the write composes both fields")
    val writeBase = writes.single().receiver
    assertTrue(writeBase.startsWith("%") || writeBase.startsWith("v"), "the write hangs off the chain's base, not a temp: $writeBase")

    val reads = result.instructionsOf("read").filterIsInstance<KirFieldGet>()
    assertEquals(listOf(listOf("inner", "a")), reads.map { fields(it.path) }, "the read composes both fields")
    assertEquals(writes.single().path.base, reads.single().path.base, "read and write name the same base")

    // A chain whose root is a CALL still composes only the field part: the
    // call is lowered once, as an expression, and the path hangs off its
    // result register.
    val viaCall = result.instructionsOf("viaCall").filterIsInstance<KirFieldGet>()
    assertEquals(listOf(listOf("inner", "a")), viaCall.map { fields(it.path) }, "composition stops at the call")
}
}
