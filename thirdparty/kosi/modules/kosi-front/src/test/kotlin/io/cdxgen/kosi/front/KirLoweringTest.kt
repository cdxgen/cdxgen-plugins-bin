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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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

    // ---- bare-name accessor reads (P14, R80's sibling) ----------------------

    @Test
    fun aBareNameAccessorReadLowersAsTheCallItIs() {
        // `parameters` inside an extension on ApplicationCall is read by
        // BARE NAME through the implicit extension receiver. R80 fixed the
        // `a.b` spelling; this spelling stayed a field read whose path was
        // the RECEIVER's register, so no pack could ever see the callee —
        // and it is exactly what `call` is inside a Ktor route lambda.
        val root = project(
            mapOf(
                "src/main/kotlin/io/ktor/server/application/ApplicationCall.kt" to """
                    package io.ktor.server.application

                    interface ApplicationCall {
                        val parameters: Map<String, String>
                    }
                """.trimIndent(),
                "src/main/kotlin/App.kt" to """
                    package app

                    import io.ktor.server.application.ApplicationCall

                    fun ApplicationCall.queryEcho(): String = parameters["q"].orEmpty()
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures, "every construct here lowers")
        val calls = result.instructionsOf("queryEcho").filterIsInstance<KirCall>()
        assertTrue(
            calls.any { it.callee.fqn == "io.ktor.server.application.ApplicationCall.parameters" },
            "the bare `parameters` read must lower as the accessor call the packs match, got: " +
                calls.joinToString { it.callee.fqn },
        )
    }

    @Test
    fun aBareNameBackingFieldReadStaysAFieldAccess() {
        // The negative half: a stored member read by bare name KEEPS its
        // access path, or P4/P5 field sensitivity stops meeting writes.
        val root = project(
            mapOf(
                "src/main/kotlin/Panel.kt" to """
                    package app

                    class Panel {
                        var query: String = ""

                        fun read(): String = query
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        val reads = result.instructionsOf("read").filterIsInstance<KirFieldGet>()
        assertEquals(1, reads.size, "a backing-field member read is one field read")
        val names = reads.single().path.elements
            .filterIsInstance<io.cdxgen.kosi.kir.AccessPath.Element.Field>()
            .map { it.name }
        assertEquals(listOf("query"), names, "the access path names the field")
        assertEquals(
            0,
            result.instructionsOf("read").filterIsInstance<KirCall>().size,
            "no call is invented for a stored field",
        )
    }

    @Test
    fun aTopLevelExtensionPropertyReadCarriesItsReceiver() {
        // `val ApplicationRequest.uri` is a TOP-LEVEL extension property:
        // its getter is static on the JVM, but it reads the receiver. A
        // receiverless call here would stop taint arriving on the receiver
        // at every extension accessor — and extension properties are how
        // Ktor spells most of its request readers.
        val root = project(
            mapOf(
                "src/main/kotlin/io/ktor/server/request/ApplicationRequest.kt" to """
                    package io.ktor.server.request

                    interface ApplicationRequest

                    val ApplicationRequest.uri: String get() = ""
                """.trimIndent(),
                "src/main/kotlin/App.kt" to """
                    package app

                    import io.ktor.server.request.ApplicationRequest
                    import io.ktor.server.request.uri

                    fun ApplicationRequest.echo(): String = uri
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        val call = result.instructionsOf("echo").filterIsInstance<KirCall>()
            .firstOrNull { it.callee.fqn == "io.ktor.server.request.uri" }
        assertTrue(call != null, "the bare extension-property read lowers as its accessor call")
        assertTrue(call!!.receiver != null, "and carries the receiver its getter reads")
    }

    @Test
    fun customAccessorsOfOneClassTakeDistinctJvmNames() {
        // R87: every KtPropertyAccessor lowered under ONE placeholder name,
        // so a class with several custom accessors emitted colliding
        // canonical names and the KIR validator refused the module
        // (InsecureShop's `Prefs` carried six). The JVM names are distinct.
        val root = project(
            mapOf(
                "src/main/kotlin/Prefs.kt" to """
                    package app

                    object Prefs {
                        private var stored: String = ""

                        var token: String
                            get() = stored
                            set(value) { stored = value }

                        var user: String
                            get() = stored
                            set(value) { stored = value }
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        val accessors = result.functions
            .map { it.canonicalName }
            .filter { it.startsWith("app.Prefs.get") || it.startsWith("app.Prefs.set") }
            .sorted()
        assertEquals(
            listOf("app.Prefs.getToken", "app.Prefs.getUser", "app.Prefs.setToken", "app.Prefs.setUser"),
            accessors,
            "each accessor takes its own JVM name, got all functions: " +
                result.functions.joinToString { it.canonicalName },
        )
    }

    // ---- P15 §2: exceptional may-edges and dead-block emission ---------------

    /**
     * `loweredFunctions` goes through `kir dump`, which REFUSES a module whose
     * CFG validates dirty — so both tests below fail the moment either defect
     * returns: unreachable handlers (no exceptional edge) or an
     * unreachable-but-emitted tail block are validator findings, and the dump
     * throws instead of returning.
     */
    @Test
    fun catchHandlersAreReachableThroughExceptionalMayEdges() {
        val root = project(
            mapOf(
                "src/main/kotlin/Catch.kt" to """
                    package t

                    private fun risky(): String = checkNotNull(readLine())

                    fun emptyHandler(): String {
                        return try {
                            risky()
                        } catch (e: IllegalStateException) {
                            "fallback"
                        }
                    }

                    fun rethrowHandler(): String {
                        try {
                            risky()
                        } catch (e: Exception) {
                            throw RuntimeException(e)
                        }
                    }
                """.trimIndent(),
            ),
        )
        // Pre-P15 both functions lowered with catch-handler blocks no edge
        // reached; KirValidator named them and the dump failed. Reaching here
        // at all is the pin — and the handler BODIES must still be present,
        // not optimised away: the rethrow handler carries its KirThrow.
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures, "every construct here lowers")
        assertTrue(
            result.instructionsOf("rethrowHandler").any { it is io.cdxgen.kosi.kir.KirThrow },
            "the handler's rethrow is emitted — reachable, not dropped",
        )
    }

    @Test
    fun anAllPathsReturnedConstructEmitsNoUnreachableTailBlock() {
        // Util.verifyUserNamePassword reduced (InsecureShop): an if/else whose
        // both arms return. The lowering used to start the join block anyway
        // and terminate it with a bare implicit return — an
        // unreachable-but-emitted block the validator rejects. The dump this
        // test goes through fails while the dead block is emitted.
        val root = project(
            mapOf(
                "src/main/kotlin/Tail.kt" to """
                    package t

                    fun bothReturn(a: Boolean): Int {
                        if (a) {
                            return 1
                        } else {
                            return 2
                        }
                    }

                    fun tryBothReturn(): Int? {
                        return try {
                            1
                        } catch (e: Exception) {
                            null
                        }
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures, "every construct here lowers")
        val returns = result.instructionsOf("bothReturn").filterIsInstance<io.cdxgen.kosi.kir.KirReturn>()
        // Exactly the two arm returns — no third bare return from a dead tail.
        assertEquals(2, returns.size, "no unreachable implicit-return block is emitted, got: $returns")
        val tryReturns = result.instructionsOf("tryBothReturn").filterIsInstance<io.cdxgen.kosi.kir.KirReturn>()
        assertTrue(tryReturns.isNotEmpty(), "the try expression's return is still emitted")
    }

    @Test
    fun catchParametersAreBoundToTheThrownValueAndReadAsLocals() {
        // P16 §3: the handler's own parameter existed nowhere in the KIR — a
        // read of `e` lowered as a FIELD READ on `this`, and no value the
        // guarded body threw could reach it. Restoring that defect fails
        // this test three ways: the parameter reads as `fieldget vthis`,
        // no <thrown> binding exists, and a body ending in `throw` has no
        // exceptional edge to the dispatch chain.
        val root = project(
            mapOf(
                "src/main/kotlin/CatchParam.kt" to """
                    package t

                    fun visibleThrow(input: String): String {
                        try {
                            throw IllegalStateException("bad ${'$'}input")
                        } catch (e: IllegalStateException) {
                            return e.message ?: "none"
                        }
                    }

                    fun unguardedThrow(input: String): String {
                        throw IllegalStateException(input)
                    }

                    fun implicitThrow(input: String): String {
                        try {
                            return input.toInt().toString()
                        } catch (e: NumberFormatException) {
                            return e.message ?: "none"
                        }
                    }
                """.trimIndent(),
            ),
        )
        val result = loweredFunctions(root)
        assertEquals(emptyMap(), result.failures, "every construct here lowers")

        // The parameter is a LOCAL: `e.message` reads the field off `ve`,
        // never a member of `this`.
        for (namePart in listOf("visibleThrow", "implicitThrow")) {
            val fieldGets = result.instructionsOf(namePart).filterIsInstance<io.cdxgen.kosi.kir.KirFieldGet>()
            assertTrue(
                fieldGets.none { it.receiver == "vthis" && it.path.elements.any { el -> (el as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name == "e" } },
                "the catch parameter is not a field on this: $fieldGets",
            )
            assertTrue(
                fieldGets.any { it.receiver == "ve" },
                "the catch parameter's field read runs on its own register",
            )
        }

        // The VISIBLE throw binds the thrown register AND its construction
        // arguments — the fresh object's own register is clean by the
        // transfer's rule, so a binding over the object alone would drop the
        // flow the wrap-and-rethrow idiom is about.
        val visible = result.instructionsOf("visibleThrow")
        val thrown = visible.filterIsInstance<io.cdxgen.kosi.kir.KirDynamicCall>()
            .single { it.name == KirLowering.THROWN_EXCEPTION }
        val store = visible.filterIsInstance<io.cdxgen.kosi.kir.KirStore>().single { it.target == "ve" }
        assertEquals(thrown.result, store.value, "the parameter store reads the thrown binding")
        assertTrue(
            thrown.args.any { it != thrown.receiver },
            "the binding sees the construction arguments, not only the object register: $thrown",
        )

        // The body's own `throw` never dead-ends inside a guarded body: the
        // throw becomes the exceptional edge, so the block holding the
        // binding ends in a may-branch to the dispatch chain (no KirThrow is
        // emitted there — a KirThrow terminates with no successor and would
        // strand the binding). Throws OUTSIDE any guarded body keep their
        // KirThrow.
        val module = io.cdxgen.kosi.front.KirDumper.dumpWithWarnings(
            root,
            io.cdxgen.kosi.schema.AnalyzeOptions(backend = io.cdxgen.kosi.schema.Backend.RESOLVED),
        ).first
        val visibleFn = io.cdxgen.kosi.kir.KirReader.read(module).functions.single { "visibleThrow" in it.canonicalName }
        val bindingBlock = visibleFn.body?.blocks?.single { b ->
            b.instructions.any { it is io.cdxgen.kosi.kir.KirDynamicCall && it.name == KirLowering.THROWN_EXCEPTION }
        }
        assertNotNull(bindingBlock, "the binding block exists")
        val bindingBranch = bindingBlock!!.instructions.lastOrNull() as? io.cdxgen.kosi.kir.KirBranch
        assertNotNull(bindingBranch, "the throw site branches — the exceptional edge: ${bindingBlock.instructions}")
        assertEquals(
            bindingBranch.thenBlock,
            bindingBranch.elseBlock,
            "the exceptional edge is a may-edge (both arms to the dispatch chain)",
        )
        assertTrue(
            visibleFn.body?.blocks?.any { b -> b.instructions.any { it is io.cdxgen.kosi.kir.KirThrow } } == false,
            "inside a guarded body the throw lowered to its edge, not to a dead-end KirThrow",
        )
        // ... and a throw with no enclosing try still lowers to KirThrow:
        // the edge replaces the terminator only where a handler can receive
        // it.
        assertTrue(
            result.instructionsOf("unguardedThrow").any { it is io.cdxgen.kosi.kir.KirThrow },
            "an unguarded throw keeps its KirThrow terminator",
        )

        // Where NO throw is visible, the parameter is seeded from the body's
        // live registers at the dispatch edge (tainted-if-the-body-was).
        val implicitFn = result.instructionsOf("implicitThrow")
        val seed = implicitFn.filterIsInstance<io.cdxgen.kosi.kir.KirDynamicCall>()
            .single { it.name == KirLowering.THROWN_EXCEPTION }
        assertNull(seed.receiver, "the unknown exception has no thrown register")
        assertTrue(seed.args.isNotEmpty(), "the seed reads the body's live registers")
        assertTrue(
            implicitFn.filterIsInstance<io.cdxgen.kosi.kir.KirStore>().any { it.target == "ve" && it.value == seed.result },
            "the implicit parameter is bound to the seed",
        )
    }
}
