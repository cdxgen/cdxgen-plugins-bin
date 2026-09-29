package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.schema.DiagnosticCodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The static-field carrier and the import-named callee of an unresolved
 * call, pinned at KIR level with their negative halves: the fixtures
 * `static-state-carriers` and `classpathless-sinks` pin them end to end.
 */
class CarriersAndImportsTest {

    private val pack = ModelPacks.loadBuiltin()

    private val attribution = TaintEngine.Attribution(
        byAbsoluteFilePath = mapOf("/a.kt" to ("a.kt" to "module-a")),
        purlByModulePath = mapOf("module-a" to "pkg:maven/test/a"),
    )

    private val options = TaintEngine.Options(
        mode = "security",
        accessPathDepth = 5,
        maxSlices = 100,
        maxTraceNodes = 64,
        maxFunctionInstructions = 20000,
        unknownCallPropagate = true,
        skipGenerated = true,
        dispatchMode = "cha",
    )

    private fun fn(canonical: String, vararg instructions: KirIns, params: List<KirParam> = emptyList()) = KirFunction(
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

    private fun analyze(vararg functions: KirFunction) =
        TaintEngine.analyze(KirModule(functions.toList()), pack, attribution, options)

    private fun source(reg: String, line: Int) =
        KirCall(reg, KirCallee("kotlin.io.readLine", null, CallKind.STATIC), null, emptyList(), line)

    private fun exec(reg: String, line: Int) = KirCall(
        null,
        KirCallee("java.lang.ProcessBuilder", null, CallKind.CONSTRUCTOR),
        null,
        listOf(reg),
        line,
    )

    private val holder = "vstatic:test/Holder"

    private fun staticRead(result: String, field: String) = KirFieldGet(result, holder, AccessPath.field(holder, field))

    @Test
    fun aStaticFieldCarriesAStoreToAnotherFunctionsRead() {
        val store = fn(
            "test.store",
            source("t0", 2),
            KirFieldSet(holder, AccessPath.field(holder, "command"), "t0"),
            KirReturn(null),
        )
        val use = fn("test.use", staticRead("t0", "command"), exec("t0", 5), KirReturn(null))
        val slices = analyze(store, use).evidence.slices
        assertEquals(1, slices.size, "the read must see the store: ${slices.map { it.sourceName }}")
        assertEquals("static test.Holder.command written in test.store", slices.single().sourceName)
        assertEquals("test.use", slices.single().sourceFunction)
    }

    @Test
    fun aStaticFieldNobodyTaintedStaysClean() {
        val store = fn(
            "test.store",
            source("t0", 2),
            KirFieldSet(holder, AccessPath.field(holder, "command"), "t0"),
            KirReturn(null),
        )
        val use = fn("test.use", staticRead("t0", "other"), exec("t0", 5), KirReturn(null))
        assertEquals(0, analyze(store, use).evidence.slices.size, "a sibling static field carries nothing")
    }

    @Test
    fun anImportNamedCalleeIsThePacksSink() {
        val query = fn(
            "test.query",
            source("t1", 2),
            KirDynamicCall(
                null,
                "queryForList",
                receiver = "%0",
                args = listOf("t1"),
                line = 3,
                importedCallees = listOf("org.springframework.jdbc.core.JdbcTemplate.queryForList"),
            ),
            KirReturn(null),
            params = listOf(KirParam("%0", "jdbc", "JdbcTemplate", receiver = false)),
        )
        val result = analyze(query)
        assertEquals(listOf("sql-query"), result.evidence.slices.map { it.sinkCategory })
        assertTrue(
            result.evidence.diagnostics.any {
                it.code == DiagnosticCodes.CALL_IMPORT_RESOLVED &&
                    "org.springframework.jdbc.core.JdbcTemplate.queryForList (1)" in it.message
            } || result.diagnostics.any { it.code == DiagnosticCodes.CALL_IMPORT_RESOLVED },
            "the import-named callee must be reported",
        )
    }

    @Test
    fun anImportNamedCalleeThePackDoesNotNameStaysDynamicAndIsNamed() {
        val query = fn(
            "test.query",
            source("t1", 2),
            KirDynamicCall(
                "t2",
                "selectList",
                receiver = "%0",
                args = listOf("t1"),
                line = 3,
                importedCallees = listOf("org.apache.ibatis.session.SqlSession.selectList"),
            ),
            KirReturn("t2"),
            params = listOf(KirParam("%0", "session", "SqlSession", receiver = false)),
        )
        val result = analyze(query)
        assertEquals(0, result.evidence.slices.size)
        val named = (result.evidence.diagnostics + result.diagnostics).filter { it.code == DiagnosticCodes.TAINT_UNRESOLVED_CALL }
        assertTrue(named.any { "org.apache.ibatis.session.SqlSession (1)" in it.message }, "got $named")
    }
}
