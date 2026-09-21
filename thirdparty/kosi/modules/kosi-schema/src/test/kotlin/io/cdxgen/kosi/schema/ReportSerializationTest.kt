package io.cdxgen.kosi.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the serialization invariants the change-1+ engines will rely on. Both
 * tests were written after fixing real defects: options dropped three fields
 * ("every effective option", 03-SCHEMA.md), and CallGraphEdge wrote
 * candidateCount twice (a duplicate-key crash) whenever it was null.
 */
class ReportSerializationTest {

    @Test
    fun everyOptionFieldIsSerialized() {
        val w = JsonWriter()
        AnalyzeOptions().writeJson(w)
        val json = JsonReader.parse(w.render()).asObject()
        // A NULL option (the budgets when off) has no effective value to
        // echo — its absence IS the echo. Every non-null field must appear.
        val options = AnalyzeOptions()
        val missing = AnalyzeOptions::class.java.declaredFields
            .map { field ->
                val value = try {
                    field.isAccessible = true
                    field.get(options)
                } catch (_: Exception) {
                    null
                }
                field.name to value
            }
            .filterNot { (name, value) -> json.members.containsKey(name) || value == null }
            .map { (name, _) -> name }
        assertEquals(emptyList(), missing, "options JSON must carry every effective option (missing: $missing)")
    }

    /**
     * Every member of the report envelope reaches the JSON.
     *
     * `runtime` did not. It was built on every run, excluded from the
     * golden digests as volatile — which only makes sense for a key that
     * IS written — documented in the attribute reference, and read by
     * cdxgen, whose `cdx:kosi:kotlinVersion` property had therefore never
     * once been emitted. Five places agreed the key existed; the
     * serializer alone disagreed, and nothing compared them.
     *
     * Written as a reflection over the declared members rather than a
     * `runtime` assertion, because the defect is the CLASS of thing worth
     * pinning: the next member added to the envelope and forgotten here
     * fails this test instead of shipping silently.
     */
    @Test
    fun everyReportMemberIsSerialized() {
        val w = JsonWriter()
        emptyReport().writeJson(w)
        val json = JsonReader.parse(w.render()).asObject()
        // Instance members only: `Companion` and the `SCHEMA_VERSION`
        // constant are statics on the same class and are not envelope keys.
        val missing = KosiReport::class.java.declaredFields
            .filterNot { java.lang.reflect.Modifier.isStatic(it.modifiers) || it.isSynthetic }
            .map { it.name }
            .filterNot { it in json.members }
        assertEquals(
            emptyList(),
            missing,
            "the report envelope must carry every declared member (missing: $missing)",
        )
    }

    private fun emptyReport() = KosiReport(
        schemaVersion = "kosi/1",
        tool = ToolInfo(name = "kosi", version = "0.0.0", description = "test", commit = "0000000"),
        runtime = RuntimeInfo(
            kotlinVersion = "2.4.0",
            languageVersionRange = LanguageVersionRange("2.0", "2.2", "2.4"),
            jvmVersion = "21",
            host = "test",
            workingDirectory = ".",
            nativeImage = false,
        ),
        options = AnalyzeOptions(),
        modules = emptyList(),
        packages = emptyList(),
        files = emptyList(),
        imports = emptyList(),
        declarations = emptyList(),
        usages = emptyList(),
        securitySignals = emptyList(),
        crypto = CryptoEvidence(
            libraries = emptyList(),
            assets = emptyList(),
            operations = emptyList(),
            materials = emptyList(),
            protocols = emptyList(),
            findings = emptyList(),
        ),
        callGraph = null,
        dataFlow = null,
        apiEndpoints = emptyList(),
        services = emptyList(),
        urls = emptyList(),
        diagnostics = emptyList(),
        stats = Stats(
            fileCount = 0,
            declarationCount = 0,
            usageCount = 0,
            importCount = 0,
            resolvedCallRatio = 0.0,
            callsTotal = 0,
            callsResolved = 0,
            unknownCallPropagations = 0,
            loweringFailures = linkedMapOf(),
            functionsLowered = 0,
            fixpointCapHits = 0,
            functionsAnalysed = 0,
            sourceCount = 0,
            sinkCount = 0,
            sliceCount = 0,
            crossDependencySliceCount = 0,
            reachableSliceCount = 0,
            truncations = linkedMapOf(),
            degraded = null,
        ),
    )

    @Test
    fun everyStatsMapKeyIsSorted() {
        val stats = Stats(
            fileCount = 0, declarationCount = 0, usageCount = 0, importCount = 0,
            resolvedCallRatio = 0.0, callsTotal = 0, callsResolved = 0, unknownCallPropagations = 0,
            loweringFailures = linkedMapOf("b-constraint" to 2, "a-constraint" to 1),
            functionsLowered = 0,
            fixpointCapHits = 0, functionsAnalysed = 0,
            sourceCount = 0, sinkCount = 0, sliceCount = 0,
            crossDependencySliceCount = 0, reachableSliceCount = 0,
            truncations = linkedMapOf("z-cap" to 1, "a-cap" to 3),
            degraded = null,
        )
        val w = JsonWriter()
        stats.writeJson(w)
        val json = w.render()
        val lowering = json.substringAfter("\"loweringFailures\":").substringBefore("}")
        val truncations = json.substringAfter("\"truncations\":").substringBefore("}")
        assertTrue(lowering.indexOf("a-constraint") < lowering.indexOf("b-constraint"), lowering)
        assertTrue(truncations.indexOf("a-cap") < truncations.indexOf("z-cap"), truncations)
    }

    @Test
    fun callGraphEdgeWithNullOptionalsSerializesWithoutDuplicateKeys() {
        val edge = CallGraphEdge(
            id = "edge-1", sourceId = "n1", targetId = "n2", callType = "static",
            line = 1, column = 1, calleeText = "foo", receiver = null, method = null,
            candidateCount = null, emittedCandidateCount = null,
            collapsedHops = null, collapsedPackages = null,
        )
        val w = JsonWriter()
        edge.writeJson(w)
        val json = w.render()
        // Null optionals appear exactly once, as nulls — never as a sentinel
        // number followed by a duplicate null key.
        assertEquals(1, Regex("\"candidateCount\":null").findAll(json).count())
        assertEquals(1, Regex("\"collapsedHops\":null").findAll(json).count())
        assertFalse("\"candidateCount\":-1" in json, "no sentinel for absent counts: $json")
        assertFalse("\"collapsedHops\":-1" in json, "no sentinel for absent counts: $json")
        // emittedCandidateCount is present ONLY when capped (schema rule).
        assertEquals(0, Regex("\"emittedCandidateCount\"").findAll(json).count())
    }

    @Test
    fun flowSummaryReturnTypeIsAStringNotAnArray() {
        val summary = FlowSummary(
            functionId = "f1", function = "pkg.f", parameterNames = listOf("a"),
            parameterTypes = listOf("String"), returnType = "String",
            paramToReturn = listOf("0"), paramToParam = emptyList(),
            paramToReceiver = emptyList(), paramToSink = linkedMapOf("sql-query" to listOf(1)),
            sourceReturns = emptyList(), sanitizes = emptyList(),
            accessPaths = linkedMapOf("a.f" to "tainted"), origin = "body",
        )
        val w = JsonWriter()
        summary.writeJson(w)
        val json = w.render()
        assertTrue("\"returnType\":\"String\"" in json, json)
        assertFalse("\"returnType\":[" in json, json)
    }
}
