package io.cdxgen.kosi.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the serialization invariants the phase-1+ engines will rely on. Both
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
        val missing = AnalyzeOptions::class.java.declaredFields
            .map { it.name }
            .filterNot { fieldName -> json.members.containsKey(fieldName) }
        assertEquals(emptyList(), missing, "options JSON must carry every effective option (missing: $missing)")
    }

    @Test
    fun everyStatsMapKeyIsSorted() {
        val stats = Stats(
            fileCount = 0, declarationCount = 0, usageCount = 0, importCount = 0,
            resolvedCallRatio = 0.0, unknownCallPropagations = 0,
            loweringFailures = linkedMapOf("b-constraint" to 2, "a-constraint" to 1),
            fixpointCapHits = 0, sourceCount = 0, sinkCount = 0, sliceCount = 0,
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
