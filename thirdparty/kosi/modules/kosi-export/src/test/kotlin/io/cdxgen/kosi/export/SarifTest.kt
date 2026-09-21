package io.cdxgen.kosi.export

import io.cdxgen.kosi.schema.DataFlowEvidence
import io.cdxgen.kosi.schema.DataFlowStats
import io.cdxgen.kosi.schema.ModelPackRef
import io.cdxgen.kosi.schema.FlowEdge
import io.cdxgen.kosi.schema.FlowNode
import io.cdxgen.kosi.schema.FlowSlice
import io.cdxgen.kosi.schema.Position
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The SARIF 2.1.0 export: one rule per rule id, one result per slice,
 * the trace as related locations in walk order, deterministic bytes.
 */
class SarifTest {

    private fun dataFlow(): DataFlowEvidence {
        val nodes = listOf(
            FlowNode(
                id = "n1", name = "readLine", kind = "source", modulePath = ".",
                purl = "pkg:generic/t", filePath = "src/Main.kt",
                position = Position("src/Main.kt", 3, 11),
            ),
            FlowNode(
                id = "n2", name = "concat", kind = "assign", modulePath = ".",
                purl = "pkg:generic/t", filePath = "src/Main.kt",
                position = Position("src/Main.kt", 4, 5),
            ),
            FlowNode(
                id = "n3", name = "executeQuery", kind = "sink", modulePath = ".",
                purl = "pkg:generic/t", filePath = "src/Main.kt",
                position = Position("src/Main.kt", 5, 9),
            ),
        )
        val edges = listOf(
            FlowEdge("e1", "n1", "n2", "assign"),
            FlowEdge("e2", "n2", "n3", "call"),
        )
        val slice = FlowSlice(
            id = "slice-000001", sourceId = "n1", sinkId = "n3",
            sourceName = "readLine", sinkName = "executeQuery",
            sourceFunction = "t.Repo.load", sinkFunction = "java.sql.Statement.executeQuery",
            sourceModulePath = ".", sinkModulePath = ".", sourcePurl = "pkg:generic/t",
            targetPurl = "pkg:generic/t", purls = listOf("pkg:generic/t"),
            sourceCategory = "untrusted-input", sinkCategory = "sql-query",
            taintKinds = listOf("untrusted-input"),
            nodeIds = listOf("n1", "n2", "n3"), edgeIds = listOf("e1", "e2"),
            pathLength = 2, elided = null, sanitizerNodeIds = emptyList(),
            sinkArgumentIndex = 1, accessPath = null, crossesModule = false,
            crossesDependency = false, pathKind = "complete",
            ruleId = "kosi-sqli", ruleName = "SQL injection",
            description = "Tainted data reaches a SQL query",
            severity = "critical", confidence = "high", riskScore = "0.90",
            flowKey = "kosi-sqli:t.Repo.load", origins = listOf("pack"),
        )
        return DataFlowEvidence(
            mode = "security",
            patterns = ModelPackRef(builtin = listOf("security-pack-v0.json"), user = emptyList(), sourceCount = 4, sinkCount = 24, passthroughCount = 52, sanitizerCount = 2, effectCount = 5),
            nodes = nodes, edges = edges, slices = listOf(slice),
            summaries = emptyList(),
            stats = DataFlowStats(
                sliceCount = 1, uniqueFlows = 1, crossDependencySlices = 0, crossModuleSlices = 0,
                reachableSlices = 0, connectivity = 1.0, integrityViolations = 0,
                summariesComputed = 0, summariesByOrigin = emptyMap<String, Int>(),
            ),
            diagnostics = emptyList(),
        )
    }

    @Test
    fun rendersSarifWithRulesResultsAndRelatedLocations() {
        val sarif = Sarif.write(dataFlow(), "kosi", "0.2.0")
        assertTrue("\"version\":\"2.1.0\"" in sarif, sarif.take(200))
        assertTrue(sarif.contains("kosi-sqli"), "the rule id is declared")
        assertTrue(sarif.contains("SQL injection"), "the rule name is declared")
        // Related locations in walk order: source (line 3) before sink (line 5).
        val related = sarif.substringAfter("\"relatedLocations\":[")
        val firstLine = related.substringAfter("\"startLine\":").substringBefore("}")
        assertTrue(firstLine == "3", "source position first, got startLine=$firstLine")
        assertTrue(sarif.contains("src/Main.kt"), "artifact URIs carry file paths")
        assertTrue(sarif.contains("\"ruleId\":\"kosi-sqli\""), "results reference the rule")
        assertTrue(sarif.contains("codeFlows"), "the walk renders as a code flow")
    }

    @Test
    fun outputIsDeterministic() {
        assertEquals(Sarif.write(dataFlow(), "kosi", "0.2.0"), Sarif.write(dataFlow(), "kosi", "0.2.0"))
    }

    /**
     * A slice that entered through an endpoint carries the endpoint's
     * DECLARATION into the export — the authentication requirement above
     * all, which was a fact kosi computed and threw away at the SARIF
     * boundary. Restore the defect (endpoints not passed to the writer) and
     * the endpoint property is absent: this fails.
     */
    @Test
    fun anEndpointLinkedSliceCarriesItsAuthenticationIntoTheExport() {
        val endpoint = io.cdxgen.kosi.schema.ApiEndpoint(
            id = "ep-000001",
            framework = "servlet",
            httpMethods = listOf("GET"),
            pathTemplate = "/legacy/report",
            pathParameters = emptyList(),
            queryParameters = emptyList(),
            consumes = listOf("application/xml"),
            produces = listOf("application/json"),
            authentication = listOf("security-constraint(admin)"),
            handlerSymbol = "t.LegacyServlet.doGet",
            handlerCanonicalName = "t.LegacyServlet.doGet",
            modulePath = ".",
            purl = "",
            position = null,
            exported = true,
            permissions = emptyList(),
            deepLinkHosts = emptyList(),
            reachableSources = emptyList(),
            sliceIds = listOf("slice-000001"),
        )
        val sarif = Sarif.write(dataFlow(), "kosi", "0.2.0", listOf(endpoint))
        assertTrue("\"endpoint\":" in sarif, "the result carries its endpoint")
        assertTrue(sarif.contains("security-constraint(admin)"), "the authentication requirement survives")
        assertTrue(sarif.contains("/legacy/report"), "the endpoint's path survives")
        assertTrue(sarif.contains("application/xml"), "the media types survive")
        // A slice linked to NO endpoint adds no endpoint property.
        val plain = Sarif.write(dataFlow(), "kosi", "0.2.0", emptyList())
        assertTrue(!plain.contains("\"endpoint\":"), "unlinked slices stay unannotated")
    }

    @Test
    fun twoEndpointsOnOneSliceResolveToTheLowestIdDeterministically() {
        // Two routes can reach the same handler (an alias mapping, a
        // method-level and a class-level publish), and the export must not
        // depend on the order the detector emitted them.
        fun ep(id: String, path: String) = io.cdxgen.kosi.schema.ApiEndpoint(
            id = id,
            framework = "servlet",
            httpMethods = listOf("GET"),
            pathTemplate = path,
            pathParameters = emptyList(),
            queryParameters = emptyList(),
            consumes = emptyList(),
            produces = emptyList(),
            authentication = emptyList(),
            handlerSymbol = "t.S.doGet",
            handlerCanonicalName = "t.S.doGet",
            modulePath = ".",
            purl = "",
            position = null,
            exported = true,
            permissions = emptyList(),
            deepLinkHosts = emptyList(),
            reachableSources = emptyList(),
            sliceIds = listOf("slice-000001"),
        )
        val first = ep("ep-000001", "/one")
        val second = ep("ep-000002", "/two")
        val a = Sarif.write(dataFlow(), "kosi", "0.2.0", listOf(first, second))
        val b = Sarif.write(dataFlow(), "kosi", "0.2.0", listOf(second, first))
        assertEquals(a, b, "the link does not depend on emission order")
        assertTrue(a.contains("/one") && !a.contains("/two"), "the lowest endpoint id wins")
    }
}
