package io.cdxgen.kosi.export

import io.cdxgen.kosi.schema.DataFlowEvidence
import io.cdxgen.kosi.schema.FlowNode
import io.cdxgen.kosi.schema.JsonWriter

/**
 * SARIF 2.1.0 export of the data-flow slices (the item; the same shape
 * golem ships). One RULE per slice rule id, one RESULT per slice: the sink
 * is the result location, the trace is the RELATED LOCATIONS list in walk
 * order (source first), and the same walk is a `codeFlow` for consumers
 * that render paths. Hand-rolled through the schema's deterministic writer
 * like every other kosi output: sorted keys, minified by default. A slice
 * whose `elided` is set keeps its related locations — the export renders
 * what the report carries, and the report already says the trace was cut.
 */
object Sarif {

    const val VERSION = "2.1.0"
    const val SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    fun write(
        dataFlow: DataFlowEvidence,
        toolName: String,
        toolVersion: String,
        apiEndpoints: List<io.cdxgen.kosi.schema.ApiEndpoint> = emptyList(),
    ): String {
        val w = JsonWriter(false)
        // JsonWriter sorts object keys: the bytes are deterministic across
        // runs, which the corpus' byte-identity gates read, even though
        // SARIF's own examples order keys conventionally.
        w.beginObject()
        w.str("\$schema", SCHEMA)
        w.str("version", VERSION)
        w.beginArray("runs")
        w.beginObject()
        w.beginObject("tool")
        w.beginObject("driver")
        w.str("informationUri", "https://github.com/cdxgen/cdxgen-plugins-bin/tree/main/thirdparty/kosi")
        w.str("name", toolName)
        w.str("semanticVersion", toolVersion)
        w.beginArray("rules")
        for (rule in rules(dataFlow)) {
            w.beginObject()
            w.str("id", rule.id)
            w.beginObject("fullDescription")
            w.str("text", rule.description)
            w.endObject()
            w.beginObject("properties")
            w.str("category", rule.category)
            w.str("name", rule.name)
            w.endObject()
            w.endObject()
        }
        w.endArray()
        w.endObject()
        w.endObject()
        val byId = dataFlow.nodes.associateBy { it.id }
        // A slice that entered through an endpoint carries the endpoint's
        // declaration into the export: without this, the
        // authentication requirement and media types were facts kosi
        // computed and threw away at the first export boundary — a result
        // about a route nobody protects is exactly the fact a SARIF
        // consumer wants first. Endpoint ids are stable; a slice links to
        // at most one endpoint in practice, and the first (lowest id) wins
        // deterministically if several do.
        val endpointBySliceId = apiEndpoints
            .sortedByDescending { it.id }
            .flatMap { ep -> ep.sliceIds.map { it to ep } }
            .toMap() // later pairs win, so descending order leaves the LOWEST id
        w.beginArray("results")
        for (slice in dataFlow.slices) {
            w.beginObject()
            w.beginArray("codeFlows")
            w.beginObject()
            w.beginArray("threadFlows")
            w.beginObject()
            w.beginArray("locations")
            for (nodeId in slice.nodeIds) {
                byId[nodeId]?.let {
                    w.beginObject()
                    location(w, it)
                    w.endObject()
                }
            }
            w.endArray()
            w.endObject()
            w.endArray()
            w.endObject()
            w.endArray()
            w.str("level", level(slice.severity))
            w.beginArray("locations")
            byId[slice.sinkId]?.let {
                w.beginObject()
                location(w, it)
                w.endObject()
            }
            w.endArray()
            w.beginObject("message")
            w.str(
                "text",
                "${slice.ruleName}: ${slice.sourceCategory} flows to ${slice.sinkCategory}" +
                    " (${slice.sourceName} -> ${slice.sinkName})",
            )
            w.endObject()
            w.beginObject("properties")
            w.beginArray("origins")
            for (o in slice.origins.sorted()) w.str(o)
            w.endArray()
            endpointBySliceId[slice.id]?.let { ep ->
                w.beginObject("endpoint")
                w.beginArray("authentication")
                for (a in ep.authentication) w.str(a)
                w.endArray()
                w.beginArray("consumes")
                for (c in ep.consumes) w.str(c)
                w.endArray()
                w.str("framework", ep.framework)
                w.str("path", ep.pathTemplate)
                w.beginArray("produces")
                for (p in ep.produces) w.str(p)
                w.endArray()
                w.endObject()
            }
            w.str("confidence", slice.confidence)
            w.bool("crossesDependency", slice.crossesDependency)
            w.bool("crossesModule", slice.crossesModule)
            w.str("flowKey", slice.flowKey)
            w.str("kosiSliceId", slice.id)
            w.str("riskScore", slice.riskScore)
            w.beginArray("taintKinds")
            for (t in slice.taintKinds) w.str(t)
            w.endArray()
            w.endObject()
            w.str("ruleId", slice.ruleId)
            w.beginArray("relatedLocations")
            for (nodeId in slice.nodeIds) {
                byId[nodeId]?.let {
                    w.beginObject()
                    location(w, it)
                    w.endObject()
                }
            }
            w.endArray()
            w.endObject()
        }
        w.endArray()
        w.beginObject("properties")
        w.str("dataflowMode", dataFlow.mode)
        w.endObject()
        w.endObject()
        w.endArray()
        w.endObject()
        return w.render()
    }

    private class Rule(val id: String, val name: String, val description: String, val category: String)

    /** One rule per rule id, first description wins; deterministic order. */
    private fun rules(dataFlow: DataFlowEvidence): List<Rule> =
        dataFlow.slices
            .groupBy { it.ruleId }
            .map { (id, slices) ->
                val first = slices.first()
                Rule(id, first.ruleName, first.description, first.sinkCategory)
            }
            .sortedBy { it.id }

    /** SARIF level from the slice severity string; unknown maps to note. */
    private fun level(severity: String): String = when (severity) {
        "critical", "high", "error" -> "error"
        "medium", "warning" -> "warning"
        else -> "note"
    }

    /** The CONTENTS of one location object; the caller opens/closes it. */
    private fun location(w: JsonWriter, node: FlowNode) {
        w.beginObject("message")
        w.str("text", node.name)
        w.endObject()
        w.beginObject("physicalLocation")
        w.beginObject("artifactLocation")
        w.str("uri", node.filePath)
        w.endObject()
        node.position?.let { p ->
            w.beginObject("region")
            w.num("startColumn", p.column)
            w.num("startLine", p.line)
            w.endObject()
        }
        w.endObject()
    }
}
