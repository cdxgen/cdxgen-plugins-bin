package io.cdxgen.kosi.schema

/**
 * CallGraph (03-SCHEMA.md). Edges carry no field that already exists on the
 * node they reference (schema rule 2), except `emittedCandidateCount`, whose
 * presence alone marks the edge as a capped sample.
 */
data class CallGraphNode(
    val id: String,
    val name: String,
    val qualifiedName: String,
    val canonicalName: String,
    val jvmDescriptor: String?,
    val kind: String,
    val modulePath: String,
    val purl: String,
    val filePath: String,
    val local: Boolean,
    val stdlib: Boolean,
    val external: Boolean,
    val synthetic: Boolean,
    val suspend: Boolean,
    /**
     * Declared visibility (`public`, `protected`, `internal`, `private`,
     * `package-private`, `local`); `unknown` for external nodes, whose
     * declarations kosi has not analysed. `--roots exported` roots exactly
     * the local nodes whose visibility is `public` or `protected`, so the
     * field a gate reads is on the artifact the gate reads.
     */
    val visibility: String,
    /**
     * Declared visibility of the enclosing class; null for ownerless
     * (top-level) functions and external nodes. A public member of an
     * internal class is not public API, and `--roots exported` gates on
     * this — the field is ON the node so every consumer applies the same
     * definition instead of re-deriving one.
     */
    val ownerVisibility: String?,
    val receiver: String?,
    val position: Position?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("canonicalName", canonicalName)
        w.bool("external", external)
        w.str("filePath", filePath)
        w.str("id", id)
        w.str("jvmDescriptor", jvmDescriptor)
        w.str("kind", kind)
        w.bool("local", local)
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.str("purl", purl)
        position?.writeJson(w, "position")
        w.str("qualifiedName", qualifiedName)
        w.str("receiver", receiver)
        w.bool("stdlib", stdlib)
        w.bool("suspend", suspend)
        w.str("visibility", visibility)
        w.str("ownerVisibility", ownerVisibility)
        w.bool("synthetic", synthetic)
        w.endObject()
    }
}

data class CallGraphEdge(
    val id: String,
    val sourceId: String,
    val targetId: String,
    val callType: String,
    val line: Int,
    val column: Int,
    val calleeText: String?,
    val receiver: String?,
    val method: String?,
    val candidateCount: Int?,
    val emittedCandidateCount: Int?,
    val collapsedHops: Int?,
    val collapsedPackages: List<String>?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("calleeText", calleeText)
        if (candidateCount != null) w.num("candidateCount", candidateCount) else w.nul("candidateCount")
        w.str("callType", callType)
        w.num("column", column)
        if (collapsedHops != null) w.num("collapsedHops", collapsedHops) else w.nul("collapsedHops")
        if (emittedCandidateCount != null) w.num("emittedCandidateCount", emittedCandidateCount)
        w.beginArray("collapsedPackages")
        for (p in (collapsedPackages ?: emptyList()).sorted()) w.str(p)
        w.endArray()
        w.str("id", id)
        w.num("line", line)
        w.str("method", method)
        w.str("receiver", receiver)
        w.str("sourceId", sourceId)
        w.str("targetId", targetId)
        w.endObject()
    }
}

data class ReachabilityEntry(
    val nodeId: String,
    val reached: Boolean,
    val distance: Int,
    val roots: List<String>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("distance", distance)
        w.str("nodeId", nodeId)
        w.bool("reached", reached)
        w.beginArray("roots")
        for (r in roots.sorted()) w.str(r)
        w.endArray()
        w.endObject()
    }
}

data class CallGraphBreakdown(
    val localNodes: Int,
    val stdlibNodes: Int,
    val dependencyNodes: Int,
    val syntheticNodes: Int,
    val localEdges: Int,
    val stdlibEdges: Int,
    val dependencyEdges: Int,
    val syntheticEdges: Int,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.num("dependencyEdges", dependencyEdges)
        w.num("dependencyNodes", dependencyNodes)
        w.num("localEdges", localEdges)
        w.num("localNodes", localNodes)
        w.num("stdlibEdges", stdlibEdges)
        w.num("stdlibNodes", stdlibNodes)
        w.num("syntheticEdges", syntheticEdges)
        w.num("syntheticNodes", syntheticNodes)
        w.endObject()
    }
}

data class CallGraph(
    val mode: String,
    val algorithmUsed: String,
    val nodes: List<CallGraphNode>,
    val edges: List<CallGraphEdge>,
    val reachability: List<ReachabilityEntry>,
    val stats: CallGraphBreakdown,
    val diagnostics: List<Diagnostic>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("algorithmUsed", algorithmUsed)
        w.beginArray("diagnostics")
        for (d in diagnostics.sortedWith(Diagnostic.COMPARATOR)) d.writeJson(w)
        w.endArray()
        w.str("mode", mode)
        w.beginArray("edges")
        for (e in edges) e.writeJson(w)
        w.endArray()
        w.beginArray("nodes")
        for (n in nodes) n.writeJson(w)
        w.endArray()
        w.beginArray("reachability")
        for (r in reachability) r.writeJson(w)
        w.endArray()
        stats.writeJson(w, "stats")
        w.endObject()
    }
}
