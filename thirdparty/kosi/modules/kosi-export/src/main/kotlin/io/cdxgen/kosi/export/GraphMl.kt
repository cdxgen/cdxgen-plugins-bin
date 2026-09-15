package io.cdxgen.kosi.export

import io.cdxgen.kosi.schema.CallGraph

/**
 * GraphML 1.1 writer for the call graph (02-ARCHITECTURE.md §9). Hand-rolled
 * and deterministic: keys declared up front, nodes and edges in emitted
 * order, attributes XML-escaped. Node attrs carry the classification
 * (local/stdlib/external/synthetic/suspend/visibility); edge attrs carry the
 * call type, call-site line, candidate count and the collapsed-bridge hop
 * count and packages. Every edge references nodes present in this document.
 */
object GraphMl {

    fun write(graph: CallGraph, title: String): String {
        val out = StringBuilder()
        out.appendLine("""<?xml version="1.0" encoding="UTF-8"?>""")
        out.appendLine(
            "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" " +
                "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                "xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns " +
                "http://graphml.graphdrawing.org/xmlns/1.1/graphml.xsd\">",
        )
        for ((id, type) in NODE_KEYS) {
            out.appendLine("""  <key id="$id" for="node" attr.name="$id" attr.type="$type"/>""")
        }
        for ((id, type) in EDGE_KEYS) {
            out.appendLine("""  <key id="$id" for="edge" attr.name="$id" attr.type="$type"/>""")
        }
        out.appendLine("""  <graph id="${Xml.escape(title)}" edgedefault="directed">""")
        for (node in graph.nodes) {
            out.appendLine("""    <node id="${Xml.escape(node.id)}">""")
            attr(out, "canonicalName", node.canonicalName)
            attr(out, "kind", node.kind)
            attr(out, "filePath", node.filePath)
            attr(out, "modulePath", node.modulePath)
            attr(out, "purl", node.purl)
            attr(out, "visibility", node.visibility)
            attrBool(out, "local", node.local)
            attrBool(out, "stdlib", node.stdlib)
            attrBool(out, "external", node.external)
            attrBool(out, "synthetic", node.synthetic)
            attrBool(out, "suspend", node.suspend)
            out.appendLine("    </node>")
        }
        for (edge in graph.edges) {
            out.appendLine(
                """    <edge id="${Xml.escape(edge.id)}" source="${Xml.escape(edge.sourceId)}" """ +
                    """target="${Xml.escape(edge.targetId)}">""",
            )
            attr(out, "callType", edge.callType)
            out.appendLine("""      <data key="line">${edge.line}</data>""")
            edge.candidateCount?.let { out.appendLine("""      <data key="candidateCount">$it</data>""") }
            edge.collapsedHops?.let { out.appendLine("""      <data key="collapsedHops">$it</data>""") }
            edge.collapsedPackages?.takeIf { it.isNotEmpty() }?.let {
                attr(out, "collapsedPackages", it.joinToString(","))
            }
            out.appendLine("    </edge>")
        }
        out.appendLine("  </graph>")
        out.appendLine("</graphml>")
        return out.toString()
    }

    private val NODE_KEYS = linkedMapOf(
        "canonicalName" to "string",
        "kind" to "string",
        "filePath" to "string",
        "modulePath" to "string",
        "purl" to "string",
        "visibility" to "string",
        "local" to "boolean",
        "stdlib" to "boolean",
        "external" to "boolean",
        "synthetic" to "boolean",
        "suspend" to "boolean",
    )

    private val EDGE_KEYS = linkedMapOf(
        "callType" to "string",
        "line" to "int",
        "candidateCount" to "int",
        "collapsedHops" to "int",
        "collapsedPackages" to "string",
    )

    private fun attr(out: StringBuilder, key: String, value: String) {
        out.appendLine("""      <data key="$key">${Xml.escape(value)}</data>""")
    }

    private fun attrBool(out: StringBuilder, key: String, value: Boolean) {
        out.appendLine("""      <data key="$key">$value</data>""")
    }
}

/** GEXF 1.3 writer for the call graph, same content as the GraphML view. */
object Gexf {

    fun write(graph: CallGraph, title: String): String {
        val out = StringBuilder()
        out.appendLine("""<?xml version="1.0" encoding="UTF-8"?>""")
        out.appendLine(
            """<gexf xmlns="http://gexf.net/1.3" version="1.3" """ +
                """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """ +
                """xsi:schemaLocation="http://gexf.net/1.3 http://gexf.net/1.3/gexf.xsd">""",
        )
        out.appendLine("""  <meta lastmodifieddate="1970-01-01T00:00:00Z">""")
        // Fixed timestamp: the export is a deterministic artifact, not a
        // snapshot of when it was produced.
        out.appendLine("""    <creator>kosi</creator>""")
        out.appendLine("""    <description>${Xml.escape(title)}</description>""")
        out.appendLine("""  </meta>""")
        out.appendLine("""  <graph defaultedgetype="directed">""")
        out.appendLine("""    <attributes class="node">""")
        for ((id, type) in listOf(
            "canonicalName" to "string",
            "kind" to "string",
            "filePath" to "string",
            "modulePath" to "string",
            "purl" to "string",
            "visibility" to "string",
            "local" to "boolean",
            "stdlib" to "boolean",
            "external" to "boolean",
            "synthetic" to "boolean",
            "suspend" to "boolean",
        )) {
            out.appendLine("""      <attribute id="$id" title="$id" type="$type"/>""")
        }
        out.appendLine("    </attributes>")
        out.appendLine("""    <attributes class="edge">""")
        for ((id, type) in listOf(
            "callType" to "string",
            "line" to "long",
            "candidateCount" to "long",
            "collapsedHops" to "long",
            "collapsedPackages" to "string",
        )) {
            out.appendLine("""      <attribute id="$id" title="$id" type="$type"/>""")
        }
        out.appendLine("    </attributes>")
        out.appendLine("    <nodes>")
        for (node in graph.nodes) {
            out.appendLine("""      <node id="${Xml.escape(node.id)}" label="${Xml.escape(node.canonicalName)}">""")
            attvalues(out) {
                value("canonicalName", node.canonicalName)
                value("kind", node.kind)
                value("filePath", node.filePath)
                value("modulePath", node.modulePath)
                value("purl", node.purl)
                value("visibility", node.visibility)
                bool("local", node.local)
                bool("stdlib", node.stdlib)
                bool("external", node.external)
                bool("synthetic", node.synthetic)
                bool("suspend", node.suspend)
            }
            out.appendLine("      </node>")
        }
        out.appendLine("    </nodes>")
        out.appendLine("    <edges>")
        for (edge in graph.edges) {
            out.appendLine(
                """      <edge id="${Xml.escape(edge.id)}" source="${Xml.escape(edge.sourceId)}" """ +
                    """target="${Xml.escape(edge.targetId)}">""",
            )
            attvalues(out) {
                value("callType", edge.callType)
                long("line", edge.line)
                edge.candidateCount?.let { long("candidateCount", it) }
                edge.collapsedHops?.let { long("collapsedHops", it) }
                edge.collapsedPackages
                    ?.takeIf { pkgs -> pkgs.isNotEmpty() }
                    ?.let { pkgs -> value("collapsedPackages", pkgs.joinToString(",")) }
            }
            out.appendLine("      </edge>")
        }
        out.appendLine("    </edges>")
        out.appendLine("  </graph>")
        out.appendLine("</gexf>")
        return out.toString()
    }

    private inline fun attvalues(out: StringBuilder, block: AttvaluesBuilder.() -> Unit) {
        out.appendLine("        <attvalues>")
        AttvaluesBuilder(out).block()
        out.appendLine("        </attvalues>")
    }

    private class AttvaluesBuilder(private val out: StringBuilder) {
        fun value(id: String, v: String) {
            out.appendLine("""          <attvalue for="$id" value="${Xml.escape(v)}"/>""")
        }

        fun bool(id: String, v: Boolean) {
            out.appendLine("""          <attvalue for="$id" value="$v"/>""")
        }

        fun long(id: String, v: Int) {
            out.appendLine("""          <attvalue for="$id" value="$v"/>""")
        }
    }
}

internal object Xml {
    fun escape(text: String): String = buildString {
        for (c in text) {
            when {
                c == '&' -> append("&amp;")
                c == '<' -> append("&lt;")
                c == '>' -> append("&gt;")
                c == '"' -> append("&quot;")
                c == '\'' -> append("&apos;")
                c < ' ' -> append("&#${c.code};")
                else -> append(c)
            }
        }
    }
}
