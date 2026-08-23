use std::fmt::Write as _;
use std::fs;
use std::io::{BufWriter, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use rusi_schema::{
    CallGraph, CallGraphEdge, CallGraphNode, DataFlowEvidence, DataFlowNode, DataFlowSlice,
    call_type_confidence,
};
use serde::Serialize;

pub const EXPORT_FORMATS: [&str; 3] = ["json", "graphml", "gexf"];

/// Edge attributes as the graph formats want them.
///
/// A report edge is normalized against its nodes, but GraphML and GEXF are
/// consumed by graph tools that read edge attributes directly and cannot join
/// to a node table, so the export re-attaches the endpoint facts here.
struct ExportedEdge<'a> {
    source_name: &'a str,
    target_name: &'a str,
    source_purl: &'a str,
    target_purl: &'a str,
    purls: Vec<&'a str>,
    position_filename: &'a str,
    properties: IndexMap<&'a str, String>,
}

impl<'a> ExportedEdge<'a> {
    fn build(edge: &'a CallGraphEdge, nodes: &IndexMap<&'a str, &'a CallGraphNode>) -> Self {
        let source = nodes.get(edge.source_id.as_str());
        let target = nodes.get(edge.target_id.as_str());
        let source_purl = source.map(|node| node.purl.as_str()).unwrap_or_default();
        let target_purl = target.map(|node| node.purl.as_str()).unwrap_or_default();
        let mut purls: Vec<&str> = [source_purl, target_purl]
            .into_iter()
            .filter(|purl| !purl.is_empty())
            .collect();
        purls.sort_unstable();
        purls.dedup();

        let mut properties = IndexMap::new();
        if let Some(callee_text) = edge.callee_text.as_deref() {
            properties.insert("calleeText", callee_text.to_string());
        }
        // `confidence` and `provenance` are derived rather than stored on the
        // edge; graph tools still expect to see them.
        properties.insert(
            "confidence",
            call_type_confidence(&edge.call_type).to_string(),
        );
        properties.insert("provenance", edge.call_type.clone());
        if let Some(receiver) = edge.receiver.as_deref() {
            properties.insert("receiver", receiver.to_string());
        }
        if let Some(method) = edge.method.as_deref() {
            properties.insert("method", method.to_string());
        }
        if let Some(candidate_count) = edge.candidate_count {
            properties.insert("candidateCount", candidate_count.to_string());
        }
        if let Some(emitted) = edge.emitted_candidate_count {
            properties.insert("candidatesTruncated", "true".to_string());
            properties.insert("emittedCandidateCount", emitted.to_string());
        }
        for (key, value) in &edge.properties {
            properties.insert(key.as_str(), value.clone());
        }

        Self {
            source_name: source
                .map(|node| node.qualified_name.as_str())
                .unwrap_or_default(),
            target_name: target
                .map(|node| node.qualified_name.as_str())
                .unwrap_or_default(),
            source_purl,
            target_purl,
            purls,
            // The call site is in the caller's file.
            position_filename: source
                .map(|node| node.file_path.as_str())
                .unwrap_or_default(),
            properties,
        }
    }
}

fn call_graph_node_index(call_graph: &CallGraph) -> IndexMap<&str, &CallGraphNode> {
    call_graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect()
}

pub fn write_call_graph_export(
    call_graph: &CallGraph,
    format: &str,
    path: &Path,
    pretty: bool,
) -> Result<()> {
    match format {
        "json" => write_json_export(path, call_graph, pretty),
        "graphml" => write_text_export(path, &render_call_graph_graphml(call_graph)),
        "gexf" => write_text_export(path, &render_call_graph_gexf(call_graph)),
        other => {
            anyhow::bail!("unsupported export format {other}; expected one of json, graphml, gexf")
        }
    }
}

pub fn write_data_flow_export(
    data_flow: &DataFlowEvidence,
    format: &str,
    path: &Path,
    pretty: bool,
) -> Result<()> {
    match format {
        "json" => write_json_export(path, data_flow, pretty),
        "graphml" => write_text_export(path, &render_data_flow_graphml(data_flow)),
        "gexf" => write_text_export(path, &render_data_flow_gexf(data_flow)),
        other => {
            anyhow::bail!("unsupported export format {other}; expected one of json, graphml, gexf")
        }
    }
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create export directory {}", parent.display()))?;
    }
    Ok(())
}

/// Stream a graph straight into the destination file rather than allocating the
/// whole document as a `String` first. Graph exports for large targets can be
/// hundreds of MB; the intermediate `String` doubled peak memory. Output is
/// minified by default; `pretty` selects indented output.
fn write_json_export<T: Serialize>(path: &Path, value: &T, pretty: bool) -> Result<()> {
    ensure_parent(path)?;
    let file = fs::File::create(path)
        .with_context(|| format!("failed to create export {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let result = if pretty {
        serde_json::to_writer_pretty(&mut writer, value)
    } else {
        serde_json::to_writer(&mut writer, value)
    };
    result.with_context(|| format!("failed to write export {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("failed to flush export {}", path.display()))
}

fn write_text_export(path: &Path, content: &str) -> Result<()> {
    ensure_parent(path)?;
    fs::write(path, content).with_context(|| format!("failed to write export {}", path.display()))
}

fn render_call_graph_graphml(call_graph: &CallGraph) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">\n");
    for (id, target, name, ty) in [
        ("graph_mode", "graph", "mode", "string"),
        ("graph_diagnostics", "graph", "diagnostics", "string"),
        ("node_name", "node", "name", "string"),
        ("node_qualified_name", "node", "qualifiedName", "string"),
        ("node_kind", "node", "kind", "string"),
        ("node_package_path", "node", "packagePath", "string"),
        ("node_purl", "node", "purl", "string"),
        ("node_file_path", "node", "filePath", "string"),
        ("node_local", "node", "local", "boolean"),
        ("node_external", "node", "external", "boolean"),
        ("node_receiver", "node", "receiver", "string"),
        (
            "node_position_filename",
            "node",
            "positionFilename",
            "string",
        ),
        ("node_position_line", "node", "positionLine", "int"),
        ("node_position_column", "node", "positionColumn", "int"),
        ("edge_source_name", "edge", "sourceName", "string"),
        ("edge_target_name", "edge", "targetName", "string"),
        ("edge_source_purl", "edge", "sourcePurl", "string"),
        ("edge_target_purl", "edge", "targetPurl", "string"),
        ("edge_purls", "edge", "purls", "string"),
        ("edge_call_type", "edge", "callType", "string"),
        (
            "edge_position_filename",
            "edge",
            "positionFilename",
            "string",
        ),
        ("edge_position_line", "edge", "positionLine", "int"),
        ("edge_position_column", "edge", "positionColumn", "int"),
        ("edge_properties", "edge", "properties", "string"),
    ] {
        let _ = writeln!(
            xml,
            "  <key id=\"{id}\" for=\"{target}\" attr.name=\"{name}\" attr.type=\"{ty}\"/>"
        );
    }
    xml.push_str("  <graph id=\"callgraph\" edgedefault=\"directed\">\n");
    push_graphml_data(&mut xml, "graph_mode", &call_graph.mode, 2);
    push_graphml_data(
        &mut xml,
        "graph_diagnostics",
        &json_text(&call_graph.diagnostics),
        2,
    );
    for node in &call_graph.nodes {
        let _ = writeln!(xml, "    <node id=\"{}\">", xml_escape(&node.id));
        render_call_graph_node_graphml(&mut xml, node);
        xml.push_str("    </node>\n");
    }
    let nodes = call_graph_node_index(call_graph);
    for edge in &call_graph.edges {
        let exported = ExportedEdge::build(edge, &nodes);
        let _ = writeln!(
            xml,
            "    <edge id=\"{}\" source=\"{}\" target=\"{}\">",
            xml_escape(&edge.id),
            xml_escape(&edge.source_id),
            xml_escape(&edge.target_id)
        );
        push_graphml_data(&mut xml, "edge_source_name", exported.source_name, 3);
        push_graphml_data(&mut xml, "edge_target_name", exported.target_name, 3);
        push_graphml_data(&mut xml, "edge_source_purl", exported.source_purl, 3);
        push_graphml_data(&mut xml, "edge_target_purl", exported.target_purl, 3);
        push_graphml_data(&mut xml, "edge_purls", &json_text(&exported.purls), 3);
        push_graphml_data(&mut xml, "edge_call_type", &edge.call_type, 3);
        push_graphml_data(
            &mut xml,
            "edge_position_filename",
            exported.position_filename,
            3,
        );
        push_graphml_data(&mut xml, "edge_position_line", &edge.line.to_string(), 3);
        push_graphml_data(
            &mut xml,
            "edge_position_column",
            &edge.column.to_string(),
            3,
        );
        push_graphml_data(
            &mut xml,
            "edge_properties",
            &json_text(&exported.properties),
            3,
        );
        xml.push_str("    </edge>\n");
    }
    xml.push_str("  </graph>\n</graphml>\n");
    xml
}

fn render_call_graph_node_graphml(xml: &mut String, node: &CallGraphNode) {
    push_graphml_data(xml, "node_name", &node.name, 3);
    push_graphml_data(xml, "node_qualified_name", &node.qualified_name, 3);
    push_graphml_data(xml, "node_kind", &node.kind, 3);
    push_graphml_data(xml, "node_package_path", &node.package_path, 3);
    push_graphml_data(xml, "node_purl", &node.purl, 3);
    push_graphml_data(xml, "node_file_path", &node.file_path, 3);
    push_graphml_data(xml, "node_local", &node.local.to_string(), 3);
    push_graphml_data(xml, "node_external", &node.external.to_string(), 3);
    push_graphml_data(
        xml,
        "node_receiver",
        node.receiver.as_deref().unwrap_or(""),
        3,
    );
    push_graphml_data(xml, "node_position_filename", &node.position.filename, 3);
    push_graphml_data(
        xml,
        "node_position_line",
        &node.position.line.to_string(),
        3,
    );
    push_graphml_data(
        xml,
        "node_position_column",
        &node.position.column.to_string(),
        3,
    );
}

fn render_call_graph_gexf(call_graph: &CallGraph) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<gexf xmlns=\"http://www.gexf.net/1.3\" version=\"1.3\">\n");
    xml.push_str("  <meta lastmodifieddate=\"2026-06-01\">\n");
    xml.push_str("    <creator>rusi</creator>\n");
    xml.push_str("    <description>Rust call graph export</description>\n");
    xml.push_str("  </meta>\n");
    let _ = writeln!(
        xml,
        "  <graph defaultedgetype=\"directed\" mode=\"{}\">",
        xml_escape(&call_graph.mode)
    );
    render_gexf_attributes(
        &mut xml,
        "node",
        &[
            ("name", "name", "string"),
            ("qualified_name", "qualifiedName", "string"),
            ("kind", "kind", "string"),
            ("package_path", "packagePath", "string"),
            ("purl", "purl", "string"),
            ("file_path", "filePath", "string"),
            ("local", "local", "boolean"),
            ("external", "external", "boolean"),
            ("receiver", "receiver", "string"),
            ("position_filename", "positionFilename", "string"),
            ("position_line", "positionLine", "integer"),
            ("position_column", "positionColumn", "integer"),
        ],
    );
    render_gexf_attributes(
        &mut xml,
        "edge",
        &[
            ("source_name", "sourceName", "string"),
            ("target_name", "targetName", "string"),
            ("source_purl", "sourcePurl", "string"),
            ("target_purl", "targetPurl", "string"),
            ("purls", "purls", "string"),
            ("call_type", "callType", "string"),
            ("position_filename", "positionFilename", "string"),
            ("position_line", "positionLine", "integer"),
            ("position_column", "positionColumn", "integer"),
            ("properties", "properties", "string"),
        ],
    );
    xml.push_str("    <nodes>\n");
    for node in &call_graph.nodes {
        let _ = writeln!(
            xml,
            "      <node id=\"{}\" label=\"{}\">",
            xml_escape(&node.id),
            xml_escape(&node.name)
        );
        xml.push_str("        <attvalues>\n");
        push_gexf_attvalue(&mut xml, "name", &node.name, 5);
        push_gexf_attvalue(&mut xml, "qualified_name", &node.qualified_name, 5);
        push_gexf_attvalue(&mut xml, "kind", &node.kind, 5);
        push_gexf_attvalue(&mut xml, "package_path", &node.package_path, 5);
        push_gexf_attvalue(&mut xml, "purl", &node.purl, 5);
        push_gexf_attvalue(&mut xml, "file_path", &node.file_path, 5);
        push_gexf_attvalue(&mut xml, "local", &node.local.to_string(), 5);
        push_gexf_attvalue(&mut xml, "external", &node.external.to_string(), 5);
        push_gexf_attvalue(
            &mut xml,
            "receiver",
            node.receiver.as_deref().unwrap_or(""),
            5,
        );
        push_gexf_attvalue(&mut xml, "position_filename", &node.position.filename, 5);
        push_gexf_attvalue(
            &mut xml,
            "position_line",
            &node.position.line.to_string(),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "position_column",
            &node.position.column.to_string(),
            5,
        );
        xml.push_str("        </attvalues>\n");
        xml.push_str("      </node>\n");
    }
    xml.push_str("    </nodes>\n    <edges>\n");
    let nodes = call_graph_node_index(call_graph);
    for edge in &call_graph.edges {
        let _ = writeln!(
            xml,
            "      <edge id=\"{}\" source=\"{}\" target=\"{}\" label=\"{}\">",
            xml_escape(&edge.id),
            xml_escape(&edge.source_id),
            xml_escape(&edge.target_id),
            xml_escape(&edge.call_type)
        );
        xml.push_str("        <attvalues>\n");
        let exported = ExportedEdge::build(edge, &nodes);
        push_gexf_attvalue(&mut xml, "source_name", exported.source_name, 5);
        push_gexf_attvalue(&mut xml, "target_name", exported.target_name, 5);
        push_gexf_attvalue(&mut xml, "source_purl", exported.source_purl, 5);
        push_gexf_attvalue(&mut xml, "target_purl", exported.target_purl, 5);
        push_gexf_attvalue(&mut xml, "purls", &json_text(&exported.purls), 5);
        push_gexf_attvalue(&mut xml, "call_type", &edge.call_type, 5);
        push_gexf_attvalue(&mut xml, "position_filename", exported.position_filename, 5);
        push_gexf_attvalue(&mut xml, "position_line", &edge.line.to_string(), 5);
        push_gexf_attvalue(&mut xml, "position_column", &edge.column.to_string(), 5);
        push_gexf_attvalue(&mut xml, "properties", &json_text(&exported.properties), 5);
        xml.push_str("        </attvalues>\n");
        xml.push_str("      </edge>\n");
    }
    xml.push_str("    </edges>\n  </graph>\n</gexf>\n");
    xml
}

fn render_data_flow_graphml(data_flow: &DataFlowEvidence) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">\n");
    for (id, target, name, ty) in [
        ("graph_mode", "graph", "mode", "string"),
        ("graph_patterns", "graph", "patterns", "string"),
        ("graph_diagnostics", "graph", "diagnostics", "string"),
        ("node_kind", "node", "kind", "string"),
        ("node_name", "node", "name", "string"),
        ("node_package_path", "node", "packagePath", "string"),
        ("node_purl", "node", "purl", "string"),
        ("node_function", "node", "function", "string"),
        ("node_source", "node", "source", "boolean"),
        ("node_sink", "node", "sink", "boolean"),
        ("node_category", "node", "category", "string"),
        ("node_parameter_index", "node", "parameterIndex", "int"),
        ("node_type_name", "node", "typeName", "string"),
        (
            "node_position_filename",
            "node",
            "positionFilename",
            "string",
        ),
        ("node_position_line", "node", "positionLine", "int"),
        ("node_position_column", "node", "positionColumn", "int"),
        ("node_properties", "node", "properties", "string"),
        ("edge_source_name", "edge", "sourceName", "string"),
        ("edge_target_name", "edge", "targetName", "string"),
        ("edge_source_function", "edge", "sourceFunction", "string"),
        ("edge_target_function", "edge", "targetFunction", "string"),
        (
            "edge_source_package_path",
            "edge",
            "sourcePackagePath",
            "string",
        ),
        (
            "edge_target_package_path",
            "edge",
            "targetPackagePath",
            "string",
        ),
        ("edge_source_purl", "edge", "sourcePurl", "string"),
        ("edge_target_purl", "edge", "targetPurl", "string"),
        ("edge_purls", "edge", "purls", "string"),
        ("edge_source_category", "edge", "sourceCategory", "string"),
        ("edge_target_category", "edge", "targetCategory", "string"),
        ("edge_path_length", "edge", "pathLength", "int"),
        (
            "edge_source_parameter_index",
            "edge",
            "sourceParameterIndex",
            "int",
        ),
        (
            "edge_target_parameter_index",
            "edge",
            "targetParameterIndex",
            "int",
        ),
        ("edge_source_type_name", "edge", "sourceTypeName", "string"),
        ("edge_target_type_name", "edge", "targetTypeName", "string"),
        ("edge_rule_name", "edge", "ruleName", "string"),
        ("edge_description", "edge", "description", "string"),
        ("edge_node_ids", "edge", "nodeIds", "string"),
        ("edge_edge_ids", "edge", "edgeIds", "string"),
        ("edge_properties", "edge", "properties", "string"),
    ] {
        let _ = writeln!(
            xml,
            "  <key id=\"{id}\" for=\"{target}\" attr.name=\"{name}\" attr.type=\"{ty}\"/>"
        );
    }
    xml.push_str("  <graph id=\"dataflow\" edgedefault=\"directed\">\n");
    push_graphml_data(&mut xml, "graph_mode", &data_flow.mode, 2);
    push_graphml_data(
        &mut xml,
        "graph_patterns",
        &json_text(&data_flow.patterns),
        2,
    );
    push_graphml_data(
        &mut xml,
        "graph_diagnostics",
        &json_text(&data_flow.diagnostics),
        2,
    );
    for node in &data_flow.nodes {
        let _ = writeln!(xml, "    <node id=\"{}\">", xml_escape(&node.id));
        render_data_flow_node_graphml(&mut xml, node);
        xml.push_str("    </node>\n");
    }
    for slice in &data_flow.slices {
        let _ = writeln!(
            xml,
            "    <edge id=\"{}\" source=\"{}\" target=\"{}\">",
            xml_escape(&slice.id),
            xml_escape(&slice.source_id),
            xml_escape(&slice.sink_id)
        );
        render_data_flow_slice_graphml(&mut xml, slice);
        xml.push_str("    </edge>\n");
    }
    xml.push_str("  </graph>\n</graphml>\n");
    xml
}

fn render_data_flow_node_graphml(xml: &mut String, node: &DataFlowNode) {
    push_graphml_data(xml, "node_kind", &node.kind, 3);
    push_graphml_data(xml, "node_name", &node.name, 3);
    push_graphml_data(xml, "node_package_path", &node.package_path, 3);
    push_graphml_data(xml, "node_purl", &node.purl, 3);
    push_graphml_data(xml, "node_function", &node.function, 3);
    push_graphml_data(xml, "node_source", &node.source.to_string(), 3);
    push_graphml_data(xml, "node_sink", &node.sink.to_string(), 3);
    push_graphml_data(xml, "node_category", &node.category, 3);
    push_graphml_data(
        xml,
        "node_parameter_index",
        &node
            .parameter_index
            .map(|value| value.to_string())
            .unwrap_or_default(),
        3,
    );
    push_graphml_data(
        xml,
        "node_type_name",
        node.type_name.as_deref().unwrap_or(""),
        3,
    );
    push_graphml_data(xml, "node_position_filename", &node.position.filename, 3);
    push_graphml_data(
        xml,
        "node_position_line",
        &node.position.line.to_string(),
        3,
    );
    push_graphml_data(
        xml,
        "node_position_column",
        &node.position.column.to_string(),
        3,
    );
    push_graphml_data(xml, "node_properties", &json_text(&node.properties), 3);
}

fn render_data_flow_slice_graphml(xml: &mut String, slice: &DataFlowSlice) {
    push_graphml_data(xml, "edge_source_name", &slice.source_name, 3);
    push_graphml_data(xml, "edge_target_name", &slice.sink_name, 3);
    push_graphml_data(xml, "edge_source_function", &slice.source_function, 3);
    push_graphml_data(xml, "edge_target_function", &slice.sink_function, 3);
    push_graphml_data(
        xml,
        "edge_source_package_path",
        &slice.source_package_path,
        3,
    );
    push_graphml_data(xml, "edge_target_package_path", &slice.sink_package_path, 3);
    push_graphml_data(xml, "edge_source_purl", &slice.source_purl, 3);
    push_graphml_data(xml, "edge_target_purl", &slice.target_purl, 3);
    push_graphml_data(xml, "edge_purls", &json_text(&slice.purls), 3);
    push_graphml_data(xml, "edge_source_category", &slice.source_category, 3);
    push_graphml_data(xml, "edge_target_category", &slice.sink_category, 3);
    push_graphml_data(xml, "edge_path_length", &slice.path_length.to_string(), 3);
    push_graphml_data(
        xml,
        "edge_source_parameter_index",
        &slice
            .source_parameter_index
            .map(|value| value.to_string())
            .unwrap_or_default(),
        3,
    );
    push_graphml_data(
        xml,
        "edge_target_parameter_index",
        &slice
            .sink_parameter_index
            .map(|value| value.to_string())
            .unwrap_or_default(),
        3,
    );
    push_graphml_data(
        xml,
        "edge_source_type_name",
        slice.source_type_name.as_deref().unwrap_or(""),
        3,
    );
    push_graphml_data(
        xml,
        "edge_target_type_name",
        slice.sink_type_name.as_deref().unwrap_or(""),
        3,
    );
    push_graphml_data(xml, "edge_rule_name", &slice.rule_name, 3);
    push_graphml_data(xml, "edge_description", &slice.description, 3);
    push_graphml_data(xml, "edge_node_ids", &json_text(&slice.node_ids), 3);
    push_graphml_data(xml, "edge_edge_ids", &json_text(&slice.edge_ids), 3);
    push_graphml_data(xml, "edge_properties", &json_text(&slice.properties), 3);
}

fn render_data_flow_gexf(data_flow: &DataFlowEvidence) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<gexf xmlns=\"http://www.gexf.net/1.3\" version=\"1.3\">\n");
    xml.push_str("  <meta lastmodifieddate=\"2026-06-01\">\n");
    xml.push_str("    <creator>rusi</creator>\n");
    xml.push_str("    <description>Rust data-flow slice export</description>\n");
    xml.push_str("  </meta>\n");
    let _ = writeln!(
        xml,
        "  <graph defaultedgetype=\"directed\" mode=\"{}\">",
        xml_escape(&data_flow.mode)
    );
    render_gexf_attributes(
        &mut xml,
        "node",
        &[
            ("kind", "kind", "string"),
            ("name", "name", "string"),
            ("package_path", "packagePath", "string"),
            ("purl", "purl", "string"),
            ("function", "function", "string"),
            ("source", "source", "boolean"),
            ("sink", "sink", "boolean"),
            ("category", "category", "string"),
            ("parameter_index", "parameterIndex", "integer"),
            ("type_name", "typeName", "string"),
            ("position_filename", "positionFilename", "string"),
            ("position_line", "positionLine", "integer"),
            ("position_column", "positionColumn", "integer"),
            ("properties", "properties", "string"),
        ],
    );
    render_gexf_attributes(
        &mut xml,
        "edge",
        &[
            ("source_name", "sourceName", "string"),
            ("target_name", "targetName", "string"),
            ("source_function", "sourceFunction", "string"),
            ("target_function", "targetFunction", "string"),
            ("source_package_path", "sourcePackagePath", "string"),
            ("target_package_path", "targetPackagePath", "string"),
            ("source_purl", "sourcePurl", "string"),
            ("target_purl", "targetPurl", "string"),
            ("purls", "purls", "string"),
            ("source_category", "sourceCategory", "string"),
            ("target_category", "targetCategory", "string"),
            ("path_length", "pathLength", "integer"),
            ("source_parameter_index", "sourceParameterIndex", "integer"),
            ("target_parameter_index", "targetParameterIndex", "integer"),
            ("source_type_name", "sourceTypeName", "string"),
            ("target_type_name", "targetTypeName", "string"),
            ("rule_name", "ruleName", "string"),
            ("description", "description", "string"),
            ("node_ids", "nodeIds", "string"),
            ("edge_ids", "edgeIds", "string"),
            ("properties", "properties", "string"),
        ],
    );
    xml.push_str("    <nodes>\n");
    for node in &data_flow.nodes {
        let _ = writeln!(
            xml,
            "      <node id=\"{}\" label=\"{}\">",
            xml_escape(&node.id),
            xml_escape(&node.name)
        );
        xml.push_str("        <attvalues>\n");
        push_gexf_attvalue(&mut xml, "kind", &node.kind, 5);
        push_gexf_attvalue(&mut xml, "name", &node.name, 5);
        push_gexf_attvalue(&mut xml, "package_path", &node.package_path, 5);
        push_gexf_attvalue(&mut xml, "purl", &node.purl, 5);
        push_gexf_attvalue(&mut xml, "function", &node.function, 5);
        push_gexf_attvalue(&mut xml, "source", &node.source.to_string(), 5);
        push_gexf_attvalue(&mut xml, "sink", &node.sink.to_string(), 5);
        push_gexf_attvalue(&mut xml, "category", &node.category, 5);
        push_gexf_attvalue(
            &mut xml,
            "parameter_index",
            &node
                .parameter_index
                .map(|value| value.to_string())
                .unwrap_or_default(),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "type_name",
            node.type_name.as_deref().unwrap_or(""),
            5,
        );
        push_gexf_attvalue(&mut xml, "position_filename", &node.position.filename, 5);
        push_gexf_attvalue(
            &mut xml,
            "position_line",
            &node.position.line.to_string(),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "position_column",
            &node.position.column.to_string(),
            5,
        );
        push_gexf_attvalue(&mut xml, "properties", &json_text(&node.properties), 5);
        xml.push_str("        </attvalues>\n");
        xml.push_str("      </node>\n");
    }
    xml.push_str("    </nodes>\n    <edges>\n");
    for slice in &data_flow.slices {
        let _ = writeln!(
            xml,
            "      <edge id=\"{}\" source=\"{}\" target=\"{}\" label=\"{}\">",
            xml_escape(&slice.id),
            xml_escape(&slice.source_id),
            xml_escape(&slice.sink_id),
            xml_escape(&slice.rule_name)
        );
        xml.push_str("        <attvalues>\n");
        push_gexf_attvalue(&mut xml, "source_name", &slice.source_name, 5);
        push_gexf_attvalue(&mut xml, "target_name", &slice.sink_name, 5);
        push_gexf_attvalue(&mut xml, "source_function", &slice.source_function, 5);
        push_gexf_attvalue(&mut xml, "target_function", &slice.sink_function, 5);
        push_gexf_attvalue(
            &mut xml,
            "source_package_path",
            &slice.source_package_path,
            5,
        );
        push_gexf_attvalue(&mut xml, "target_package_path", &slice.sink_package_path, 5);
        push_gexf_attvalue(&mut xml, "source_purl", &slice.source_purl, 5);
        push_gexf_attvalue(&mut xml, "target_purl", &slice.target_purl, 5);
        push_gexf_attvalue(&mut xml, "purls", &json_text(&slice.purls), 5);
        push_gexf_attvalue(&mut xml, "source_category", &slice.source_category, 5);
        push_gexf_attvalue(&mut xml, "target_category", &slice.sink_category, 5);
        push_gexf_attvalue(&mut xml, "path_length", &slice.path_length.to_string(), 5);
        push_gexf_attvalue(
            &mut xml,
            "source_parameter_index",
            &slice
                .source_parameter_index
                .map(|value| value.to_string())
                .unwrap_or_default(),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "target_parameter_index",
            &slice
                .sink_parameter_index
                .map(|value| value.to_string())
                .unwrap_or_default(),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "source_type_name",
            slice.source_type_name.as_deref().unwrap_or(""),
            5,
        );
        push_gexf_attvalue(
            &mut xml,
            "target_type_name",
            slice.sink_type_name.as_deref().unwrap_or(""),
            5,
        );
        push_gexf_attvalue(&mut xml, "rule_name", &slice.rule_name, 5);
        push_gexf_attvalue(&mut xml, "description", &slice.description, 5);
        push_gexf_attvalue(&mut xml, "node_ids", &json_text(&slice.node_ids), 5);
        push_gexf_attvalue(&mut xml, "edge_ids", &json_text(&slice.edge_ids), 5);
        push_gexf_attvalue(&mut xml, "properties", &json_text(&slice.properties), 5);
        xml.push_str("        </attvalues>\n");
        xml.push_str("      </edge>\n");
    }
    xml.push_str("    </edges>\n  </graph>\n</gexf>\n");
    xml
}

fn render_gexf_attributes(xml: &mut String, class: &str, attributes: &[(&str, &str, &str)]) {
    let _ = writeln!(xml, "    <attributes class=\"{class}\">");
    for (id, title, ty) in attributes {
        let _ = writeln!(
            xml,
            "      <attribute id=\"{}\" title=\"{}\" type=\"{}\"/>",
            xml_escape(id),
            xml_escape(title),
            xml_escape(ty)
        );
    }
    let _ = writeln!(xml, "    </attributes>");
}

fn push_graphml_data(xml: &mut String, key: &str, value: &str, indent: usize) {
    if value.is_empty() {
        return;
    }
    let _ = writeln!(
        xml,
        "{}<data key=\"{}\">{}</data>",
        "  ".repeat(indent),
        xml_escape(key),
        xml_escape(value)
    );
}

fn push_gexf_attvalue(xml: &mut String, key: &str, value: &str, indent: usize) {
    if value.is_empty() {
        return;
    }
    let _ = writeln!(
        xml,
        "{}<attvalue for=\"{}\" value=\"{}\"/>",
        "  ".repeat(indent),
        xml_escape(key),
        xml_escape(value)
    );
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\u{9}' | '\u{A}' | '\u{D}' => escaped.push(ch),
            ch if matches!(ch, '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}') => {
                escaped.push(ch)
            }
            _ => escaped.push('\u{FFFD}'),
        }
    }
    escaped
}

fn json_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

#[cfg(test)]
mod tests {
    use rusi_schema::{
        CallGraph, CallGraphEdge, CallGraphNode, DataFlowEvidence, DataFlowNode,
        DataFlowPatternSet, DataFlowSlice, DataFlowStats, Diagnostic, GraphStats, Position,
    };

    use std::path::Path;

    use super::{
        render_call_graph_gexf, render_call_graph_graphml, render_data_flow_gexf,
        render_data_flow_graphml, write_call_graph_export, write_data_flow_export, xml_escape,
    };

    #[test]
    fn xml_escape_replaces_invalid_control_characters() {
        let escaped = xml_escape("bad\u{1f}&<>'\"\n\t\r");
        assert!(!escaped.contains('\u{1f}'));
        assert!(escaped.contains('\u{FFFD}'));
        assert!(escaped.contains("&amp;"));
        assert!(escaped.contains("&lt;"));
        assert!(escaped.contains("&gt;"));
        assert!(escaped.contains("&apos;"));
        assert!(escaped.contains("&quot;"));
        assert!(escaped.contains('\n'));
        assert!(escaped.contains('\t'));
        assert!(escaped.contains('\r'));
    }

    #[test]
    fn call_graph_graphml_and_gexf_include_purls() {
        let call_graph = CallGraph {
            mode: "static".to_string(),
            nodes: vec![
                CallGraphNode {
                    id: "src".to_string(),
                    name: "main".to_string(),
                    qualified_name: "demo::main".to_string(),
                    canonical_name: "demo::main".to_string(),
                    kind: "function".to_string(),
                    package_path: "demo".to_string(),
                    purl: "pkg:cargo/demo@0.1.0".to_string(),
                    file_path: "src/main.rs".to_string(),
                    local: true,
                    external: false,
                    receiver: None,
                    position: Position {
                        filename: "src/main.rs".to_string(),
                        line: 1,
                        column: 1,
                    },
                },
                CallGraphNode {
                    id: "dst".to_string(),
                    name: "helper".to_string(),
                    qualified_name: "demo::helper".to_string(),
                    canonical_name: "demo::helper".to_string(),
                    kind: "function".to_string(),
                    package_path: "demo".to_string(),
                    purl: "pkg:cargo/demo@0.1.0".to_string(),
                    file_path: "src/helper.rs".to_string(),
                    local: true,
                    external: false,
                    receiver: None,
                    position: Position {
                        filename: "src/helper.rs".to_string(),
                        line: 1,
                        column: 1,
                    },
                },
            ],
            edges: vec![CallGraphEdge {
                id: "edge-1".to_string(),
                source_id: "src".to_string(),
                target_id: "dst".to_string(),
                call_type: "static".to_string(),
                line: 3,
                column: 5,
                callee_text: Some("helper".to_string()),
                receiver: None,
                method: None,
                candidate_count: None,
                emitted_candidate_count: None,
                properties: Default::default(),
            }],
            diagnostics: vec![Diagnostic {
                kind: "note".to_string(),
                message: "ok".to_string(),
                package_path: None,
                file_path: None,
                position: None,
            }],
            stats: GraphStats {
                node_count: 2,
                edge_count: 1,
            },
        };

        let graphml = render_call_graph_graphml(&call_graph);
        assert!(graphml.contains("sourcePurl"));
        assert!(graphml.contains("<data key=\"node_purl\">pkg:cargo/demo@0.1.0</data>"));
        assert!(graphml.contains("pkg:cargo/demo@0.1.0"));

        let gexf = render_call_graph_gexf(&call_graph);
        assert!(gexf.contains("targetPurl"));
        assert!(gexf.contains("title=\"purl\""));
        assert!(gexf.contains("pkg:cargo/demo@0.1.0"));
    }

    #[test]
    fn data_flow_graphml_and_gexf_include_slice_purls() {
        let data_flow = DataFlowEvidence {
            mode: "security".to_string(),
            patterns: DataFlowPatternSet::default(),
            nodes: vec![
                DataFlowNode {
                    id: "src-node".to_string(),
                    kind: "source".to_string(),
                    name: "APP_CMD".to_string(),
                    package_path: "demo".to_string(),
                    purl: "pkg:cargo/demo@0.1.0".to_string(),
                    function: "demo::main".to_string(),
                    position: Position {
                        filename: "src/main.rs".to_string(),
                        line: 1,
                        column: 1,
                    },
                    source: true,
                    sink: false,
                    category: "env".to_string(),
                    parameter_index: None,
                    type_name: Some("String".to_string()),
                    properties: Default::default(),
                },
                DataFlowNode {
                    id: "sink-node".to_string(),
                    kind: "sink".to_string(),
                    name: "Command::new".to_string(),
                    package_path: "demo".to_string(),
                    purl: "pkg:cargo/demo@0.1.0".to_string(),
                    function: "demo::run".to_string(),
                    position: Position {
                        filename: "src/main.rs".to_string(),
                        line: 4,
                        column: 3,
                    },
                    source: false,
                    sink: true,
                    category: "process-exec".to_string(),
                    parameter_index: Some(0),
                    type_name: Some("String".to_string()),
                    properties: Default::default(),
                },
            ],
            edges: Vec::new(),
            slices: vec![DataFlowSlice {
                id: "slice-1".to_string(),
                source_id: "src-node".to_string(),
                sink_id: "sink-node".to_string(),
                source_name: "APP_CMD".to_string(),
                sink_name: "Command::new".to_string(),
                source_function: "demo::main".to_string(),
                sink_function: "demo::run".to_string(),
                source_package_path: "demo".to_string(),
                sink_package_path: "demo".to_string(),
                source_purl: "pkg:cargo/demo@0.1.0".to_string(),
                target_purl: "pkg:cargo/demo@0.1.0".to_string(),
                purls: vec!["pkg:cargo/demo@0.1.0".to_string()],
                source_category: "env".to_string(),
                sink_category: "process-exec".to_string(),
                node_ids: vec!["src-node".to_string(), "sink-node".to_string()],
                edge_ids: vec!["edge-1".to_string()],
                path_length: 1,
                source_parameter_index: None,
                sink_parameter_index: Some(0),
                source_type_name: Some("String".to_string()),
                sink_type_name: Some("String".to_string()),
                rule_name: "env-to-process-exec".to_string(),
                description: "env can reach exec".to_string(),
                properties: Default::default(),
            }],
            summaries: Vec::new(),
            diagnostics: Vec::new(),
            stats: DataFlowStats::default(),
        };

        let graphml = render_data_flow_graphml(&data_flow);
        assert!(graphml.contains("targetPurl"));
        assert!(graphml.contains("<data key=\"node_purl\">pkg:cargo/demo@0.1.0</data>"));
        assert!(graphml.contains("env-to-process-exec"));

        let gexf = render_data_flow_gexf(&data_flow);
        assert!(gexf.contains("sourcePurl"));
        assert!(gexf.contains("title=\"purl\""));
        assert!(gexf.contains("pkg:cargo/demo@0.1.0"));

        // The JSON format streams straight to disk; verify it round-trips.
        let dir = std::env::temp_dir().join(format!(
            "rusi-export-json-{}",
            data_flow.slices.len() as u64 + data_flow.nodes.len() as u64
        ));
        let path = dir.join("data_flow.json");
        write_data_flow_export(&data_flow, "json", &path, false).expect("json export succeeds");
        let written = std::fs::read_to_string(&path).expect("read json export");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        let parsed: DataFlowEvidence =
            serde_json::from_str(&written).expect("json export round-trips");
        assert_eq!(parsed, data_flow);
    }

    #[test]
    fn json_export_creates_parent_directories_and_round_trips() {
        let call_graph = CallGraph {
            mode: "static".to_string(),
            nodes: vec![CallGraphNode {
                id: "src".to_string(),
                ..CallGraphNode::default()
            }],
            edges: Vec::new(),
            diagnostics: Vec::new(),
            stats: GraphStats {
                node_count: 1,
                edge_count: 0,
            },
        };

        let dir = std::env::temp_dir().join("rusi-export-json-nested/inner");
        let path = dir.join("call_graph.json");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap_or_else(|| Path::new(".")));

        write_call_graph_export(&call_graph, "json", &path, false)
            .expect("json export creates parents");
        let written = std::fs::read_to_string(&path).expect("read json export");
        let parsed: CallGraph = serde_json::from_str(&written).expect("json export round-trips");
        assert_eq!(parsed, call_graph);

        let _ = std::fs::remove_dir_all(dir.parent().unwrap_or_else(|| Path::new(".")));
    }
}
