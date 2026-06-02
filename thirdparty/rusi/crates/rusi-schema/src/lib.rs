use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Position {
    pub filename: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub rustc_version: String,
    pub cargo_version: String,
    pub host: String,
    pub working_directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AnalysisOptions {
    pub directory: String,
    pub backend: String,
    #[serde(default = "default_analysis_scope")]
    pub analysis_scope: String,
    pub call_graph_mode: String,
    pub data_flow_mode: String,
    pub include_tests: bool,
}

fn default_analysis_scope() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ModuleRef {
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub workspace_member: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ImportUsage {
    pub path: String,
    pub alias: Option<String>,
    pub package_path: String,
    pub purl: String,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Declaration {
    pub id: String,
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub package_path: String,
    pub purl: String,
    pub file_path: String,
    pub signature: String,
    pub receiver: Option<String>,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LibraryUsage {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub package_path: String,
    pub purl: String,
    pub enclosing_declaration: Option<String>,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CryptoLibrary {
    pub id: String,
    pub path: String,
    pub family: String,
    pub package_path: String,
    pub file_path: String,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CryptoComponent {
    pub id: String,
    pub kind: String,
    pub algorithm: String,
    pub provider: String,
    pub operation: String,
    pub symbol: String,
    pub package_path: String,
    pub file_path: String,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CryptoMaterial {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub package_path: String,
    pub file_path: String,
    pub function: String,
    pub confidence: String,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CryptoFinding {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub summary: String,
    pub package_path: String,
    pub file_path: String,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CryptoEvidence {
    pub libraries: Vec<CryptoLibrary>,
    pub components: Vec<CryptoComponent>,
    pub materials: Vec<CryptoMaterial>,
    pub findings: Vec<CryptoFinding>,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecuritySignal {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub description: String,
    pub package_path: String,
    pub purl: String,
    pub file_path: String,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FileEvidence {
    pub path: String,
    pub package_name: String,
    pub package_path: String,
    pub purl: String,
    pub imports: Vec<ImportUsage>,
    pub declarations: Vec<Declaration>,
    pub usages: Vec<LibraryUsage>,
    pub security_signals: Vec<SecuritySignal>,
    pub crypto: Option<CryptoEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PackageEvidence {
    pub id: String,
    pub name: String,
    pub package_path: String,
    pub purl: String,
    pub manifest_path: String,
    pub module: ModuleRef,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: String,
    pub message: String,
    pub package_path: Option<String>,
    pub file_path: Option<String>,
    pub position: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CallGraphNode {
    pub id: String,
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub package_path: String,
    pub purl: String,
    pub file_path: String,
    pub local: bool,
    pub external: bool,
    pub receiver: Option<String>,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CallGraphEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub source_name: String,
    pub target_name: String,
    #[serde(rename = "sourcePurl")]
    pub source_purl: String,
    #[serde(rename = "targetPurl")]
    pub target_purl: String,
    pub purls: Vec<String>,
    pub call_type: String,
    pub position: Position,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CallGraph {
    pub mode: String,
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: GraphStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DataFlowPattern {
    #[serde(default)]
    pub target: String,
    pub pattern: String,
    pub category: String,
    #[serde(default)]
    pub relevant_arguments: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct DataFlowPatternSet {
    pub sources: Vec<DataFlowPattern>,
    pub sinks: Vec<DataFlowPattern>,
    pub passthroughs: Vec<DataFlowPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DataFlowNode {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub package_path: String,
    pub purl: String,
    pub function: String,
    pub position: Position,
    pub source: bool,
    pub sink: bool,
    pub category: String,
    pub parameter_index: Option<usize>,
    pub type_name: Option<String>,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DataFlowEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub kind: String,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DataFlowSlice {
    pub id: String,
    pub source_id: String,
    pub sink_id: String,
    pub source_name: String,
    pub sink_name: String,
    pub source_function: String,
    pub sink_function: String,
    pub source_package_path: String,
    pub sink_package_path: String,
    #[serde(rename = "sourcePurl")]
    pub source_purl: String,
    #[serde(rename = "targetPurl")]
    pub target_purl: String,
    pub purls: Vec<String>,
    pub source_category: String,
    pub sink_category: String,
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
    pub path_length: usize,
    pub source_parameter_index: Option<usize>,
    pub sink_parameter_index: Option<usize>,
    pub source_type_name: Option<String>,
    pub sink_type_name: Option<String>,
    pub rule_name: String,
    pub description: String,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DataFlowMethodSummary {
    pub function_id: String,
    pub function: String,
    pub package_path: String,
    pub purl: String,
    pub parameter_names: Vec<String>,
    pub parameter_types: Vec<String>,
    pub return_type: String,
    pub param_to_return: Vec<usize>,
    pub param_to_sink: IndexMap<String, Vec<usize>>,
    pub source_returns: Vec<String>,
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct DataFlowStats {
    pub source_count: usize,
    pub sink_count: usize,
    pub slice_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub summary_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct DataFlowEvidence {
    pub mode: String,
    pub patterns: DataFlowPatternSet,
    pub nodes: Vec<DataFlowNode>,
    pub edges: Vec<DataFlowEdge>,
    pub slices: Vec<DataFlowSlice>,
    pub summaries: Vec<DataFlowMethodSummary>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: DataFlowStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CompilerEvidence {
    pub diagnostics: Vec<Diagnostic>,
    pub files: Vec<FileEvidence>,
    pub imports: Vec<ImportUsage>,
    pub declarations: Vec<Declaration>,
    pub usages: Vec<LibraryUsage>,
    pub security_signals: Vec<SecuritySignal>,
    pub crypto: Option<CryptoEvidence>,
    pub call_graph: Option<CallGraph>,
    pub data_flow: Option<DataFlowEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Stats {
    pub package_count: usize,
    pub file_count: usize,
    pub import_count: usize,
    pub declaration_count: usize,
    pub usage_count: usize,
    pub security_signal_count: usize,
    pub crypto_library_count: usize,
    pub crypto_component_count: usize,
    pub crypto_material_count: usize,
    pub crypto_finding_count: usize,
    pub call_graph_node_count: usize,
    pub call_graph_edge_count: usize,
    pub data_flow_node_count: usize,
    pub data_flow_edge_count: usize,
    pub data_flow_slice_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Report {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub runtime: RuntimeInfo,
    pub options: AnalysisOptions,
    pub modules: Vec<ModuleRef>,
    pub packages: Vec<PackageEvidence>,
    pub files: Vec<FileEvidence>,
    pub imports: Vec<ImportUsage>,
    pub declarations: Vec<Declaration>,
    pub usages: Vec<LibraryUsage>,
    pub security_signals: Vec<SecuritySignal>,
    pub crypto: Option<CryptoEvidence>,
    pub call_graph: Option<CallGraph>,
    pub data_flow: Option<DataFlowEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
