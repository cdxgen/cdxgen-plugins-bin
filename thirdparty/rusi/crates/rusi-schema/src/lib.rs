use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Reduce a qualified Rust function name to a stable canonical form.
///
/// The canonical form is generic-free, lifetime-free, and hash-free, of the
/// shape `crate::module::Type::method`. It is the join key used to match a
/// source callgraph against a binary callgraph: emitting it here means
/// consumers do not have to re-implement Rust naming normalization, and the
/// match key stays authoritative and stable across tool versions.
///
/// The transformation is deliberately lossy:
/// * trailing compiler disambiguation hashes (`::h1a2b..`) and LLVM thunk
///   suffixes (`.llvm.123..`) are removed,
/// * a leading trait/impl qualifier is reduced to the implementing type
///   (`<Type as Trait>::m` -> `Type::m`, `<impl Trait for Type>` -> `Type`),
/// * generic argument groups, lifetimes, reference and mutability markers, and
///   whitespace are stripped, collapsing every monomorphized instance onto the
///   single source definition it came from.
pub fn canonical_name(qualified_name: &str) -> String {
    let mut work = qualified_name.trim().to_string();
    if work.is_empty() {
        return String::new();
    }
    work = strip_hash_suffix(&work);
    work = strip_llvm_suffix(&work);
    work = reduce_qualified_self(&work);
    work = strip_generics(&work);
    work = strip_lifetimes(&work);
    work = work
        .replace("&mut ", "")
        .replace('&', "")
        .replace('(', "")
        .replace(')', "")
        .replace(' ', "");
    collapse_separators(&work)
}

/// Remove a trailing `::h<hex>` Rust symbol-hash segment.
fn strip_hash_suffix(name: &str) -> String {
    if let Some(idx) = name.rfind("::h") {
        let suffix = &name[idx + 3..];
        if suffix.len() >= 8 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return name[..idx].to_string();
        }
    }
    name.to_string()
}

/// Remove a trailing `.llvm.<digits>` thunk suffix.
fn strip_llvm_suffix(name: &str) -> String {
    if let Some(idx) = name.rfind(".llvm.") {
        let suffix = &name[idx + 6..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return name[..idx].to_string();
        }
    }
    name.to_string()
}

/// Find a needle outside any `<...>` group, returning its byte index.
fn find_top_level(name: &str, needle: &str) -> Option<usize> {
    let bytes = name.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut depth: i32 = 0;
    let mut idx = 0usize;
    while idx + needle_bytes.len() <= bytes.len() {
        match bytes[idx] {
            b'<' => depth += 1,
            b'>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ if depth == 0 && name[idx..].starts_with(needle) => return Some(idx),
            _ => {}
        }
        idx += 1;
    }
    None
}

/// Split a leading balanced `<...>` group into (inner, rest).
fn split_balanced_angle(name: &str) -> Option<(String, String)> {
    if !name.starts_with('<') {
        return None;
    }
    let bytes = name.as_bytes();
    let mut depth = 0i32;
    for (idx, &ch) in bytes.iter().enumerate() {
        match ch {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return Some((name[1..idx].to_string(), name[idx + 1..].to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Reduce `<Type as Trait>::m` / `<impl Trait for Type>::m` to the implementing type.
fn reduce_qualified_self(name: &str) -> String {
    match split_balanced_angle(name) {
        None => name.to_string(),
        Some((inner, rest)) => {
            let mut implementing = inner.trim().to_string();
            if let Some(body) = implementing.strip_prefix("impl ") {
                if let Some(for_idx) = find_top_level(body, " for ") {
                    implementing = body[for_idx + 5..].to_string();
                } else {
                    implementing = body.to_string();
                }
            } else if let Some(as_idx) = find_top_level(&implementing, " as ") {
                implementing = implementing[..as_idx].to_string();
            }
            format!("{}{}", reduce_qualified_self(implementing.trim()), rest)
        }
    }
}

/// Remove balanced `<...>` generic argument groups.
fn strip_generics(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0i32;
    for ch in name.chars() {
        match ch {
            '<' => depth += 1,
            '>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Remove lifetime tokens such as `'a` and `'_`.
fn strip_lifetimes(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            // Drop the lifetime identifier that follows the quote.
            while let Some(&next) = chars.peek() {
                if next == '_' || next.is_alphanumeric() {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Collapse runs of three or more `:` to `::` and trim leading/trailing colons.
fn collapse_separators(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut colon_run = 0usize;
    for ch in name.chars() {
        if ch == ':' {
            colon_run += 1;
        } else {
            if colon_run > 0 {
                out.push_str("::");
                colon_run = 0;
            }
            out.push(ch);
        }
    }
    if colon_run > 0 {
        out.push_str("::");
    }
    out.trim_matches(':').to_string()
}

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
    #[serde(default)]
    pub canonical_name: String,
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

/// One parameter to an HTTP endpoint, extracted from the handler's
/// signature. `location` is `path` or `query`; `type_name` is the Rust
/// type spelled as written (e.g. `i32`, `String`, `Option<bool>`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EndpointParameter {
    pub name: String,
    pub location: String,
    pub type_name: String,
}

/// Structured HTTP API endpoint discovered in source code.
///
/// Populated by the api-discovery pass when an HTTP framework (axum,
/// actix-web, rocket; warp planned) is detected. Each entry represents one
/// fully-resolved route registration: HTTP method, path with any prefixes
/// from nested routers already composed in, the handler function it
/// dispatches to, and — when the handler's signature can be resolved —
/// the request/response shape pulled from the handler's parameter and
/// return types.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ApiEndpoint {
    pub id: String,
    pub method: String,
    pub path: String,
    pub framework: String,
    pub handler: String,
    pub package_path: String,
    pub purl: String,
    pub file_path: String,
    pub position: Position,
    #[serde(default)]
    pub parameters: Vec<EndpointParameter>,
    #[serde(default)]
    pub request_body_type: Option<String>,
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub properties: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FileEvidence {
    pub path: String,
    pub package_name: String,
    pub package_path: String,
    pub purl: String,
    // These per-file collections duplicate the flattened, canonical top-level
    // `Report.imports/declarations/usages/security_signals` (every item carries
    // `file_path`/`position.filename` for file association). The producers
    // populate both, but the report finalizer clears these to avoid emitting the
    // same data twice (~38 MB on large targets). They remain in the type so the
    // compiler backend and merger can accumulate per-file evidence internally;
    // `skip_serializing_if` keeps them out of the serialized report when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<ImportUsage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declarations: Vec<Declaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usages: Vec<LibraryUsage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    #[serde(default)]
    pub canonical_name: String,
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
    #[serde(default)]
    pub api_endpoint_count: usize,
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
    #[serde(default)]
    pub api_endpoints: Vec<ApiEndpoint>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

impl Report {
    /// Populate `canonical_name` for every declaration and callgraph node from
    /// its `qualified_name`. Call this once the report is fully assembled, just
    /// before serialization, so the canonical match key is always present and
    /// consistent regardless of where the nodes were constructed.
    pub fn fill_canonical_names(&mut self) {
        for declaration in &mut self.declarations {
            declaration.canonical_name = canonical_name(&declaration.qualified_name);
        }
        if let Some(call_graph) = self.call_graph.as_mut() {
            for node in &mut call_graph.nodes {
                node.canonical_name = canonical_name(&node.qualified_name);
            }
        }
    }
}

#[cfg(test)]
mod canonical_name_tests {
    use super::canonical_name;

    #[test]
    fn reduces_trait_qualified_self() {
        assert_eq!(
            canonical_name("<wasm_tools::dump::Dump as core::fmt::Debug>::fmt"),
            "wasm_tools::dump::Dump::fmt"
        );
    }

    #[test]
    fn strips_generics_and_hash() {
        assert_eq!(
            canonical_name("alloc::vec::Vec<u8>::push::h1a2b3c4d5e6f7a8b"),
            "alloc::vec::Vec::push"
        );
    }

    #[test]
    fn reduces_impl_for_block_and_lifetimes() {
        assert_eq!(
            canonical_name("<impl core::fmt::Debug for myapp::Widget<'a>>::fmt"),
            "myapp::Widget::fmt"
        );
    }

    #[test]
    fn collapses_monomorphized_instances() {
        assert_eq!(
            canonical_name("alloc::vec::Vec<myapp::Token>::push"),
            canonical_name("alloc::vec::Vec<u8>::push")
        );
    }

    #[test]
    fn passes_through_plain_names() {
        assert_eq!(canonical_name("wasm_tools::main"), "wasm_tools::main");
        assert_eq!(canonical_name(""), "");
    }
}
