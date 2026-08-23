use std::ops::Range;
use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Build the deterministic identifier used for every entity in a report.
///
/// The identifier is `<prefix>-<16 hex chars>`, where the hex is the first
/// eight bytes of the SHA-256 of `components` joined by a NUL byte. The NUL
/// separator is what makes the hash unambiguous: without it, the component
/// lists `["ab", "c"]` and `["a", "bc"]` would collide.
///
/// Identifiers are stable across runs and across machines for the same
/// inputs, so consumers can diff two reports by id. They are *not* stable
/// across changes to the component list a caller passes in.
pub fn stable_id(prefix: &str, components: &[&str]) -> String {
    // Lowercase nibble table. Formatting each byte with `format!("{byte:02x}")`
    // would allocate a throwaway `String` per byte, and this function runs once
    // per declaration, usage, signal, node, and edge in the report.
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut hasher = Sha256::new();
    for component in components {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        hex.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        hex.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    format!("{prefix}-{hex}")
}

/// Render `path` relative to `root`, always with `/` separators.
///
/// Paths in a report are display strings meant to be compared and joined by
/// consumers, so they are normalized to forward slashes on every platform: a
/// report produced on Windows names the same file as one produced on Linux.
/// A `path` that does not live under `root` is returned unchanged rather than
/// rewritten, so absolute paths outside the analysis root stay recognizable.
pub fn relative_display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

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
    work = work.replace("&mut ", "").replace(['&', '(', ')', ' '], "");
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

/// Find a needle outside any `<...>` group, returning the byte range it spans.
///
/// The range rather than the start index is returned so callers can slice
/// either side of the match without restating the needle's length.
fn find_top_level(name: &str, needle: &str) -> Option<Range<usize>> {
    let bytes = name.as_bytes();
    let mut depth: i32 = 0;
    let mut idx = 0usize;
    while idx + needle.len() <= bytes.len() {
        match bytes[idx] {
            b'<' => depth += 1,
            b'>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ if depth == 0 && name[idx..].starts_with(needle) => {
                return Some(idx..idx + needle.len());
            }
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
                // `impl Trait for Type` names the implementing type after `for`.
                if let Some(separator) = find_top_level(body, " for ") {
                    implementing = body[separator.end..].to_string();
                } else {
                    implementing = body.to_string();
                }
            } else if let Some(separator) = find_top_level(&implementing, " as ") {
                // `Type as Trait` names the implementing type before `as`.
                implementing = implementing[..separator.start].to_string();
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
    /// Ceiling on call-graph edges emitted per ambiguous call site (`0` means
    /// no cap). Edges at a site that hit the ceiling carry `candidateCount` and
    /// `candidatesTruncated`, so a consumer can tell a sampled site from a
    /// fully enumerated one.
    #[serde(default = "default_max_call_candidates")]
    pub max_call_candidates: usize,
}

fn default_max_call_candidates() -> usize {
    8
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
    /// The `#[cfg(...)]` gate this declaration sits behind, as written, when it
    /// is conditional. Absent for unconditional declarations. Consumers can use
    /// it to report a finding as reachable only under a given feature or target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cfg_gate: Option<String>,
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
    /// The `#[cfg(...)]` gate this signal sits behind, as written, when it is
    /// conditional. See [`Declaration::cfg_gate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cfg_gate: Option<String>,
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
/// One call-site edge.
///
/// Edges are normalized against [`CallGraphNode`]: the endpoints' names, purls,
/// and file are read from the referenced nodes rather than repeated here. On a
/// large workspace those repeated fields were the single largest part of the
/// report (61 MB of 132 MB of edge bytes on wasm-tools 1.247.0), and every one
/// of them was byte-identical to a field already on the node.
///
/// To read an edge, index `CallGraph::nodes` by `source_id`/`target_id`:
///
/// - source symbol -> source node's `qualified_name`
/// - target symbol -> target node's `qualified_name`
/// - source/target purl -> the nodes' `purl`
/// - call-site file -> the **source** node's `file_path`; `line`/`column` on the
///   edge locate the call within it.
pub struct CallGraphEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    /// How the target was resolved: `static`, `receiver-typed`, `trait-impl`,
    /// `static-overapprox`, `trait-overapprox`, `higher-order`, `external`, or a
    /// compiler-backend dispatch label. `confidence` is a function of this (see
    /// [`call_type_confidence`]) and is therefore not stored per edge.
    pub call_type: String,
    /// Call-site line within the source node's file, 1-based.
    pub line: usize,
    /// Call-site column within the source node's file, 1-based.
    pub column: usize,
    /// Callee path as written at the call site, after import resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee_text: Option<String>,
    /// Receiver expression text, for method calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// Bare method name, for method calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Total local candidates this call site resolved to, when more than one.
    /// Always the true count, even when the emitted edges were capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_count: Option<usize>,
    /// Edges actually emitted for this call site. Present only when the site hit
    /// the `max_call_candidates` ceiling, so its presence means "these edges are
    /// a sample of `candidate_count`, not the whole set".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitted_candidate_count: Option<usize>,
    /// Backend-specific extras (compiler-backend dispatch metadata). Empty for
    /// everything the stable backend models with the typed fields above.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, String>,
}

impl CallGraph {
    /// Looks up a node by id. Edges reference their endpoints this way.
    pub fn node(&self, id: &str) -> Option<&CallGraphNode> {
        self.nodes.iter().find(|node| node.id == id)
    }

    /// Qualified name of an edge's source symbol.
    pub fn source_name(&self, edge: &CallGraphEdge) -> &str {
        self.node(&edge.source_id)
            .map(|node| node.qualified_name.as_str())
            .unwrap_or_default()
    }

    /// Qualified name of an edge's target symbol.
    pub fn target_name(&self, edge: &CallGraphEdge) -> &str {
        self.node(&edge.target_id)
            .map(|node| node.qualified_name.as_str())
            .unwrap_or_default()
    }

    /// File the call site sits in: the source node's file.
    pub fn call_site_file(&self, edge: &CallGraphEdge) -> &str {
        self.node(&edge.source_id)
            .map(|node| node.file_path.as_str())
            .unwrap_or_default()
    }
}

/// Coarse confidence implied by an edge's `call_type`.
///
/// Stored as a function rather than a per-edge string: it never carried
/// information the `call_type` did not.
/// Covers both backends. The stable backend emits a bare provenance name; the
/// compiler backend suffixes it with how many targets the call resolved to
/// (`static-exact`, `dyn-dispatch-bounded`, `…-unknown`), and that suffix is
/// the more informative half — without reading it, an exactly resolved
/// compiler-backend edge fell through to `low`.
pub fn call_type_confidence(call_type: &str) -> &'static str {
    if let Some(base) = call_type.strip_suffix("-exact") {
        return if base.is_empty() { "low" } else { "high" };
    }
    if call_type.ends_with("-bounded") {
        return "medium";
    }
    if call_type.ends_with("-unknown") {
        return "low";
    }
    match call_type {
        "static" | "trait-impl" | "higher-order" => "high",
        "receiver-typed" => "medium",
        _ => "low",
    }
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
    /// Restricts the pattern to a method call whose receiver has this type.
    ///
    /// Without it, a sink named after a common builder method would fire on
    /// every type that happens to share the name: `arg` is `Command::arg` on a
    /// `Command`, and something else entirely on any other builder. With it,
    /// `Command::new(x).arg(tainted)` is a process-exec sink while
    /// `some_other_builder.arg(x)` is not.
    ///
    /// For a method call, argument 0 is the receiver, so the first real argument
    /// is index 1 in `relevant_arguments`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_type: Option<String>,
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

    #[test]
    fn finds_the_separator_outside_generic_arguments() {
        // ` for ` and ` as ` must be located at nesting depth zero. A naive
        // search would stop at the one inside `HashMap<K, V>`-style arguments
        // and slice the name in the wrong place.
        assert_eq!(
            canonical_name("<impl myapp::Sink<Box<dyn Trait>> for myapp::Widget>::write"),
            "myapp::Widget::write"
        );
        assert_eq!(
            canonical_name("<myapp::Widget<Box<dyn Trait>> as core::fmt::Debug>::fmt"),
            "myapp::Widget::fmt"
        );
    }

    #[test]
    fn slices_exactly_at_the_separator_boundaries() {
        // Regression cover for the offsets around the separator: an off-by-one
        // would leave a stray space or eat the first character of the type.
        // Any leakage would survive into the output, since only whitespace
        // inside the name is stripped later.
        assert_eq!(
            canonical_name("<impl Trait for myapp::Widget>::method"),
            "myapp::Widget::method"
        );
        assert_eq!(
            canonical_name("<myapp::Widget as Trait>::method"),
            "myapp::Widget::method"
        );
    }

    #[test]
    fn reduces_a_bare_inherent_impl_block() {
        // `impl Type` with no `for` clause: the whole body is the type.
        assert_eq!(
            canonical_name("<impl myapp::Widget>::method"),
            "myapp::Widget::method"
        );
    }

    #[test]
    fn reduces_nested_qualified_selves() {
        // The reduction recurses, so a qualifier whose implementing type is
        // itself qualified collapses all the way down.
        assert_eq!(
            canonical_name("<<myapp::Widget as Trait>::Assoc as core::fmt::Debug>::fmt"),
            "myapp::Widget::Assoc::fmt"
        );
    }
}

/// Tests for the report-identity helpers shared by every backend.
#[cfg(test)]
mod stable_id_tests {
    use std::path::{Path, PathBuf};

    use super::{relative_display_path, stable_id};

    #[test]
    fn has_the_documented_shape() {
        let id = stable_id("decl", &["demo", "demo::main"]);
        let (prefix, hex) = id
            .split_once('-')
            .expect("prefix and hex are dash-separated");
        assert_eq!(prefix, "decl");
        assert_eq!(hex.len(), 16, "eight bytes render as sixteen hex chars");
        assert!(
            hex.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
            "hex must be lowercase: {hex}"
        );
    }

    #[test]
    fn is_deterministic_across_calls() {
        assert_eq!(
            stable_id("signal", &["src/lib.rs", "extern-block", "10:5"]),
            stable_id("signal", &["src/lib.rs", "extern-block", "10:5"])
        );
    }

    #[test]
    fn distinguishes_component_boundaries() {
        // The NUL separator is what makes this hold. Concatenating the
        // components without it would hash both lists identically, so two
        // different declarations would share an id and one would be
        // deduplicated out of the report.
        assert_ne!(stable_id("x", &["ab", "c"]), stable_id("x", &["a", "bc"]));
        assert_ne!(stable_id("x", &["a", ""]), stable_id("x", &["", "a"]));
        assert_ne!(stable_id("x", &["a"]), stable_id("x", &["a", ""]));
    }

    #[test]
    fn distinguishes_prefixes_but_not_by_hash() {
        // The prefix labels the entity kind; it is not hashed, so the same
        // components under two prefixes share the hex.
        let declaration = stable_id("decl", &["a"]);
        let signal = stable_id("signal", &["a"]);
        assert_ne!(declaration, signal);
        assert_eq!(
            declaration.split_once('-').expect("dash").1,
            signal.split_once('-').expect("dash").1
        );
    }

    #[test]
    fn empty_components_are_accepted() {
        assert!(stable_id("decl", &[]).starts_with("decl-"));
    }

    #[test]
    fn matches_the_hex_encoding_it_replaced() {
        // Guards the nibble-table encoding against the `format!("{byte:02x}")`
        // loop it replaced: zero bytes must still render as two digits.
        let id = stable_id("t", &["\u{0}"]);
        let hex = id.split_once('-').expect("dash").1;
        assert_eq!(hex.len(), 16);
    }

    #[test]
    fn renders_a_path_under_the_root_relatively() {
        let root = PathBuf::from("repo");
        let file = root.join("src").join("lib.rs");
        // Forward slashes on every platform, including Windows.
        assert_eq!(relative_display_path(&root, &file), "src/lib.rs");
    }

    #[test]
    fn renders_the_root_itself_as_empty() {
        let root = PathBuf::from("repo");
        assert_eq!(relative_display_path(&root, &root), "");
    }

    #[test]
    fn leaves_a_path_outside_the_root_unchanged() {
        // A path that is not under the root stays recognizable rather than
        // being silently rewritten into a misleading relative path.
        let root = PathBuf::from("repo");
        let outside = PathBuf::from("elsewhere").join("main.rs");
        assert_eq!(relative_display_path(&root, &outside), "elsewhere/main.rs");
    }

    #[test]
    fn normalizes_backslashes_to_forward_slashes() {
        // Windows path separators must not leak into a report, so that the
        // same file is named identically wherever the analysis ran.
        assert_eq!(
            relative_display_path(
                Path::new("nonexistent-root"),
                Path::new(r"src\nested\lib.rs")
            ),
            "src/nested/lib.rs"
        );
    }
}
