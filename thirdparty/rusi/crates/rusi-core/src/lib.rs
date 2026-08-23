use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use indexmap::IndexMap;
use proc_macro2::Span;
use quote::ToTokens;
use rusi_schema::{
    AnalysisOptions, CallGraph, CallGraphEdge, CallGraphNode, CryptoComponent, CryptoEvidence,
    CryptoFinding, CryptoLibrary, CryptoMaterial, DataFlowEdge, DataFlowEvidence,
    DataFlowMethodSummary, DataFlowNode, DataFlowPattern, DataFlowPatternSet, DataFlowSlice,
    DataFlowStats, Declaration, Diagnostic, FileEvidence, GraphStats, ImportUsage, LibraryUsage,
    ModuleRef, PackageEvidence, Position, Report, RuntimeInfo, SecuritySignal, Stats, ToolInfo,
};
pub(crate) use rusi_schema::{relative_display_path, stable_id};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Expr, ExprAsync, ExprBlock, ExprCall, ExprClosure, ExprField, ExprLit, ExprMacro,
    ExprMethodCall, ExprParen, ExprPath, ExprReference, ExprReturn, ExprTuple, FnArg, ImplItem,
    Item, ItemFn, ItemImpl, ItemMod, Lit, Pat, PatIdent, PatType, ReturnType, Signature, Stmt,
    Token, UseRename, UseTree,
};

mod api_discovery;
mod cfg;
mod import_resolution;
mod modeling;
mod module_tree;

use api_discovery::discover_api_endpoints;
use cfg::{CfgEvaluator, CfgExpr, CfgOptions};
use import_resolution::{ImportResolution, ItemTable, UseRecord, collect_use_records};
pub use modeling::{AnalysisScope, load_custom_pattern_set};
use modeling::{crypto_only_pattern_set, merge_pattern_sets, retain_crypto_focus};

const SCHEMA_VERSION: &str = "https://appthreat.github.io/rusi/schema/report-0.1";
const TOOL_NAME: &str = "rusi";
const TOOL_DESCRIPTION: &str = "Rust source analysis inspector";

pub const BACKEND_STABLE: &str = "stable";
pub const BACKEND_COMPILER: &str = "compiler";
pub const DATAFLOW_SECURITY: &str = "security";
pub const DATAFLOW_SECURITY_DEPS: &str = "security-deps";

/// Stable bootstrap configuration for the first `rusi` engine.
///
/// This implementation intentionally uses Cargo metadata plus parsed Rust
/// source so the schema/orchestrator and review workflow can move forward on
/// stable toolchains. A future compiler-backed HIR/MIR engine can plug into the
/// same orchestration layer and schema.
#[derive(Debug, Clone)]
pub struct AnalyzeOptionsInput {
    pub dir: PathBuf,
    pub backend: String,
    pub analysis_scope: AnalysisScope,
    pub call_graph_mode: String,
    pub data_flow_mode: String,
    pub custom_data_flow_patterns: Option<DataFlowPatternSet>,
    pub include_tests: bool,
    pub debug: bool,
    /// Maximum call-graph edges emitted for one ambiguous call site.
    ///
    /// An unresolved bare method name matches every same-named candidate in
    /// the workspace, and emitting the full cross product dominates both the
    /// report size and peak memory (on wasm-tools: 97% of 1.15M edges, 785 MB
    /// of a 790 MB report) without telling a consumer anything a candidate
    /// count would not. Over-approximated sites are truncated to this many
    /// edges, ordered so the most plausible targets survive, and the surviving
    /// edges carry the true `candidateCount` plus `candidatesTruncated`.
    ///
    /// `0` disables the cap and restores the full cross product. Exactly
    /// resolved sites (`static`, `trait-impl`, `receiver-typed`,
    /// `higher-order`, `external`) are never capped.
    pub max_call_candidates: usize,
    /// Also analyze the resolved dependency crates, not just the workspace.
    ///
    /// Dependencies are analyzed at a lighter tier by default: their `lib`
    /// target only, and declarations/imports/impls/usage evidence without
    /// function bodies. That is enough to resolve a workspace call *into* a
    /// dependency, which is otherwise reported as merely external. Bodies —
    /// needed for taint to flow *through* a dependency — are collected only
    /// under the `security-deps` data-flow mode, because a dependency closure is
    /// typically an order of magnitude larger than the workspace (283 packages
    /// and 5,913 files against 28 and 375, on wasm-tools 1.247.0).
    pub include_dependencies: bool,
}

/// Default ceiling on edges emitted per ambiguous call site.
pub const DEFAULT_MAX_CALL_CANDIDATES: usize = 8;

impl Default for AnalyzeOptionsInput {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("."),
            backend: BACKEND_STABLE.to_string(),
            analysis_scope: AnalysisScope::Default,
            call_graph_mode: "static".to_string(),
            data_flow_mode: DATAFLOW_SECURITY.to_string(),
            custom_data_flow_patterns: None,
            include_tests: false,
            debug: false,
            max_call_candidates: crate::DEFAULT_MAX_CALL_CANDIDATES,
            include_dependencies: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompilerBackendPayload {
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

#[derive(Debug, Clone, Default)]
struct RuntimeVersions {
    rustc_version: String,
    cargo_version: String,
    host: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PackageContext {
    pub(crate) package_name: String,
    pub(crate) crate_name: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) root_dir: PathBuf,
    pub(crate) src_dir: PathBuf,
    pub(crate) module_ref: ModuleRef,
    /// False for a resolved dependency: it gets the lighter analysis tier.
    pub(crate) workspace_member: bool,
}

#[derive(Debug, Clone)]
struct FileContext {
    package_name: String,
    /// Owning package's crate name. Used for grouping and purl resolution, so
    /// it stays the package identity even for files that belong to a
    /// non-library target.
    package_path: String,
    /// Crate name of the Cargo target that owns this file, and therefore the
    /// root of every qualified name in it.
    ///
    /// Each `bin`/`example`/`test` target is its own crate, so `src/bin/a.rs`
    /// and `src/bin/b.rs` must not share a qualified-name root: they both
    /// define a crate-root `main`, and a shared root would give the two the
    /// same declaration id.
    crate_path: String,
    relative_file_path: String,
    module_path: Vec<String>,
}

#[derive(Debug, Clone)]
struct SimplifiedCall {
    callee_text: String,
    position: Position,
    /// Receiver expression text for method calls (e.g. `store`, `x.field`).
    /// Populated for `ExprMethodCall` so the resolver can apply
    /// receiver-type inference (P1.2) and trait-impl filtering (P1.3).
    receiver_text: Option<String>,
    /// The receiver as a simplified expression, so its type can be inferred
    /// structurally. The text form cannot express a call result, which is what
    /// a method chain's receiver usually is (`builder().build().run()`).
    receiver_expr: Option<SimpleExpr>,
    /// Bare method name for method calls (last segment only, no qualifier).
    /// None for free-function `ExprCall`. Used by the trait/method resolver.
    method_name: Option<String>,
    /// True when this edge links a caller to an inline closure body that
    /// was passed as an argument to a higher-order combinator
    /// (`map`/`for_each`/`spawn`/...). The resolver labels these
    /// `HigherOrder` so consumers can filter combinator-driven edges.
    is_higher_order: bool,
}

#[derive(Debug, Clone)]
struct FunctionRecord {
    declaration: Declaration,
    package_path: String,
    file_path: String,
    params: Vec<String>,
    param_types: Vec<String>,
    param_source_categories: BTreeMap<usize, String>,
    return_type: String,
    operations: Vec<Operation>,
    direct_calls: Vec<SimplifiedCall>,
    receiver_type: Option<String>,
    /// Transmitter/receiver variable pairs declared by `let (tx, rx) =
    /// channel()`-style tuple bindings in this function. Used by the
    /// concrete pass to unify per-channel taint slots across the two
    /// endpoints (P4.2) so an unrelated channel doesn't inherit another
    /// channel's taint via a shared global slot.
    channel_pairs: Vec<(String, String)>,
    // Reserved for loop-aware analysis; populated but not yet consumed.
    #[allow(dead_code)]
    is_loop_body: bool,
    /// Types written explicitly on `let` bindings, which outrank anything
    /// inferred.
    declared_types: BTreeMap<String, String>,
    /// Whether this record's body was analyzed.
    ///
    /// False for a dependency at the lighter tier. Data flow must skip such a
    /// record entirely: an empty operation list is indistinguishable from "this
    /// function does nothing", so summarizing it would conclude that taint stops
    /// there and silently drop real flows through it.
    has_body: bool,
}

#[derive(Debug, Clone)]
enum Operation {
    Assign {
        target: String,
        value: SimpleExpr,
    },
    AssignField {
        target: String,
        field: String,
        value: SimpleExpr,
    },
    Expr(SimpleExpr),
    Return(SimpleExpr),
    // Matched where loop operations are walked, but not yet emitted by the
    // source collector.
    #[allow(dead_code)]
    LoopBody(Vec<Operation>),
}

#[derive(Debug, Clone)]
enum SimpleExpr {
    Var(String),
    Call {
        callee: String,
        args: Vec<SimpleExpr>,
        position: Position,
    },
    Compose(Vec<SimpleExpr>),
    Literal,
    Field {
        base: Box<SimpleExpr>,
        // Field name is consulted for access-path-aware reads/writes (P3.5).
        field: String,
    },
    MethodCall {
        receiver: Box<SimpleExpr>,
        method: String,
        args: Vec<SimpleExpr>,
        position: Position,
    },
    /// `&x` / `&mut x`. Preserved (rather than silently unwrapped) so the
    /// out-parameter propagation heuristic (P4.1) can fire only for true
    /// mutable references, instead of unioning every call's taint onto
    /// every Var argument.
    Reference {
        expr: Box<SimpleExpr>,
        mutable: bool,
    },
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FunctionSummary {
    returns_source_categories: BTreeSet<String>,
    param_to_return: BTreeSet<usize>,
    param_to_sink: BTreeMap<String, BTreeSet<usize>>,
    param_to_field_sink: BTreeMap<(usize, String), BTreeSet<String>>,
    field_to_return: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct TaintStep {
    node: DataFlowNode,
    edge: Option<DataFlowEdge>,
}

#[derive(Debug, Clone)]
struct TaintPath {
    origin_key: String,
    category: String,
    steps: Vec<TaintStep>,
}

#[derive(Debug, Clone, Default)]
struct ConcreteTaint {
    paths: Vec<TaintPath>,
}

/// Maximum number of distinct taint witnesses retained for a single value.
///
/// Interprocedural propagation unions argument taint at every call, copy, and
/// channel hop, so the number of source→value paths grows combinatorially with
/// branching. Because every [`TaintStep`] carries a fully cloned
/// [`DataFlowNode`], an unbounded path set was the dominant whole-program OOM
/// contributor (RC-1). One witness is enough to prove a flow; this cap keeps
/// memory linear in program size while preserving every distinct source.
const MAX_TAINT_PATHS: usize = 32;

/// Maximum number of steps in a retained taint witness. Pathologically deep
/// chains (long passthrough/assignment cascades) are dropped rather than stored;
/// real findings are short.
const MAX_TAINT_PATH_STEPS: usize = 64;

impl ConcreteTaint {
    /// Bound the in-flight path set (RC-1): drop pathologically long witnesses,
    /// deduplicate witnesses that share an origin and node sequence, and cap the
    /// number retained. Cheap no-op for the common single-path case.
    fn bounded(mut self) -> Self {
        let within_step_limit = self
            .paths
            .first()
            .is_none_or(|path| path.steps.len() <= MAX_TAINT_PATH_STEPS);
        if self.paths.len() <= 1 && within_step_limit {
            return self;
        }
        let mut seen = HashSet::with_capacity(self.paths.len());
        let mut kept = Vec::with_capacity(self.paths.len().min(MAX_TAINT_PATHS));
        for path in self.paths.drain(..) {
            if path.steps.len() > MAX_TAINT_PATH_STEPS {
                continue;
            }
            let mut signature = String::with_capacity(path.origin_key.len() + path.steps.len() * 8);
            signature.push_str(&path.origin_key);
            for step in &path.steps {
                signature.push('\u{1}');
                signature.push_str(&step.node.id);
            }
            if seen.insert(signature) {
                kept.push(path);
                if kept.len() >= MAX_TAINT_PATHS {
                    break;
                }
            }
        }
        self.paths = kept;
        self
    }
}

#[derive(Debug, Clone, Default)]
struct TraitImplIndex {
    // Built for future trait-to-impl resolution; method_to_impls is the index
    // currently consumed by call resolution.
    #[allow(dead_code)]
    trait_to_impl_methods: HashMap<String, Vec<String>>,
    method_to_impls: HashMap<String, Vec<String>>,
    /// Methods from blanket impls, by bare name. These are the only local
    /// methods that can apply to a receiver whose type has no local impl.
    blanket_method_to_impls: HashMap<String, Vec<String>>,
}

/// Method names that mark a *crate-defined* method as a passthrough.
///
/// This list does not itself model the standard library — the built-in pattern
/// pack in [`built_in_dataflow_patterns`] does that. It is the allowlist that
/// [`discover_auto_passthroughs`] consults when the analyzed crate defines a
/// method of its own with one of these names and a `self` receiver: such a
/// method is following the standard library's naming convention, and by that
/// convention it returns its receiver's data.
///
/// Matching is on the final path segment only, because the stable (syn-only)
/// backend has no type resolution and so cannot tell `String::as_str` from a
/// user-defined `as_str`. Treating a same-named user method as a passthrough
/// is the safe direction of error for taint tracking; omitting a real one is
/// not, because taint then stops dead at the call and every downstream sink
/// goes unreported. That asymmetry is why the list is deliberately generous.
///
/// Methods returning *indices* into the receiver rather than its data — such
/// as `substr_range` and `subslice_range` — are deliberately absent: an offset
/// is not the tainted content.
///
/// Entries are grouped by the kind of operation they name.
const KNOWN_PASSTHROUGH_NAMES: &[&str] = &[
    // Conversions and borrows.
    "as_ref",
    "as_mut",
    "as_str",
    "as_bytes",
    "as_encoded_bytes",
    "as_os_str",
    "as_path",
    "as_slice",
    "as_mut_slice",
    "as_deref",
    "as_deref_mut",
    "to_str",
    "to_string",
    "to_owned",
    "to_os_string",
    "to_string_lossy",
    "to_path_buf",
    "to_vec",
    "into_owned",
    "into_inner",
    "into_string",
    "into_bytes",
    "into_vec",
    "into_boxed_str",
    "into_boxed_slice",
    "clone",
    "clone_from",
    "try_into",
    "deref",
    "deref_mut",
    "borrow",
    "borrow_mut",
    "leak",
    // Container and option/result access.
    "read",
    "write",
    "get_mut",
    "get",
    "get_or_insert",
    "get_or_insert_with",
    "iter",
    "iter_mut",
    "into_iter",
    "keys",
    "values",
    "values_mut",
    "first",
    "last",
    "unwrap_or_default",
    // Predicates and searches (the needle argument flows to the result).
    "is_empty",
    "is_none",
    "is_some",
    "is_ok",
    "is_err",
    "contains",
    "starts_with",
    "ends_with",
    "find",
    "rfind",
    // Slicing and splitting.
    "split",
    "split_at",
    "split_whitespace",
    "split_once",
    "rsplit_once",
    "split_terminator",
    "splitn",
    "rsplitn",
    "strip_prefix",
    "strip_suffix",
    "strip_circumfix",
    // Trimming.
    "trim",
    "trim_start",
    "trim_end",
    "trim_matches",
    "trim_start_matches",
    "trim_end_matches",
    "trim_ascii",
    "trim_ascii_start",
    "trim_ascii_end",
    // Case folding, escaping, and other in-place text transforms.
    "to_lowercase",
    "to_uppercase",
    "to_ascii_lowercase",
    "to_ascii_uppercase",
    "escape_debug",
    "escape_default",
    "escape_unicode",
    "chars",
    "bytes",
    "lines",
    "replace",
    "replacen",
    "repeat",
];

fn discover_auto_passthroughs(functions: &[FunctionRecord]) -> Vec<DataFlowPattern> {
    // Same reason data flow skips them: a body-less record cannot be read as
    // "does not pass its argument through".
    let functions: Vec<FunctionRecord> = functions
        .iter()
        .filter(|function| function.has_body)
        .cloned()
        .collect();
    let functions = functions.as_slice();
    let mut method_counts: HashMap<String, usize> = HashMap::new();
    let mut proven_passthrough: HashSet<String> = HashSet::new();

    let known_passthrough_names: HashSet<&str> = KNOWN_PASSTHROUGH_NAMES
        .iter()
        .copied()
        .collect::<HashSet<_>>();

    for function in functions {
        if let Some(receiver_type) = &function.receiver_type {
            let has_self_receiver = receiver_type.contains("Self")
                || receiver_type.contains("&Self")
                || receiver_type.contains("&mut Self")
                || !receiver_type.is_empty();
            if has_self_receiver {
                let name = function.declaration.name.clone();
                let fqn = function.declaration.qualified_name.clone();
                if known_passthrough_names.contains(name.as_str()) {
                    proven_passthrough.insert(name.clone());
                    proven_passthrough.insert(fqn);
                }
            }
        }
    }

    for function in functions {
        for operation in &function.operations {
            let callee = match operation {
                Operation::Expr(SimpleExpr::Call { callee, .. })
                | Operation::Return(SimpleExpr::Call { callee, .. }) => Some(callee.as_str()),
                Operation::Expr(SimpleExpr::MethodCall { method, .. })
                | Operation::Return(SimpleExpr::MethodCall { method, .. }) => Some(method.as_str()),
                _ => None,
            };
            if let Some(callee) = callee {
                let last_seg = last_segment(callee);
                *method_counts.entry(last_seg.to_string()).or_default() += 1;
            }
        }
    }

    for function in functions {
        // P4.5: drop the unsound "return type contains `Self` => passthrough"
        // rule. A method returning Self is not automatically a passthrough —
        // it may discard its arguments entirely (e.g. `fn reset(&mut self) ->
        // Self`). Only methods whose *abstract summary actually shows
        // param→return flow* (computed below) AND whose name is in the
        // curated allowlist count as proven passthroughs.
        //
        // We also explicitly exclude any method whose name matches a
        // built-in sanitizer pattern: a method that is BOTH a sanitizer
        // (clears taint) AND a passthrough (propagates taint) would be
        // self-contradictory and historically laundered taint past the
        // sanitize step.
        let _ = function.return_type.contains("Self"); // intentionally dropped
    }

    let mut patterns = Vec::new();
    for (method_name, count) in &method_counts {
        if proven_passthrough.contains(method_name)
            && *count >= 1
            && !is_sanitizer_call(method_name)
        {
            let short_name = last_segment(method_name);
            patterns.push(DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: short_name.to_string(),
                category: "auto-discovered-passthrough".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            });
            if short_name != *method_name {
                patterns.push(DataFlowPattern {
                    target: "passthrough".to_string(),
                    pattern: method_name.clone(),
                    category: "auto-discovered-passthrough".to_string(),
                    relevant_arguments: vec![],
                    receiver_type: None,
                });
            }
        }
    }
    patterns
}

/// Parsed evidence collected from a single Rust source file.
///
/// The bootstrap engine extracts structural facts here first and then reuses
/// them for callgraph construction and data-flow slicing.
#[derive(Debug, Clone)]
struct AnalyzedFile {
    file: FileEvidence,
    declarations: Vec<Declaration>,
    usages: Vec<LibraryUsage>,
    imports: Vec<ImportUsage>,
    security_signals: Vec<SecuritySignal>,
    functions: Vec<FunctionRecord>,
    trait_impl_records: Vec<TraitImplRecord>,
    /// Module path this file occupies, resolved by following `mod`
    /// declarations from the crate root.
    module_path: Vec<String>,
    /// Crate name of the owning Cargo target: the root of this file's
    /// qualified names, and the unit import resolution groups by.
    crate_path: String,
    /// Every `use` in the file, consumed by package-wide import resolution.
    use_records: Vec<UseRecord>,
    /// Struct field types, for typing `self.field`-shaped receivers.
    field_types: HashMap<String, String>,
    /// Macro paths in this file whose bodies could not be recovered as Rust.
    unanalyzed_macros: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct SourcePatternMatch {
    category: String,
}

#[derive(Debug, Clone)]
struct SinkPatternMatch {
    category: String,
    relevant_arguments: Vec<usize>,
}

#[derive(Debug, Clone)]
struct StableCryptoRule {
    kind: &'static str,
    algorithm: &'static str,
    provider: &'static str,
    operation: &'static str,
    symbol: &'static str,
    finding: Option<(&'static str, &'static str, &'static str)>,
}

/// Analyze a Cargo workspace or package directory and emit a deterministic report.
pub fn analyze(options: AnalyzeOptionsInput) -> Result<Report> {
    analyze_with_optional_compiler(options, None)
}

/// Analyze a directory while allowing a compiler backend to contribute callgraph,
/// data-flow, and diagnostic information through a stable intermediate payload.
pub fn analyze_with_optional_compiler(
    options: AnalyzeOptionsInput,
    compiler_payload: Option<CompilerBackendPayload>,
) -> Result<Report> {
    let analysis_root = fs::canonicalize(&options.dir)
        .with_context(|| format!("failed to resolve {}", options.dir.display()))?;
    debug_log(
        options.debug,
        format_args!("pass=metadata root={}", analysis_root.display()),
    );
    let metadata = load_metadata(&analysis_root)?;
    debug_log(options.debug, format_args!("pass=runtime-info"));
    let runtime_versions = collect_runtime_versions();
    let mut diagnostics = Vec::new();

    debug_log(options.debug, format_args!("pass=workspace-discovery"));
    let package_plans = plan_packages(
        &metadata,
        options.include_tests,
        options.include_dependencies,
    )?;
    let package_contexts: Vec<PackageContext> = package_plans
        .iter()
        .map(|plan| plan.package_ctx.clone())
        .collect();
    let mut report = Report {
        schema_version: SCHEMA_VERSION.to_string(),
        tool: ToolInfo {
            name: TOOL_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: TOOL_DESCRIPTION.to_string(),
        },
        runtime: RuntimeInfo {
            rustc_version: runtime_versions.rustc_version,
            cargo_version: runtime_versions.cargo_version,
            host: runtime_versions.host,
            working_directory: analysis_root.display().to_string(),
        },
        options: AnalysisOptions {
            directory: analysis_root.display().to_string(),
            backend: options.backend.clone(),
            analysis_scope: options.analysis_scope.as_str().to_string(),
            call_graph_mode: options.call_graph_mode.clone(),
            data_flow_mode: options.data_flow_mode.clone(),
            include_tests: options.include_tests,
            max_call_candidates: options.max_call_candidates,
        },
        modules: package_contexts
            .iter()
            .map(|ctx| ctx.module_ref.clone())
            .collect(),
        ..Report::default()
    };

    let mut analysis_tasks = Vec::new();
    for plan in &package_plans {
        let package_ctx = &plan.package_ctx;
        debug_log(
            options.debug,
            format_args!("pass=file-discovery package={}", package_ctx.crate_name),
        );
        // Module discovery follows `mod` declarations from each Cargo target's
        // crate root, so every file carries the module path it actually
        // occupies rather than one derived from its location on disk.
        for note in &plan.module_tree.notes {
            diagnostics.push(Diagnostic {
                kind: "module-resolution".to_string(),
                message: note.message.clone(),
                package_path: Some(package_ctx.crate_name.clone()),
                file_path: note
                    .file_path
                    .as_ref()
                    .map(|path| relative_display_path(&analysis_root, path)),
                position: None,
            });
        }
        let files: Vec<PathBuf> = plan
            .module_tree
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect();
        report.packages.push(PackageEvidence {
            id: stable_id(
                "pkg",
                &[
                    &package_ctx.package_name,
                    &package_ctx.manifest_path.display().to_string(),
                ],
            ),
            name: package_ctx.package_name.clone(),
            package_path: package_ctx.crate_name.clone(),
            purl: String::new(),
            manifest_path: package_ctx.manifest_path.display().to_string(),
            module: package_ctx.module_ref.clone(),
            files: files
                .iter()
                .map(|path| relative_display_path(&analysis_root, path))
                .collect(),
        });

        // Workspace code always gets bodies. A dependency gets them only in
        // `security-deps` mode, where taint is meant to flow through it.
        let collect_bodies =
            plan.package_ctx.workspace_member || options.data_flow_mode == DATAFLOW_SECURITY_DEPS;
        for file in &plan.module_tree.files {
            analysis_tasks.push(FileAnalysisTask {
                package_ctx: package_ctx.clone(),
                evaluator: plan.evaluator.clone(),
                path: file.path.clone(),
                module_path: file.module_path.clone(),
                crate_path: module_tree::crate_path(package_ctx, file),
                collect_bodies,
            });
        }
    }

    let mut analyzed_files = Vec::new();
    debug_log(
        options.debug,
        format_args!("pass=stable-file-analysis files={}", analysis_tasks.len()),
    );
    let mut parse_diagnostics = parallel_map_collect(&analysis_tasks, |task| {
        match analyze_file(
            &task.package_ctx,
            &analysis_root,
            &task.path,
            &task.module_path,
            &task.crate_path,
            &task.evaluator,
            task.collect_bodies,
        ) {
            Ok(file) => {
                debug_log(
                    options.debug,
                    format_args!(
                        "pass=stable-file-analysis file={}",
                        relative_display_path(&analysis_root, &task.path)
                    ),
                );
                Ok(file)
            }
            // Boxed so the per-file result stays small: a parse failure is
            // the rare path, while every successfully analyzed file would
            // otherwise carry the unused Diagnostic's footprint.
            Err(error) => Err(Box::new(Diagnostic {
                kind: "parse".to_string(),
                message: error.to_string(),
                package_path: Some(task.package_ctx.crate_name.clone()),
                file_path: Some(relative_display_path(&analysis_root, &task.path)),
                position: None,
            })),
        }
    });
    for result in parse_diagnostics.drain(..) {
        match result {
            Ok(file) => analyzed_files.push(file),
            Err(diagnostic) => diagnostics.push(*diagnostic),
        }
    }
    analyzed_files.sort_by(|left, right| left.file.path.cmp(&right.file.path));

    debug_log(options.debug, format_args!("pass=import-resolution"));
    for glob in resolve_imports(&mut analyzed_files) {
        diagnostics.push(Diagnostic {
            kind: "import-resolution".to_string(),
            message: format!(
                "glob import `{glob}` targets a module outside this workspace; names imported \
                 through it stay unresolved"
            ),
            package_path: None,
            file_path: None,
            position: None,
        });
    }

    // Everything that needs the whole set of analyzed files is derived first, so
    // the per-file evidence can then be *moved* into the report instead of
    // cloned. Cloning held two copies of every declaration, usage, signal, and
    // function record at once — on a large workspace, hundreds of megabytes.
    let trait_index = build_trait_impl_index(&analyzed_files);
    // Struct field types, workspace-wide: a receiver written `self.sink` needs
    // the declaring type's field table, which may live in another file.
    let mut field_types: HashMap<String, String> = HashMap::new();
    for analyzed in &analyzed_files {
        for (key, value) in &analyzed.field_types {
            field_types.insert(key.clone(), value.clone());
        }
    }

    // Report the macro bodies that could not be recovered as Rust, aggregated by
    // macro path: a consumer can then see exactly which blind spots this scan
    // has, instead of the evidence simply being absent.
    let mut unanalyzed_macros: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for analyzed in &analyzed_files {
        for macro_path in &analyzed.unanalyzed_macros {
            unanalyzed_macros
                .entry(macro_path.clone())
                .or_default()
                .insert(analyzed.file.path.clone());
        }
    }
    for (macro_path, files) in unanalyzed_macros {
        let sample: Vec<&str> = files.iter().take(3).map(String::as_str).collect();
        diagnostics.push(Diagnostic {
            kind: "macro".to_string(),
            message: format!(
                "{macro_path} bodies were not analyzed in {} file(s) (for example {}); calls \
                 inside them are not in the call graph",
                files.len(),
                sample.join(", ")
            ),
            package_path: None,
            file_path: None,
            position: None,
        });
    }

    // Type names declared in the analyzed code, so a method missing from one of
    // them can be read as leaving the analyzed code rather than as unknown.
    let local_types: HashSet<String> = analyzed_files
        .iter()
        .flat_map(|analyzed| analyzed.declarations.iter())
        .filter(|declaration| {
            matches!(
                declaration.kind.as_str(),
                "struct" | "enum" | "union" | "trait" | "type"
            )
        })
        .map(|declaration| declaration.name.clone())
        .collect();

    let mut all_functions = Vec::new();
    for mut analyzed in analyzed_files {
        merge_crypto_evidence(&mut report.crypto, analyzed.file.crypto.clone());
        report.files.push(analyzed.file);
        report.imports.append(&mut analyzed.imports);
        report.declarations.append(&mut analyzed.declarations);
        report.usages.append(&mut analyzed.usages);
        report
            .security_signals
            .append(&mut analyzed.security_signals);
        all_functions.append(&mut analyzed.functions);
    }

    let fallback_call_graph = if options.call_graph_mode != "none" {
        debug_log(
            options.debug,
            format_args!("pass=stable-callgraph functions={}", all_functions.len()),
        );
        Some(build_call_graph(
            &all_functions,
            &trait_index,
            &field_types,
            &local_types,
            options.max_call_candidates,
        ))
    } else {
        None
    };
    let mut dataflow_patterns = built_in_dataflow_patterns();
    if options.analysis_scope == AnalysisScope::Cryptos {
        dataflow_patterns = crypto_only_pattern_set(dataflow_patterns);
    }
    if let Some(custom_patterns) = options.custom_data_flow_patterns.clone() {
        merge_pattern_sets(&mut dataflow_patterns, custom_patterns);
    }
    let auto_passthroughs = discover_auto_passthroughs(&all_functions);
    if !auto_passthroughs.is_empty() {
        merge_pattern_sets(
            &mut dataflow_patterns,
            DataFlowPatternSet {
                sources: Vec::new(),
                sinks: Vec::new(),
                passthroughs: auto_passthroughs,
            },
        );
    }
    let fallback_data_flow = if options.data_flow_mode != "none" {
        debug_log(
            options.debug,
            format_args!("pass=stable-dataflow functions={}", all_functions.len()),
        );
        Some(build_data_flow(
            &options.data_flow_mode,
            &all_functions,
            dataflow_patterns,
            &field_types,
        ))
    } else {
        None
    };

    if let Some(payload) = compiler_payload {
        debug_log(options.debug, format_args!("pass=compiler-payload-merge"));
        merge_file_evidence(&mut report.files, payload.files);
        extend_unique_imports(&mut report.imports, payload.imports);
        extend_unique_declarations(&mut report.declarations, payload.declarations);
        extend_unique_usages(&mut report.usages, payload.usages);
        extend_unique_security_signals(&mut report.security_signals, payload.security_signals);
        merge_crypto_evidence(&mut report.crypto, payload.crypto);
        report.call_graph = if options.call_graph_mode != "none" {
            payload.call_graph.or(fallback_call_graph)
        } else {
            None
        };
        report.data_flow = if options.data_flow_mode != "none" {
            merge_data_flow_evidence(payload.data_flow, fallback_data_flow)
        } else {
            None
        };
        diagnostics.extend(payload.diagnostics);
    } else {
        report.call_graph = fallback_call_graph;
        report.data_flow = fallback_data_flow;
    }

    report.diagnostics = diagnostics;
    if options.analysis_scope == AnalysisScope::Cryptos {
        retain_crypto_focus(&mut report);
    }
    // API endpoints are discovered for all scopes. Running this in the
    // cryptos scope as well lets downstream consumers correlate which
    // crypto operations participate in which API endpoint flow (e.g.
    // "this /auth/login endpoint touches sha2::Sha256::digest and
    // jsonwebtoken::EncodingKey::from_secret").
    debug_log(options.debug, format_args!("pass=api-discovery"));
    let framework_purls = build_framework_purls(&metadata);
    report.api_endpoints = discover_api_endpoints(
        &package_contexts,
        &analysis_root,
        &report.imports,
        &framework_purls,
    );
    debug_log(options.debug, format_args!("pass=normalize-report"));
    normalize_report(&mut report);
    debug_log(options.debug, format_args!("pass=canonical-names"));
    report.fill_canonical_names();
    debug_log(options.debug, format_args!("pass=stats"));
    report.stats = compute_stats(&report);
    debug_log(options.debug, format_args!("pass=done"));
    Ok(report)
}

fn debug_log(enabled: bool, args: std::fmt::Arguments<'_>) {
    if enabled {
        eprintln!("rusi debug: {args}");
    }
}

fn merge_file_evidence(target: &mut Vec<FileEvidence>, incoming: Vec<FileEvidence>) {
    for file in incoming {
        if let Some(existing) = target.iter_mut().find(|entry| entry.path == file.path) {
            extend_unique_imports(&mut existing.imports, file.imports);
            extend_unique_declarations(&mut existing.declarations, file.declarations);
            extend_unique_usages(&mut existing.usages, file.usages);
            extend_unique_security_signals(&mut existing.security_signals, file.security_signals);
            merge_crypto_evidence(&mut existing.crypto, file.crypto);
        } else {
            target.push(file);
        }
    }
}

fn merge_crypto_evidence(target: &mut Option<CryptoEvidence>, incoming: Option<CryptoEvidence>) {
    let Some(mut incoming) = incoming else {
        return;
    };
    let existing = target.get_or_insert_with(CryptoEvidence::default);
    extend_unique_crypto_libraries(
        &mut existing.libraries,
        std::mem::take(&mut incoming.libraries),
    );
    extend_unique_crypto_components(
        &mut existing.components,
        std::mem::take(&mut incoming.components),
    );
    extend_unique_crypto_materials(
        &mut existing.materials,
        std::mem::take(&mut incoming.materials),
    );
    extend_unique_crypto_findings(
        &mut existing.findings,
        std::mem::take(&mut incoming.findings),
    );
    for (key, value) in incoming.properties {
        existing.properties.entry(key).or_insert(value);
    }
}

fn extend_unique_crypto_libraries(target: &mut Vec<CryptoLibrary>, incoming: Vec<CryptoLibrary>) {
    for library in incoming {
        if !target.iter().any(|existing| existing.id == library.id) {
            target.push(library);
        }
    }
}

fn extend_unique_crypto_components(
    target: &mut Vec<CryptoComponent>,
    incoming: Vec<CryptoComponent>,
) {
    for component in incoming {
        if !target.iter().any(|existing| existing.id == component.id) {
            target.push(component);
        }
    }
}

fn extend_unique_crypto_materials(target: &mut Vec<CryptoMaterial>, incoming: Vec<CryptoMaterial>) {
    for material in incoming {
        if !target.iter().any(|existing| existing.id == material.id) {
            target.push(material);
        }
    }
}

fn extend_unique_crypto_findings(target: &mut Vec<CryptoFinding>, incoming: Vec<CryptoFinding>) {
    for finding in incoming {
        if !target.iter().any(|existing| existing.id == finding.id) {
            target.push(finding);
        }
    }
}

fn extend_unique_imports(target: &mut Vec<ImportUsage>, incoming: Vec<ImportUsage>) {
    for import_usage in incoming {
        let exists = target.iter().any(|existing| {
            existing.path == import_usage.path
                && existing.alias == import_usage.alias
                && existing.package_path == import_usage.package_path
                && existing.position == import_usage.position
        });
        if !exists {
            target.push(import_usage);
        }
    }
}

fn extend_unique_declarations(target: &mut Vec<Declaration>, incoming: Vec<Declaration>) {
    for declaration in incoming {
        if !target.iter().any(|existing| existing.id == declaration.id) {
            target.push(declaration);
        }
    }
}

fn extend_unique_usages(target: &mut Vec<LibraryUsage>, incoming: Vec<LibraryUsage>) {
    for usage in incoming {
        if !target.iter().any(|existing| existing.id == usage.id) {
            target.push(usage);
        }
    }
}

fn extend_unique_security_signals(target: &mut Vec<SecuritySignal>, incoming: Vec<SecuritySignal>) {
    for signal in incoming {
        if !target.iter().any(|existing| existing.id == signal.id) {
            target.push(signal);
        }
    }
}

fn merge_data_flow_evidence(
    primary: Option<DataFlowEvidence>,
    fallback: Option<DataFlowEvidence>,
) -> Option<DataFlowEvidence> {
    match (primary, fallback) {
        (None, None) => None,
        (Some(flow), None) | (None, Some(flow)) => Some(flow),
        (Some(mut primary), Some(mut fallback)) => {
            merge_pattern_sets(
                &mut primary.patterns,
                std::mem::take(&mut fallback.patterns),
            );
            for node in std::mem::take(&mut fallback.nodes) {
                if !primary.nodes.iter().any(|entry| entry.id == node.id) {
                    primary.nodes.push(node);
                }
            }
            for edge in std::mem::take(&mut fallback.edges) {
                if !primary.edges.iter().any(|entry| entry.id == edge.id) {
                    primary.edges.push(edge);
                }
            }
            for slice in std::mem::take(&mut fallback.slices) {
                if !primary.slices.iter().any(|entry| entry.id == slice.id) {
                    primary.slices.push(slice);
                }
            }
            for summary in std::mem::take(&mut fallback.summaries) {
                if !primary
                    .summaries
                    .iter()
                    .any(|entry| entry.function_id == summary.function_id)
                {
                    primary.summaries.push(summary);
                }
            }
            for diagnostic in fallback.diagnostics {
                if !primary.diagnostics.iter().any(|entry| entry == &diagnostic) {
                    primary.diagnostics.push(diagnostic);
                }
            }
            Some(primary)
        }
    }
}

fn load_metadata(dir: &Path) -> Result<Metadata> {
    let mut command = MetadataCommand::new();
    command.current_dir(dir);
    command.exec().context("cargo metadata failed")
}

/// Build a map of HTTP framework crate name → purl, looking up resolved
/// versions from cargo metadata. Used by the api-discovery pass so each
/// emitted `ApiEndpoint` can identify the dependency crate that actually
/// owns the routing (axum, actix-web, rocket) rather than the user's
/// own package. When a supported framework is referenced in source but
/// not present in the resolved dependency graph (test fixtures, etc.)
/// the entry falls back to an unversioned `pkg:cargo/<name>` purl so the
/// field is never blank.
fn build_framework_purls(metadata: &Metadata) -> BTreeMap<String, String> {
    const SUPPORTED_FRAMEWORK_CRATES: &[&str] = &["axum", "actix-web", "rocket"];
    let mut purls = BTreeMap::new();
    for crate_name in SUPPORTED_FRAMEWORK_CRATES {
        purls.insert(crate_name.to_string(), format!("pkg:cargo/{}", crate_name));
    }
    for package in &metadata.packages {
        let name = package.name.as_str();
        if SUPPORTED_FRAMEWORK_CRATES.contains(&name) {
            purls.insert(
                name.to_string(),
                format!("pkg:cargo/{}@{}", name, package.version),
            );
        }
    }
    purls
}

fn collect_runtime_versions() -> RuntimeVersions {
    let rustc_version = capture_command_output("rustc", &["--version"]);
    let cargo_version = capture_command_output("cargo", &["--version"]);
    let host = std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS;
    RuntimeVersions {
        rustc_version,
        cargo_version,
        host,
    }
}

fn capture_command_output(binary: &str, args: &[&str]) -> String {
    Command::new(binary)
        .args(args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn parallel_map_collect<T, U, F>(items: &[T], func: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> U + Sync,
{
    let configured_workers = std::env::var("RUSI_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let workers = configured_workers
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
        })
        .min(items.len().max(1));
    if workers <= 1 || items.len() <= 1 {
        return items.iter().map(&func).collect();
    }

    let chunk_size = items.len().div_ceil(workers);
    let mut flattened = Vec::with_capacity(items.len());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in items.chunks(chunk_size) {
            let func_ref = &func;
            handles.push(scope.spawn(move || chunk.iter().map(func_ref).collect::<Vec<U>>()));
        }
        for handle in handles {
            flattened.extend(handle.join().expect("parallel worker panicked"));
        }
    });
    flattened
}

/// One workspace package plus everything discovery resolved for it: the active
/// cfg environment and the module tree reached from its crate roots.
struct PackageAnalysisPlan {
    package_ctx: PackageContext,
    evaluator: CfgEvaluator,
    module_tree: module_tree::ModuleTree,
}

/// One file to analyze, with its resolved module path and the cfg environment
/// of the package that owns it.
struct FileAnalysisTask {
    package_ctx: PackageContext,
    evaluator: CfgEvaluator,
    path: PathBuf,
    module_path: Vec<String>,
    crate_path: String,
    collect_bodies: bool,
}

/// Resolves cfg options and the module tree for every package to analyze.
///
/// The target atoms are shared across packages (one host, one `rustc`), while
/// the feature set is per package, taken from the resolved dependency graph.
///
/// With `include_dependencies`, the resolved dependency packages are planned
/// too, but only their library targets: a dependency's binaries, tests, and
/// examples are not part of the artifact being analyzed.
fn plan_packages(
    metadata: &Metadata,
    include_tests: bool,
    include_dependencies: bool,
) -> Result<Vec<PackageAnalysisPlan>> {
    let host_cfg = CfgOptions::from_host();
    let workspace_members: HashSet<&cargo_metadata::PackageId> =
        metadata.workspace_members.iter().collect();
    let packages: Vec<(&Package, bool)> = if include_dependencies {
        metadata
            .packages
            .iter()
            .map(|package| (package, workspace_members.contains(&package.id)))
            .collect()
    } else {
        metadata
            .workspace_packages()
            .into_iter()
            .map(|package| (package, true))
            .collect()
    };
    // Module discovery parses every module file to read its `mod` declarations,
    // so it is worth spreading across packages the same way file analysis is.
    let planned = parallel_map_collect(&packages, |(package, workspace_member)| {
        let package_ctx = package_context(package, *workspace_member)?;
        let mut cfg_options = host_cfg.clone();
        cfg_options.insert_package_features(metadata, package);
        let evaluator = CfgEvaluator::new(cfg_options, include_tests);
        // A dependency contributes only its library; test targets of a
        // dependency are never built here either.
        let roots = module_tree::crate_roots(
            package,
            include_tests && *workspace_member,
            !*workspace_member,
        );
        let module_tree = module_tree::discover(&package_ctx, &roots, &evaluator, include_tests)?;
        Ok(PackageAnalysisPlan {
            package_ctx,
            evaluator,
            module_tree,
        })
    });
    let mut plans = planned.into_iter().collect::<Result<Vec<_>>>()?;
    plans.sort_by(|left, right| {
        left.package_ctx
            .package_name
            .cmp(&right.package_ctx.package_name)
    });
    Ok(plans)
}

/// Resolves imports per package and rewrites call targets through the resulting
/// alias table, so calls made through glob imports, renamed imports, and
/// `pub use` facades name the module that actually declares the callee.
fn resolve_imports(analyzed_files: &mut [AnalyzedFile]) -> Vec<String> {
    let mut declarations_by_package: HashMap<String, Vec<Declaration>> = HashMap::new();
    let mut use_records_by_package: HashMap<String, Vec<UseRecord>> = HashMap::new();
    for analyzed in analyzed_files.iter() {
        // Grouped per crate, not per package: each Cargo target is its own
        // crate, so a `bin`'s `crate::` paths must not resolve against the
        // library's item table.
        let crate_path = analyzed.crate_path.clone();
        declarations_by_package
            .entry(crate_path.clone())
            .or_default()
            .extend(analyzed.declarations.iter().cloned());
        use_records_by_package
            .entry(crate_path)
            .or_default()
            .extend(analyzed.use_records.iter().cloned());
    }

    let mut resolutions: HashMap<String, ImportResolution> = HashMap::new();
    let mut unexpanded_globs = BTreeSet::new();
    for (package_path, declarations) in &declarations_by_package {
        let items = ItemTable::from_declarations(declarations);
        let records = use_records_by_package
            .get(package_path)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let resolution = ImportResolution::build(package_path, &items, records);
        for glob in resolution.unexpanded_globs() {
            unexpanded_globs.insert(glob.to_string());
        }
        resolutions.insert(package_path.clone(), resolution);
    }

    for analyzed in analyzed_files.iter_mut() {
        let Some(resolution) = resolutions.get(&analyzed.crate_path) else {
            continue;
        };
        let module_path = analyzed.module_path.clone();
        for function in &mut analyzed.functions {
            for call in &mut function.direct_calls {
                if let Some(resolved) = resolution.resolve_path(&module_path, &call.callee_text) {
                    call.callee_text = resolved;
                }
            }
            for operation in &mut function.operations {
                rewrite_operation_paths(operation, resolution, &module_path);
            }
        }
    }

    unexpanded_globs.into_iter().collect()
}

fn rewrite_operation_paths(
    operation: &mut Operation,
    resolution: &ImportResolution,
    module_path: &[String],
) {
    match operation {
        Operation::Assign { value, .. }
        | Operation::AssignField { value, .. }
        | Operation::Expr(value)
        | Operation::Return(value) => rewrite_expr_paths(value, resolution, module_path),
        Operation::LoopBody(operations) => {
            for nested in operations {
                rewrite_operation_paths(nested, resolution, module_path);
            }
        }
    }
}

fn rewrite_expr_paths(
    expr: &mut SimpleExpr,
    resolution: &ImportResolution,
    module_path: &[String],
) {
    match expr {
        SimpleExpr::Call { callee, args, .. } => {
            if let Some(resolved) = resolution.resolve_path(module_path, callee) {
                *callee = resolved;
            }
            for arg in args {
                rewrite_expr_paths(arg, resolution, module_path);
            }
        }
        SimpleExpr::MethodCall { receiver, args, .. } => {
            rewrite_expr_paths(receiver, resolution, module_path);
            for arg in args {
                rewrite_expr_paths(arg, resolution, module_path);
            }
        }
        SimpleExpr::Compose(parts) => {
            for part in parts {
                rewrite_expr_paths(part, resolution, module_path);
            }
        }
        SimpleExpr::Field { base, .. } => rewrite_expr_paths(base, resolution, module_path),
        SimpleExpr::Reference { expr, .. } => rewrite_expr_paths(expr, resolution, module_path),
        SimpleExpr::Var(_) | SimpleExpr::Literal | SimpleExpr::Unknown => {}
    }
}

#[allow(dead_code)]
fn workspace_package_contexts(metadata: &Metadata) -> Result<Vec<PackageContext>> {
    let mut packages = Vec::new();
    for package in metadata.workspace_packages() {
        packages.push(package_context(package, true)?);
    }
    packages.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    Ok(packages)
}

fn package_context(package: &Package, workspace_member: bool) -> Result<PackageContext> {
    let manifest_path =
        fs::canonicalize(package.manifest_path.as_std_path()).with_context(|| {
            format!(
                "failed to resolve package manifest {}",
                package.manifest_path.as_std_path().display()
            )
        })?;
    let root_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .context("package manifest has no parent directory")?;
    let src_dir = root_dir.join("src");
    Ok(PackageContext {
        package_name: package.name.to_string(),
        crate_name: package.name.replace('-', "_"),
        manifest_path: manifest_path.clone(),
        root_dir,
        src_dir,
        module_ref: ModuleRef {
            name: package.name.to_string(),
            version: package.version.to_string(),
            manifest_path: manifest_path.display().to_string(),
            workspace_member,
        },
        workspace_member,
    })
}

pub(crate) fn discover_rust_files(
    package_ctx: &PackageContext,
    include_tests: bool,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut visited_dirs = HashSet::new();
    let allowed_root = canonical_path(&package_ctx.root_dir);
    if package_ctx.src_dir.exists() {
        walk_rust_files(
            &package_ctx.src_dir,
            &allowed_root,
            &mut visited_dirs,
            &mut files,
        )?;
    }
    if include_tests {
        let tests_dir = package_ctx.root_dir.join("tests");
        if tests_dir.exists() {
            walk_rust_files(&tests_dir, &allowed_root, &mut visited_dirs, &mut files)?;
        }
    }
    files.sort();
    Ok(files)
}

fn walk_rust_files(
    dir: &Path,
    allowed_root: &Path,
    visited_dirs: &mut HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(dir)
        .with_context(|| format!("failed to inspect {}", dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(());
    }
    let canonical_dir =
        fs::canonicalize(dir).with_context(|| format!("failed to resolve {}", dir.display()))?;
    if !canonical_dir.starts_with(allowed_root) || !visited_dirs.insert(canonical_dir.clone()) {
        return Ok(());
    }
    for entry in fs::read_dir(&canonical_dir)
        .with_context(|| format!("failed to read {}", canonical_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk_rust_files(&path, allowed_root, visited_dirs, files)?;
        } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            let canonical_file = fs::canonicalize(&path)
                .with_context(|| format!("failed to resolve {}", path.display()))?;
            if canonical_file.starts_with(allowed_root) {
                files.push(canonical_file);
            }
        }
    }
    Ok(())
}

fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn analyze_file(
    package_ctx: &PackageContext,
    root: &Path,
    file_path: &Path,
    module_path: &[String],
    crate_path: &str,
    evaluator: &CfgEvaluator,
    collect_bodies: bool,
) -> Result<AnalyzedFile> {
    let source = fs::read_to_string(file_path)
        .with_context(|| format!("failed to read {}", file_path.display()))?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("failed to parse {}", file_path.display()))?;
    let relative_file_path = relative_display_path(root, file_path);
    let file_ctx = FileContext {
        package_name: package_ctx.package_name.clone(),
        package_path: package_ctx.crate_name.clone(),
        crate_path: crate_path.to_string(),
        relative_file_path: relative_file_path.clone(),
        module_path: module_path.to_vec(),
    };

    let mut collector = SourceCollector::new(file_ctx.clone(), evaluator.clone(), collect_bodies);
    collector.visit_file(&syntax);

    // The per-file `imports`/`declarations`/`usages`/`security_signals` are
    // deliberately left empty: the canonical copies are the flattened top-level
    // report collections (each item carries its `file_path`), and the report
    // finalizer clears these anyway. Populating them held a second copy of all
    // per-file evidence for the whole run. The compiler backend still fills them
    // on its own path, which merges into the same top-level arrays.
    let file = FileEvidence {
        path: relative_file_path,
        package_name: file_ctx.package_name.clone(),
        package_path: file_ctx.package_path.clone(),
        purl: String::new(),
        imports: Vec::new(),
        declarations: Vec::new(),
        usages: Vec::new(),
        security_signals: Vec::new(),
        crypto: optional_crypto_evidence(&collector.crypto),
    };

    Ok(AnalyzedFile {
        file,
        declarations: collector.declarations,
        usages: collector.usages,
        imports: collector.imports,
        security_signals: collector.security_signals,
        functions: collector.functions,
        trait_impl_records: collector.trait_impl_records,
        module_path: module_path.to_vec(),
        crate_path: crate_path.to_string(),
        use_records: collector.use_records,
        field_types: collector.field_types,
        unanalyzed_macros: collector.unanalyzed_macros,
    })
}

pub(crate) fn module_path_for_file(package_ctx: &PackageContext, file_path: &Path) -> Vec<String> {
    let relative = file_path
        .strip_prefix(&package_ctx.root_dir)
        .unwrap_or(file_path)
        .to_string_lossy()
        .replace('\\', "/");
    let mut segments = Vec::new();
    for segment in relative.split('/') {
        if segment == "src" || segment.is_empty() {
            continue;
        }
        if let Some(stem) = segment.strip_suffix(".rs") {
            if stem == "lib" || stem == "main" || stem == "mod" {
                continue;
            }
            segments.push(stem.to_string());
        } else {
            segments.push(segment.to_string());
        }
    }
    segments
}

struct SourceCollector {
    file_ctx: FileContext,
    imports: Vec<ImportUsage>,
    declarations: Vec<Declaration>,
    usages: Vec<LibraryUsage>,
    security_signals: Vec<SecuritySignal>,
    crypto: CryptoEvidence,
    functions: Vec<FunctionRecord>,
    current_function: Option<FunctionFrame>,
    trait_impl_records: Vec<TraitImplRecord>,
    struct_field_names: HashMap<String, Vec<String>>,
    /// `"<TypeToken>::<field>" -> <TypeToken of the field>`, so a receiver
    /// written `self.sink` can be typed once `self`'s type is known.
    field_types: HashMap<String, String>,
    /// Macro invocations whose token stream could not be recovered as Rust, so
    /// the gap is reported instead of silently swallowed.
    unanalyzed_macros: BTreeSet<String>,
    /// Whether to record function bodies (operations and direct calls).
    ///
    /// Off for a dependency at the lighter tier: its declarations, imports,
    /// impls, and usage evidence are cheap and useful, while its bodies are the
    /// bulk of the memory and are only needed for taint to flow *through* the
    /// dependency.
    collect_bodies: bool,
    /// Every `use` in the file, kept for package-wide import resolution.
    use_records: Vec<UseRecord>,
    evaluator: CfgEvaluator,
    /// Trait being implemented by the enclosing `impl` block, if any. Part of a
    /// method's identity: `impl Section for T` and `impl ComponentSection for T`
    /// can both define `fn id(&self) -> u8`, identical in name and signature.
    current_impl_trait: Option<String>,
    /// The `#[cfg(...)]` gates of the enclosing items, innermost last. Only
    /// enabled items are visited, so this describes evidence that is real but
    /// conditional.
    cfg_gates: Vec<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TraitImplRecord {
    trait_name: String,
    impl_type: String,
    method_ids: Vec<String>,
    method_names: Vec<String>,
    /// True for a blanket impl (`impl<T: Read> MyExt for T`), where the self
    /// type is one of the impl's own generic parameters.
    ///
    /// Such a method applies to receivers of *any* type, including types from
    /// other crates, so it cannot be matched by comparing the receiver's type
    /// against the impl's self type.
    is_blanket: bool,
}

#[derive(Debug, Clone)]
struct FunctionFrame {
    declaration_id: String,
    operations: Vec<Operation>,
    direct_calls: Vec<SimplifiedCall>,
    // Carried on the frame for future use; the emitted record derives these
    // separately, so they are not read back off the frame yet.
    #[allow(dead_code)]
    receiver_type: Option<String>,
    #[allow(dead_code)]
    is_loop_body: bool,
    /// Channel transmitter/receiver pairs declared inside this frame.
    /// Populated by visit_stmt when it sees `let (tx, rx) = ... channel()`.
    channel_pairs: Vec<(String, String)>,
    /// Types written explicitly on `let` bindings in this frame.
    declared_types: BTreeMap<String, String>,
    /// Whether body detail is kept. A dependency at the lighter tier is still
    /// walked — its imports, usages, crypto, and signals are cheap and useful —
    /// but the per-statement trees, which are the bulk of the memory, are not
    /// retained.
    collect_bodies: bool,
}

impl FunctionFrame {
    fn record_operation(&mut self, operation: Operation) {
        if self.collect_bodies {
            self.operations.push(operation);
        }
    }

    fn record_call(&mut self, call: SimplifiedCall) {
        if self.collect_bodies {
            self.direct_calls.push(call);
        }
    }

    fn record_channel_pair(&mut self, pair: (String, String)) {
        if self.collect_bodies {
            self.channel_pairs.push(pair);
        }
    }
}

impl SourceCollector {
    fn new(file_ctx: FileContext, evaluator: CfgEvaluator, collect_bodies: bool) -> Self {
        Self {
            file_ctx,
            collect_bodies,
            use_records: Vec::new(),
            evaluator,
            current_impl_trait: None,
            cfg_gates: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            crypto: CryptoEvidence::default(),
            functions: Vec::new(),
            current_function: None,
            trait_impl_records: Vec::new(),
            struct_field_names: HashMap::new(),
            field_types: HashMap::new(),
            unanalyzed_macros: BTreeSet::new(),
        }
    }

    fn push_declaration(
        &mut self,
        name: &str,
        kind: &str,
        signature: String,
        receiver: Option<String>,
        span: Span,
    ) -> Declaration {
        let qualified_name = qualify_name(&self.file_ctx, receiver.as_deref(), name);
        let declaration = Declaration {
            // The signature is part of the identity: two trait impls for the
            // same type produce the same qualified name (`impl From<A> for
            // String` and `impl From<B> for String` are both `String::from`),
            // and without it they collapse onto one id.
            id: stable_id(
                "decl",
                &[
                    &self.file_ctx.package_path,
                    &qualified_name,
                    // The signature and the implemented trait complete the
                    // identity: two trait impls for one type can share both the
                    // qualified name (`impl From<A>/<B> for String` are both
                    // `String::from`) and, for a trait with a fixed method
                    // shape, the signature too.
                    &signature,
                    self.current_impl_trait.as_deref().unwrap_or_default(),
                ],
            ),
            name: name.to_string(),
            canonical_name: rusi_schema::canonical_name(&qualified_name),
            qualified_name,
            kind: kind.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            file_path: self.file_ctx.relative_file_path.clone(),
            signature,
            receiver,
            position: position_from_span(&self.file_ctx.relative_file_path, span),
            cfg_gate: self.current_cfg_gate(),
        };
        self.declarations.push(declaration.clone());
        declaration
    }

    /// Recovers the Rust inside a macro invocation and visits it.
    ///
    /// This is **not** macro expansion: no matcher is run and no transcriber is
    /// applied. It parses the invocation's token stream as Rust and walks
    /// whatever comes out, which is what makes the calls inside `write!`,
    /// `println!`, `assert!`, `vec![]`, and `lazy_static!` visible at all —
    /// previously every one of them was invisible to the call graph, so a sink
    /// reached only through a macro argument produced no evidence.
    ///
    /// The recovery is deliberately conservative:
    ///
    /// * `macro_rules!` definitions are skipped. A definition body is a matcher
    ///   and a transcriber, not code that runs at that location, so walking it
    ///   would attribute calls to the defining module that never happen there.
    /// * Anything that does not parse is recorded in `unanalyzed_macros` rather
    ///   than guessed at, so the blind spot is reported.
    fn visit_macro_body(&mut self, mac: &syn::Macro) {
        let path = path_to_string(&mac.path);
        // A `macro_rules!` body is a template, not code in this position.
        if path == "macro_rules" {
            self.unanalyzed_macros.insert(format!("{path}!"));
            return;
        }
        let tokens = mac.tokens.clone();
        if tokens.is_empty() {
            return;
        }

        // Comma-separated expressions: the shape of `write!`, `println!`,
        // `assert_eq!`, and most argument-taking macros.
        if let Ok(arguments) =
            Punctuated::<Expr, Token![,]>::parse_terminated.parse2(tokens.clone())
        {
            for argument in &arguments {
                syn::visit::visit_expr(self, argument);
            }
            return;
        }
        // A single expression: `assert!(cond)` with a comma inside a call, and
        // similar.
        if let Ok(expression) = syn::parse2::<Expr>(tokens.clone()) {
            syn::visit::visit_expr(self, &expression);
            return;
        }
        // Statements: a block-bodied macro such as `lazy_static!`, once the
        // `static ref` spelling is normalized to something Rust can parse.
        let statement_tokens = rewrite_static_ref_tokens(tokens.clone());
        if let Ok(block) = syn::parse2::<syn::Block>(quote::quote! { { #statement_tokens } }) {
            syn::visit::visit_block(self, &block);
            return;
        }
        // Items: a macro that declares functions or types.
        if let Ok(file) = syn::parse2::<syn::File>(statement_tokens) {
            for item in &file.items {
                syn::visit::visit_item(self, item);
            }
            return;
        }
        self.unanalyzed_macros.insert(format!("{path}!"));
    }

    /// The conjunction of the `#[cfg(...)]` gates currently in scope.
    fn current_cfg_gate(&self) -> Option<String> {
        if self.cfg_gates.is_empty() {
            return None;
        }
        Some(self.cfg_gates.join(" && "))
    }

    fn current_declaration_id(&self) -> Option<String> {
        self.current_function
            .as_ref()
            .map(|frame| frame.declaration_id.clone())
    }

    fn current_function_name(&self) -> String {
        self.current_function
            .as_ref()
            .and_then(|frame| {
                self.declarations
                    .iter()
                    .find(|declaration| declaration.id == frame.declaration_id)
            })
            .map(|declaration| declaration.qualified_name.clone())
            .unwrap_or_default()
    }

    fn push_crypto_library(&mut self, provider: &str, family: &str, span: Span, evidence: &str) {
        let file_path = self.file_ctx.relative_file_path.clone();
        let mut properties = IndexMap::new();
        properties.insert("evidence".to_string(), evidence.to_string());
        properties.insert("confidence".to_string(), "medium".to_string());
        let library = CryptoLibrary {
            id: stable_id("crypto-library", &[provider, &file_path]),
            path: provider.to_string(),
            family: family.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            file_path: file_path.clone(),
            position: position_from_span(&file_path, span),
            properties,
        };
        if !self
            .crypto
            .libraries
            .iter()
            .any(|existing| existing.id == library.id)
        {
            self.crypto.libraries.push(library);
        }
    }

    fn push_crypto_component(&mut self, rule: &StableCryptoRule, span: Span, evidence: &str) {
        self.push_crypto_library(rule.provider, rule.kind, span, evidence);
        let file_path = self.file_ctx.relative_file_path.clone();
        let position = position_from_span(&file_path, span);
        let mut properties = IndexMap::new();
        properties.insert("evidence".to_string(), evidence.to_string());
        properties.insert("confidence".to_string(), "medium".to_string());
        let component = CryptoComponent {
            id: stable_id(
                "crypto-component",
                &[rule.symbol, &file_path, &span_key(span)],
            ),
            kind: rule.kind.to_string(),
            algorithm: rule.algorithm.to_string(),
            provider: rule.provider.to_string(),
            operation: rule.operation.to_string(),
            symbol: rule.symbol.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            file_path: file_path.clone(),
            position: position.clone(),
            properties,
        };
        if !self
            .crypto
            .components
            .iter()
            .any(|existing| existing.id == component.id)
        {
            self.crypto.components.push(component);
        }
        if let Some((category, severity, summary)) = rule.finding {
            let finding = CryptoFinding {
                id: stable_id("crypto-finding", &[category, rule.symbol, &span_key(span)]),
                category: category.to_string(),
                severity: severity.to_string(),
                confidence: "medium".to_string(),
                summary: summary.to_string(),
                package_path: self.file_ctx.package_path.clone(),
                file_path,
                position,
                properties: IndexMap::new(),
            };
            if !self
                .crypto
                .findings
                .iter()
                .any(|existing| existing.id == finding.id)
            {
                self.crypto.findings.push(finding);
            }
        }
    }

    fn push_crypto_material(&mut self, span: Span, kind: &str, name: &str) {
        if !looks_like_secret_name(name) {
            return;
        }
        let file_path = self.file_ctx.relative_file_path.clone();
        let material = CryptoMaterial {
            id: stable_id(
                "crypto-material",
                &[kind, name, &file_path, &span_key(span)],
            ),
            kind: kind.to_string(),
            name: name.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            file_path: file_path.clone(),
            function: self.current_function_name(),
            confidence: "medium".to_string(),
            position: position_from_span(&file_path, span),
            properties: IndexMap::new(),
        };
        if !self
            .crypto
            .materials
            .iter()
            .any(|existing| existing.id == material.id)
        {
            self.crypto.materials.push(material);
        }
    }

    fn collect_inline_closure(&mut self, closure: &ExprClosure, source_category: Option<&str>) {
        let name = closure_symbol_name(closure.span());
        let declaration = self.push_declaration(
            &name,
            "closure",
            closure.to_token_stream().to_string(),
            None,
            closure.span(),
        );
        let position = position_from_span(&self.file_ctx.relative_file_path, closure.span());
        if let Some(parent) = self.current_function.as_mut() {
            parent.record_call(SimplifiedCall {
                callee_text: declaration.qualified_name.clone(),
                position,
                receiver_text: None,
                receiver_expr: None,
                method_name: None,
                is_higher_order: true,
            });
        }

        let previous = self.current_function.replace(FunctionFrame {
            declaration_id: declaration.id.clone(),
            operations: Vec::new(),
            direct_calls: Vec::new(),
            receiver_type: None,
            is_loop_body: false,
            channel_pairs: Vec::new(),
            declared_types: BTreeMap::new(),
            collect_bodies: self.collect_bodies,
        });
        visit_callable_body(self, &closure.body);
        let mut finished = self.current_function.take().expect("closure frame exists");
        if let Some(tail_expr) = callable_body_tail_expr(&closure.body) {
            finished.operations.push(Operation::Return(tail_expr));
        }
        let param_types = closure_parameter_types(closure);
        self.functions.push(FunctionRecord {
            declaration,
            package_path: self.file_ctx.package_path.clone(),
            file_path: self.file_ctx.relative_file_path.clone(),
            params: closure_parameters(closure),
            param_types: param_types.clone(),
            param_source_categories: if let Some(category) = source_category {
                closure_source_categories(closure, category)
            } else {
                infer_param_source_categories(&param_types)
            },
            return_type: closure_return_type(closure),
            operations: finished.operations.clone(),
            direct_calls: finished.direct_calls,
            receiver_type: None,
            is_loop_body: false,
            channel_pairs: finished.channel_pairs.clone(),
            declared_types: finished.declared_types.clone(),
            has_body: self.collect_bodies,
        });
        self.current_function = previous;
    }
}

impl<'ast> Visit<'ast> for SourceCollector {
    fn visit_item_use(&mut self, item_use: &'ast syn::ItemUse) {
        collect_use_records(item_use, &self.file_ctx.module_path, &mut self.use_records);
        let before = self.imports.len();
        flatten_use_tree(
            &item_use.tree,
            String::new(),
            &self.file_ctx.package_path,
            &self.file_ctx.relative_file_path,
            item_use.span(),
            &mut self.imports,
        );
        let imported_paths = self.imports[before..]
            .iter()
            .map(|import| import.path.clone())
            .collect::<Vec<_>>();
        for path in imported_paths {
            if let Some((provider, family)) = classify_crypto_import_path(&path) {
                self.push_crypto_library(provider, family, item_use.span(), "import");
            }
        }
        syn::visit::visit_item_use(self, item_use);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let declaration = self.push_declaration(
            &node.sig.ident.to_string(),
            if matches!(node.sig.safety, syn::Safety::Unsafe(_)) {
                "unsafe-function"
            } else {
                "function"
            },
            signature_text(&node.sig),
            None,
            node.sig.ident.span(),
        );
        if matches!(node.sig.safety, syn::Safety::Unsafe(_)) {
            self.security_signals.push(SecuritySignal {
                id: stable_id("signal", &[&declaration.id, "unsafe-fn"]),
                category: "unsafe-code".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                description: format!("function {} is declared unsafe", declaration.qualified_name),
                package_path: declaration.package_path.clone(),
                purl: String::new(),
                file_path: declaration.file_path.clone(),
                position: declaration.position.clone(),
                cfg_gate: self.current_cfg_gate(),
            });
        }

        let previous = self.current_function.replace(FunctionFrame {
            declaration_id: declaration.id.clone(),
            operations: Vec::new(),
            direct_calls: Vec::new(),
            receiver_type: None,
            is_loop_body: false,
            channel_pairs: Vec::new(),
            declared_types: BTreeMap::new(),
            collect_bodies: self.collect_bodies,
        });
        syn::visit::visit_block(self, &node.block);
        let mut finished = self.current_function.take().expect("function frame exists");
        if let Some(tail_expr) = block_tail_expr(&node.block) {
            finished.operations.push(Operation::Return(tail_expr));
        }
        let param_types = function_parameter_types(&node.sig);
        self.functions.push(FunctionRecord {
            declaration,
            package_path: self.file_ctx.package_path.clone(),
            file_path: self.file_ctx.relative_file_path.clone(),
            params: function_parameters(&node.sig),
            param_types: param_types.clone(),
            param_source_categories: infer_param_source_categories_with_attrs(
                &node.sig,
                &node.attrs,
            ),
            return_type: function_return_type(&node.sig),
            operations: finished.operations.clone(),
            direct_calls: finished.direct_calls,
            receiver_type: None,
            is_loop_body: false,
            channel_pairs: finished.channel_pairs.clone(),
            declared_types: finished.declared_types.clone(),
            has_body: self.collect_bodies,
        });
        self.current_function = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let receiver = node.self_ty.to_token_stream().to_string().replace(' ', "");
        let trait_name = node.trait_.as_ref().map(|(path, _)| path_to_string(path));
        let previous_impl_trait = self
            .current_impl_trait
            .replace(trait_name.clone().unwrap_or_default());
        let mut method_ids = Vec::new();
        let mut method_names = Vec::new();
        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                // A method can carry its own gate on top of the impl block's.
                let method_gate = CfgExpr::from_attrs(&method.attrs);
                if !self.evaluator.is_enabled(&method_gate) {
                    continue;
                }
                let method_gate = method_gate.display();
                if let Some(gate) = method_gate.clone() {
                    self.cfg_gates.push(gate);
                }
                let declaration = self.push_declaration(
                    &method.sig.ident.to_string(),
                    if matches!(method.sig.safety, syn::Safety::Unsafe(_)) {
                        "unsafe-method"
                    } else {
                        "method"
                    },
                    signature_text(&method.sig),
                    Some(receiver.clone()),
                    method.sig.ident.span(),
                );
                method_ids.push(declaration.id.clone());
                method_names.push(declaration.qualified_name.clone());
                let previous = self.current_function.replace(FunctionFrame {
                    declaration_id: declaration.id.clone(),
                    operations: Vec::new(),
                    direct_calls: Vec::new(),
                    receiver_type: Some(receiver.clone()),
                    is_loop_body: false,
                    channel_pairs: Vec::new(),
                    declared_types: BTreeMap::new(),
                    collect_bodies: self.collect_bodies,
                });
                syn::visit::visit_block(self, &method.block);
                let mut finished = self.current_function.take().expect("method frame exists");
                if let Some(tail_expr) = block_tail_expr(&method.block) {
                    finished.operations.push(Operation::Return(tail_expr));
                }
                let param_types = function_parameter_types(&method.sig);
                self.functions.push(FunctionRecord {
                    declaration,
                    package_path: self.file_ctx.package_path.clone(),
                    file_path: self.file_ctx.relative_file_path.clone(),
                    params: function_parameters(&method.sig),
                    param_types: param_types.clone(),
                    param_source_categories: infer_param_source_categories_with_attrs(
                        &method.sig,
                        &method.attrs,
                    ),
                    return_type: function_return_type(&method.sig),
                    operations: finished.operations.clone(),
                    direct_calls: finished.direct_calls,
                    receiver_type: Some(receiver.clone()),
                    is_loop_body: false,
                    channel_pairs: finished.channel_pairs.clone(),
                    declared_types: finished.declared_types.clone(),
                    has_body: self.collect_bodies,
                });
                self.current_function = previous;
                if method_gate.is_some() {
                    self.cfg_gates.pop();
                }
            }
        }
        if let Some(trait_name) = trait_name {
            self.trait_impl_records.push(TraitImplRecord {
                trait_name,
                is_blanket: impl_is_blanket(node),
                impl_type: receiver,
                method_ids,
                method_names,
            });
        }
        // The method bodies were walked above. Delegating to the default
        // visitor here would walk them a second time, which duplicated every
        // item declared inside a body — and for a nested `fn`, re-emitted its
        // whole call set under the same declaration id. Visit only the impl
        // items the loop above skipped.
        for item in &node.items {
            if !matches!(item, ImplItem::Fn(_)) {
                syn::visit::visit_impl_item(self, item);
            }
        }
        self.current_impl_trait = previous_impl_trait;
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        self.push_declaration(
            &node.ident.to_string(),
            "module",
            format!("mod {}", node.ident),
            None,
            node.ident.span(),
        );
        // Items inside an inline module live one level deeper, so the module
        // segment has to be in scope while they are collected; otherwise they
        // are qualified as if they sat at file level.
        if node.content.is_some() {
            self.file_ctx.module_path.push(node.ident.to_string());
            syn::visit::visit_item_mod(self, node);
            self.file_ctx.module_path.pop();
        } else {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item(&mut self, node: &'ast Item) {
        // Single choke point for conditional compilation: `syn` routes every
        // item — in a file, an inline module, or a block — through here before
        // the kind-specific visitors, so a disabled item is never collected.
        let gate = CfgExpr::from_attrs(item_attrs(node));
        if !self.evaluator.is_enabled(&gate) {
            return;
        }
        let gate = gate.display();
        if let Some(gate) = gate.clone() {
            self.cfg_gates.push(gate);
        }
        match node {
            Item::Struct(item) => {
                self.push_declaration(
                    &item.ident.to_string(),
                    "struct",
                    item.to_token_stream().to_string(),
                    None,
                    item.ident.span(),
                );
                let field_names: Vec<String> = item
                    .fields
                    .iter()
                    .filter_map(|field| field.ident.as_ref().map(|ident| ident.to_string()))
                    .collect();
                for field in &item.fields {
                    if let Some(ident) = field.ident.as_ref()
                        && let Some(field_type) =
                            bare_type_token(&field.ty.to_token_stream().to_string())
                    {
                        self.field_types
                            .insert(format!("{}::{}", item.ident, ident), field_type);
                    }
                }
                if !field_names.is_empty() {
                    let key = qualify_name(&self.file_ctx, None, &item.ident.to_string());
                    self.struct_field_names.insert(key, field_names);
                }
            }
            Item::Enum(item) => {
                self.push_declaration(
                    &item.ident.to_string(),
                    "enum",
                    item.to_token_stream().to_string(),
                    None,
                    item.ident.span(),
                );
            }
            Item::Trait(item) => {
                self.push_declaration(
                    &item.ident.to_string(),
                    "trait",
                    item.to_token_stream().to_string(),
                    None,
                    item.ident.span(),
                );
                let trait_name = qualify_name(&self.file_ctx, None, &item.ident.to_string());
                let method_names: Vec<String> = item
                    .items
                    .iter()
                    .filter_map(|trait_item| match trait_item {
                        syn::TraitItem::Fn(method) => Some(method.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                if !method_names.is_empty() {
                    let key = format!("trait:{}", trait_name);
                    self.struct_field_names.insert(key, method_names);
                }
            }
            _ => {}
        }
        syn::visit::visit_item(self, node);
        if gate.is_some() {
            self.cfg_gates.pop();
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let callee_name = callee_text_from_expr(&node.func);
        if let Some(rule) = classify_stable_crypto_call(&callee_name, None) {
            self.push_crypto_component(&rule, node.span(), "syntax-call");
        }
        let usage_id = stable_id(
            "usage",
            &[
                &self.file_ctx.relative_file_path,
                &callee_name,
                &span_key(node.span()),
            ],
        );
        self.usages.push(LibraryUsage {
            id: usage_id,
            kind: "call".to_string(),
            name: callee_name.clone(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            enclosing_declaration: self.current_declaration_id(),
            position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
            properties: IndexMap::new(),
        });

        if let Some(frame) = self.current_function.as_mut() {
            let args = node.args.iter().map(simple_expr).collect::<Vec<_>>();
            let call = SimpleExpr::Call {
                callee: callee_name.clone(),
                args: args.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
            };
            frame.record_operation(Operation::Expr(call.clone()));
            frame.record_call(SimplifiedCall {
                callee_text: callee_name.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
                receiver_text: None,
                receiver_expr: None,
                method_name: None,
                is_higher_order: false,
            });
        }
        syn::visit::visit_expr(self, &node.func);
        for (index, arg) in node.args.iter().enumerate() {
            if let Expr::Closure(closure) = arg {
                self.collect_inline_closure(
                    closure,
                    inline_closure_source_category_for_call(&callee_name, index),
                );
            } else {
                syn::visit::visit_expr(self, arg);
            }
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let callee_name = method_call_callee(&node.receiver, &node.method.to_string());
        let receiver_text = node.receiver.to_token_stream().to_string();
        if let Some(rule) = classify_stable_crypto_call(&callee_name, Some(&receiver_text)) {
            self.push_crypto_component(&rule, node.span(), "syntax-call");
        }
        let usage_id = stable_id(
            "usage",
            &[
                &self.file_ctx.relative_file_path,
                &callee_name,
                &span_key(node.span()),
            ],
        );
        let mut properties = IndexMap::new();
        properties.insert("receiver".to_string(), receiver_text.clone());
        self.usages.push(LibraryUsage {
            id: usage_id,
            kind: "method-call".to_string(),
            name: callee_name.clone(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            enclosing_declaration: self.current_declaration_id(),
            position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
            properties,
        });

        if let Some(frame) = self.current_function.as_mut() {
            let mut args = vec![simple_expr(&node.receiver)];
            args.extend(node.args.iter().map(simple_expr));
            let call = SimpleExpr::Call {
                callee: callee_name.clone(),
                args: args.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
            };
            frame.record_operation(Operation::Expr(call.clone()));
            frame.record_call(SimplifiedCall {
                callee_text: callee_name.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
                receiver_text: Some(receiver_text.clone()),
                receiver_expr: Some(simple_expr(&node.receiver)),
                method_name: Some(node.method.to_string()),
                is_higher_order: false,
            });
        }
        syn::visit::visit_expr(self, &node.receiver);
        for (index, arg) in node.args.iter().enumerate() {
            if let Expr::Closure(closure) = arg {
                self.collect_inline_closure(
                    closure,
                    inline_closure_source_category_for_method_call(
                        &callee_name,
                        &node.receiver,
                        index,
                    ),
                );
            } else {
                syn::visit::visit_expr(self, arg);
            }
        }
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        self.visit_macro_body(&node.mac);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        self.visit_macro_body(&node.mac);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        self.visit_macro_body(&node.mac);
    }

    fn visit_impl_item_macro(&mut self, node: &'ast syn::ImplItemMacro) {
        self.visit_macro_body(&node.mac);
    }

    fn visit_trait_item_macro(&mut self, node: &'ast syn::TraitItemMacro) {
        self.visit_macro_body(&node.mac);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.security_signals.push(SecuritySignal {
            id: stable_id(
                "signal",
                &[
                    &self.file_ctx.relative_file_path,
                    "unsafe-block",
                    &span_key(node.span()),
                ],
            ),
            category: "unsafe-code".to_string(),
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            description: "unsafe block detected".to_string(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            file_path: self.file_ctx.relative_file_path.clone(),
            position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
            cfg_gate: self.current_cfg_gate(),
        });
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        let secret_binding = match node {
            Stmt::Local(local) => match &local.pat {
                Pat::Ident(PatIdent { ident, .. }) => {
                    let kind = classify_secret_name_kind(&ident.to_string());
                    if kind != "material" {
                        Some((ident.span(), kind, ident.to_string()))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((span, kind, name)) = secret_binding {
            self.push_crypto_material(span, kind, &name);
        }
        if let Some(frame) = self.current_function.as_mut() {
            match node {
                Stmt::Local(local) => {
                    // `let x: T = ..` wraps the pattern in `Pat::Type`. Matching
                    // only on the inner shapes below meant an annotated binding
                    // recorded no assignment at all, so taint stopped dead at
                    // it — `let secret: String = env::var(..)` propagated
                    // nothing, while the identical unannotated line did.
                    let (pattern, declared_type) = match &local.pat {
                        Pat::Type(pat_type) => (
                            pat_type.pat.as_ref(),
                            Some(pat_type.ty.to_token_stream().to_string()),
                        ),
                        other => (other, None),
                    };
                    // An annotation is the most reliable type information
                    // available, so it is kept verbatim rather than re-derived.
                    if let (Some(declared_type), Pat::Ident(PatIdent { ident, .. })) =
                        (declared_type.as_deref(), pattern)
                        && let Some(token) = bare_type_token(declared_type)
                    {
                        frame.declared_types.insert(ident.to_string(), token);
                    }
                    if let Some(init) = &local.init {
                        // P4.2: detect `let (tx, rx) = ... channel()`-style
                        // tuple bindings so the concrete pass can unify
                        // per-channel taint slots across the two endpoints.
                        if let Pat::Tuple(pat_tuple) = pattern
                            && pat_tuple.elems.len() == 2
                            && let Some((tx_name, rx_name)) = channel_pair_names(pat_tuple)
                            && channel_construction(init)
                        {
                            frame.record_channel_pair((tx_name.clone(), rx_name.clone()));
                            // Bind both names so the rest of the visitor
                            // treats them like ordinary locals.
                            frame.record_operation(Operation::Assign {
                                target: tx_name,
                                value: simple_expr(&init.expr),
                            });
                            frame.record_operation(Operation::Assign {
                                target: rx_name,
                                value: simple_expr(&init.expr),
                            });
                        } else if let Pat::Ident(PatIdent { ident, .. }) = pattern {
                            if let Expr::Field(ExprField { base, member, .. }) = &*init.expr
                                && let Some(target_var) = extract_path_name(base)
                            {
                                let target_name = qualified_target_name(
                                    &self.struct_field_names,
                                    &target_var,
                                    &member_from_expr(member),
                                );
                                frame.record_operation(Operation::AssignField {
                                    target: ident.to_string(),
                                    field: target_name,
                                    value: simple_expr(&init.expr),
                                });
                            } else if let Expr::Struct(syn::ExprStruct { fields, .. }) = &*init.expr
                            {
                                // P3.5: struct-literal binding. Emit one
                                // AssignField per named field so access-path-
                                // aware reads can distinguish `x.tainted`
                                // from `x.clean`. Critically, do NOT emit a
                                // whole-object Assign for `x` — that would
                                // union every field's taint back onto the
                                // base key and defeat the per-field precision.
                                // Whole-object reads of `x` still see the
                                // union of all `x.*` keys via the
                                // `SimpleExpr::Var` arm (sound-leaning).
                                let target = ident.to_string();
                                for field in fields {
                                    let field_name = member_from_expr(&field.member);
                                    frame.record_operation(Operation::AssignField {
                                        target: target.clone(),
                                        field: field_name,
                                        value: simple_expr(&field.expr),
                                    });
                                }
                            } else {
                                frame.record_operation(Operation::Assign {
                                    target: ident.to_string(),
                                    value: simple_expr(&init.expr),
                                });
                            }
                        }
                    }
                }
                Stmt::Expr(expr, _) => {
                    if let Expr::Return(ExprReturn {
                        expr: Some(value), ..
                    }) = expr
                    {
                        frame.record_operation(Operation::Return(simple_expr(value)));
                    } else if let Expr::Assign(assign) = expr {
                        if let Expr::Field(field_expr) = &*assign.left
                            && let Some(target_var) = extract_path_name(&field_expr.base)
                        {
                            let field_name = member_from_expr(&field_expr.member);
                            let qualified_field = qualified_target_name(
                                &self.struct_field_names,
                                &target_var,
                                &field_name,
                            );
                            frame.record_operation(Operation::AssignField {
                                target: target_var,
                                field: qualified_field,
                                value: simple_expr(&assign.right),
                            });
                        } else {
                            frame.record_operation(Operation::Expr(simple_expr(expr)));
                        }
                    } else {
                        frame.record_operation(Operation::Expr(simple_expr(expr)));
                    }
                }
                _ => {}
            }
        }
        syn::visit::visit_stmt(self, node);
    }
}

/// Whether an impl block is a blanket impl: its self type is one of its own
/// generic type parameters, so it applies to every type that satisfies the
/// bounds rather than to one named type.
fn impl_is_blanket(node: &ItemImpl) -> bool {
    let self_type = node.self_ty.to_token_stream().to_string().replace(' ', "");
    node.generics.params.iter().any(|param| match param {
        syn::GenericParam::Type(type_param) => type_param.ident == self_type,
        _ => false,
    })
}

/// Attributes written on any item, for cfg evaluation.
fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        // `Item` is non-exhaustive; an unrecognized shape carries no gate we
        // can evaluate, so it stays enabled.
        _ => &[],
    }
}

fn flatten_use_tree(
    tree: &UseTree,
    prefix: String,
    package_path: &str,
    file_path: &str,
    span: Span,
    imports: &mut Vec<ImportUsage>,
) {
    match tree {
        UseTree::Path(path) => {
            let next = if prefix.is_empty() {
                path.ident.to_string()
            } else {
                format!("{prefix}::{}", path.ident)
            };
            flatten_use_tree(&path.tree, next, package_path, file_path, span, imports);
        }
        UseTree::Name(name) => {
            let path = if prefix.is_empty() {
                name.ident.to_string()
            } else {
                format!("{prefix}::{}", name.ident)
            };
            imports.push(ImportUsage {
                path,
                alias: None,
                package_path: package_path.to_string(),
                purl: String::new(),
                position: position_from_span(file_path, span),
            });
        }
        UseTree::Rename(UseRename { ident, rename, .. }) => {
            let path = if prefix.is_empty() {
                ident.to_string()
            } else {
                format!("{prefix}::{ident}")
            };
            imports.push(ImportUsage {
                path,
                alias: Some(rename.to_string()),
                package_path: package_path.to_string(),
                purl: String::new(),
                position: position_from_span(file_path, span),
            });
        }
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix.clone(), package_path, file_path, span, imports);
            }
        }
        UseTree::Glob(_) => {
            let path = if prefix.is_empty() {
                "*".to_string()
            } else {
                format!("{prefix}::*")
            };
            imports.push(ImportUsage {
                path,
                alias: None,
                package_path: package_path.to_string(),
                purl: String::new(),
                position: position_from_span(file_path, span),
            });
        }
    }
}

fn function_parameters(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Typed(pat_type) => match &*pat_type.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            FnArg::Receiver(_) => Some("self".to_string()),
        })
        .collect()
}

fn function_parameter_types(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .map(|input| match input {
            FnArg::Typed(pat_type) => pat_type.ty.to_token_stream().to_string(),
            FnArg::Receiver(receiver) => match &receiver.kind {
                // `&self` / `&mut self`; the `mut` lives inside the variant,
                // while `Receiver::mutability` only covers by-value `mut self`.
                syn::ReceiverKind::Reference(.., Some(_)) => "&mut Self".to_string(),
                syn::ReceiverKind::Reference(.., None) => "&Self".to_string(),
                // `self`, `mut self`, and explicit `self: Box<Self>` receivers.
                _ => "Self".to_string(),
            },
        })
        .collect()
}

fn function_return_type(sig: &Signature) -> String {
    match &sig.output {
        ReturnType::Default => "()".to_string(),
        ReturnType::Type(_, ty) => ty.to_token_stream().to_string(),
    }
}

fn closure_parameters(closure: &ExprClosure) -> Vec<String> {
    closure
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| closure_parameter_name(input, index))
        .collect()
}

fn closure_parameter_types(closure: &ExprClosure) -> Vec<String> {
    closure
        .inputs
        .iter()
        .map(|input| match input {
            Pat::Type(PatType { ty, .. }) => ty.to_token_stream().to_string(),
            _ => "_".to_string(),
        })
        .collect()
}

fn closure_parameter_name(input: &Pat, index: usize) -> String {
    match input {
        Pat::Ident(ident) => ident.ident.to_string(),
        Pat::Type(PatType { pat, .. }) => match &**pat {
            Pat::Ident(ident) => ident.ident.to_string(),
            _ => format!("arg_{index}"),
        },
        _ => format!("arg_{index}"),
    }
}

fn closure_source_categories(closure: &ExprClosure, category: &str) -> BTreeMap<usize, String> {
    let mut sources = BTreeMap::new();
    for (index, _) in closure.inputs.iter().enumerate() {
        sources.insert(index, category.to_string());
    }
    sources
}

fn closure_return_type(_closure: &ExprClosure) -> String {
    "_".to_string()
}

fn closure_symbol_name(span: Span) -> String {
    let start = span.start();
    format!("closure_{}_{}", start.line, start.column + 1)
}

fn visit_callable_body<'ast, V: Visit<'ast>>(visitor: &mut V, body: &'ast Expr) {
    match body {
        Expr::Block(ExprBlock { block, .. }) => syn::visit::visit_block(visitor, block),
        Expr::Async(ExprAsync { block, .. }) => syn::visit::visit_block(visitor, block),
        other => syn::visit::visit_expr(visitor, other),
    }
}

fn callable_body_tail_expr(body: &Expr) -> Option<SimpleExpr> {
    match body {
        Expr::Block(ExprBlock { block, .. }) => block_tail_expr(block),
        Expr::Async(ExprAsync { block, .. }) => block_tail_expr(block),
        Expr::Return(_) => None,
        other => Some(simple_expr(other)),
    }
}

fn http_source_type_patterns() -> &'static [&'static str] {
    &[
        "Request",
        "HttpRequest",
        "IncomingRequest",
        "RouterRequest",
        "axum::extract::Path<",
        "axum::extract::Query<",
        "axum::extract::Json<",
        "axum::extract::Form<",
        "axum::extract::RawQuery",
        "axum::extract::Host",
        "actix_web::web::Path<",
        "actix_web::web::Query<",
        "actix_web::web::Json<",
        "actix_web::web::Form<",
        "rocket::form::Form<",
        "rocket::serde::json::Json<",
        "rocket::request::Request",
        "poem::web::Path<",
        "poem::web::Query<",
        "poem::web::Json<",
        "poem::web::Form<",
        "salvo::Request",
        "salvo::http::Request",
        "salvo::extract::QueryParam<",
        "salvo::extract::FormBody<",
        "salvo::extract::JsonBody<",
        "ntex::web::types::Path<",
        "ntex::web::types::Query<",
        "ntex::web::types::Json<",
        "ntex::web::types::Form<",
        "gotham::state::State",
        "gotham::extractor::path::PathExtractor<",
        "gotham::extractor::query_string::QueryStringExtractor<",
        "dropshot::RequestContext<",
        "dropshot::TypedBody<",
        "dropshot::Query<",
        "tide::Request<",
        "rouille::Request",
        "iron::Request",
        "nickel::Request<",
        "thruster::Context",
        "hyper::Request<",
        "warp::filters::path::Tail",
        "poem_openapi::payload::Json<",
    ]
}

fn http_route_attr_names() -> &'static [&'static str] {
    &[
        "get", "post", "put", "delete", "patch", "head", "options", "route", "routes", "handler",
        "endpoint", "oai", "method", "trace",
    ]
}

fn looks_like_http_payload_type(normalized: &str) -> bool {
    matches!(
        normalized,
        "String"
            | "&str"
            | "str"
            | "usize"
            | "u64"
            | "u32"
            | "u16"
            | "u8"
            | "isize"
            | "i64"
            | "i32"
            | "i16"
            | "i8"
            | "bool"
            | "PathBuf"
            | "Bytes"
    ) || normalized.starts_with("Option<")
        || normalized.starts_with("Vec<")
        || normalized.starts_with("HashMap<")
        || normalized.starts_with("BTreeMap<")
        || normalized.starts_with("serde_json::Value")
        || normalized.starts_with("Value")
}

fn looks_like_injected_framework_state(normalized: &str) -> bool {
    [
        "State<",
        "Extension<",
        "Data<",
        "Pool",
        "Client",
        "Connection",
        "Config",
        "Context",
    ]
    .iter()
    .any(|pattern| normalized.contains(pattern))
}

fn infer_param_source_categories(param_types: &[String]) -> BTreeMap<usize, String> {
    let mut sources = BTreeMap::new();
    for (index, ty) in param_types.iter().enumerate() {
        let normalized = ty.replace(' ', "");
        if http_source_type_patterns()
            .iter()
            .any(|pattern| normalized.contains(pattern))
        {
            sources.insert(index, "http-request".to_string());
        }
    }
    sources
}

fn infer_param_source_categories_with_attrs(
    sig: &Signature,
    attrs: &[syn::Attribute],
) -> BTreeMap<usize, String> {
    let param_types = function_parameter_types(sig);
    let mut sources = infer_param_source_categories(&param_types);
    let route_handler = attrs.iter().any(|attr| {
        let attr_path = path_to_string(attr.path());
        let name = last_segment(&attr_path);
        http_route_attr_names().contains(&name)
    });
    if route_handler {
        for (index, ty) in param_types.iter().enumerate() {
            let normalized = ty.replace(' ', "");
            if looks_like_http_payload_type(&normalized)
                && !looks_like_injected_framework_state(&normalized)
            {
                sources
                    .entry(index)
                    .or_insert_with(|| "http-request".to_string());
            }
        }
    }
    sources
}

fn inline_closure_source_category_for_call(
    callee_name: &str,
    index: usize,
) -> Option<&'static str> {
    let normalized = normalize_pattern_text(callee_name);
    // Only the first argument is the handler closure in either shape: the
    // whole-server form (`Iron::new(handler)`) and the per-route form
    // (`get(handler)`). Both hand the closure an HTTP request.
    let is_handler_position = index == 0
        && (matches!(normalized.as_str(), "Iron::new" | "iron::Iron::new")
            || matches!(
                last_segment(&normalized),
                "get"
                    | "post"
                    | "put"
                    | "delete"
                    | "patch"
                    | "options"
                    | "head"
                    | "route"
                    | "handler"
            ));
    is_handler_position.then_some("http-request")
}

fn inline_closure_source_category_for_method_call(
    method_name: &str,
    receiver: &Expr,
    index: usize,
) -> Option<&'static str> {
    if index > 0 {
        return None;
    }
    let normalized_receiver = receiver.to_token_stream().to_string().replace(' ', "");
    if matches!(method_name, "map" | "then" | "and_then")
        && [
            "warp::path::param()",
            "warp::query()",
            "warp::body::json()",
            "warp::body::form()",
        ]
        .iter()
        .any(|pattern| normalized_receiver.contains(pattern))
    {
        Some("http-request")
    } else {
        None
    }
}

/// Rewrites `static ref NAME: T = ...` to `static NAME: T = ...`.
///
/// `lazy_static!` and its relatives spell their bodies with a `ref` that is not
/// valid Rust, so the body cannot be parsed as-is. Dropping that one token
/// makes the initializer — usually where the interesting call lives, such as
/// `Regex::new` or a client constructor — recoverable.
fn rewrite_static_ref_tokens(tokens: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    let mut output = proc_macro2::TokenStream::new();
    let mut after_static = false;
    for token in tokens {
        match &token {
            proc_macro2::TokenTree::Ident(ident) if after_static && ident == "ref" => {
                // Drop it, and stay out of `after_static` so `static ref ref`
                // (which cannot occur) is not treated specially.
                after_static = false;
                continue;
            }
            proc_macro2::TokenTree::Ident(ident) => {
                after_static = ident == "static";
            }
            proc_macro2::TokenTree::Group(group) => {
                after_static = false;
                let inner = rewrite_static_ref_tokens(group.stream());
                let mut rewritten = proc_macro2::Group::new(group.delimiter(), inner);
                rewritten.set_span(group.span());
                output.extend(std::iter::once(proc_macro2::TokenTree::Group(rewritten)));
                continue;
            }
            _ => after_static = false,
        }
        output.extend(std::iter::once(token));
    }
    output
}

fn parse_macro_like_call(expr: &ExprMacro) -> Option<SimpleExpr> {
    if !expr.mac.path.is_ident("format") {
        return None;
    }

    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    let args = parser.parse2(expr.mac.tokens.clone()).ok()?;
    let mut args_iter = args.into_iter();
    let first = args_iter.next();
    let html_template = matches!(
        first,
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        })) if value.value().contains('<')
    );
    let callee = if html_template {
        "format!#html"
    } else {
        "format!"
    };
    Some(SimpleExpr::Call {
        callee: callee.to_string(),
        args: args_iter.map(|arg| simple_expr(&arg)).collect(),
        position: Position::default(),
    })
}

fn optional_crypto_evidence(crypto: &CryptoEvidence) -> Option<CryptoEvidence> {
    if crypto.libraries.is_empty()
        && crypto.components.is_empty()
        && crypto.materials.is_empty()
        && crypto.findings.is_empty()
    {
        None
    } else {
        Some(crypto.clone())
    }
}

fn classify_crypto_import_path(path: &str) -> Option<(&'static str, &'static str)> {
    let normalized = normalize_pattern_text(path).replace('-', "_");
    let root = normalized.split("::").next().unwrap_or(normalized.as_str());
    match root {
        "sha1" => Some(("sha1", "hash")),
        "sha2" => Some(("sha2", "hash")),
        "md5" => Some(("md5", "hash")),
        "blake3" => Some(("blake3", "hash")),
        "aes_gcm" => Some(("aes_gcm", "aead")),
        "aes_gcm_siv" => Some(("aes_gcm_siv", "aead")),
        "chacha20poly1305" => Some(("chacha20poly1305", "aead")),
        "hmac" => Some(("hmac", "mac")),
        "argon2" => Some(("argon2", "kdf")),
        "pbkdf2" => Some(("pbkdf2", "kdf")),
        "scrypt" => Some(("scrypt", "kdf")),
        "hkdf" => Some(("hkdf", "kdf")),
        "jsonwebtoken" => Some(("jsonwebtoken", "token")),
        "rustls" => Some(("rustls", "protocol")),
        "tokio_rustls" => Some(("tokio_rustls", "protocol")),
        "native_tls" => Some(("native_tls", "protocol")),
        "openssl" => Some(("openssl", "protocol")),
        "x509_parser" => Some(("x509_parser", "certificate")),
        "webpki" => Some(("webpki", "certificate")),
        "rustls_pemfile" => Some(("rustls_pemfile", "certificate")),
        "rcgen" => Some(("rcgen", "certificate")),
        "rsa" => Some(("rsa", "asymmetric")),
        "p256" => Some(("p256", "asymmetric")),
        "p384" => Some(("p384", "asymmetric")),
        "k256" => Some(("k256", "asymmetric")),
        "ed25519_dalek" => Some(("ed25519_dalek", "asymmetric")),
        "x25519_dalek" => Some(("x25519_dalek", "asymmetric")),
        "ring" if normalized.contains("::aead") => Some(("ring", "aead")),
        "ring" if normalized.contains("::digest") => Some(("ring", "hash")),
        "ring" if normalized.contains("::signature") || normalized.contains("::agreement") => {
            Some(("ring", "asymmetric"))
        }
        "ring" => Some(("ring", "crypto")),
        _ => None,
    }
}

fn classify_stable_crypto_call(
    callee: &str,
    receiver_text: Option<&str>,
) -> Option<StableCryptoRule> {
    let normalized = normalize_pattern_text(callee);
    let receiver = receiver_text
        .map(normalize_pattern_text)
        .unwrap_or_default();

    if normalized.ends_with("sha2::Sha256::digest") || normalized.ends_with("Sha256::digest") {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "SHA-256",
            provider: "sha2",
            operation: "digest",
            symbol: "sha2::Sha256::digest",
            finding: None,
        })
    } else if normalized.ends_with("sha2::Sha512::digest") || normalized.ends_with("Sha512::digest")
    {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "SHA-512",
            provider: "sha2",
            operation: "digest",
            symbol: "sha2::Sha512::digest",
            finding: None,
        })
    } else if normalized.ends_with("sha1::Sha1::digest") || normalized.ends_with("Sha1::digest") {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "SHA-1",
            provider: "sha1",
            operation: "digest",
            symbol: "sha1::Sha1::digest",
            finding: Some(("weak-crypto", "high", "SHA-1 usage detected")),
        })
    } else if normalized.ends_with("md5::compute") {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "MD5",
            provider: "md5",
            operation: "digest",
            symbol: "md5::compute",
            finding: Some(("weak-crypto", "high", "MD5 usage detected")),
        })
    } else if normalized.ends_with("blake3::hash") {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "BLAKE3",
            provider: "blake3",
            operation: "digest",
            symbol: "blake3::hash",
            finding: None,
        })
    } else if normalized.ends_with("ring::digest::digest") || normalized == "digest" {
        Some(StableCryptoRule {
            kind: "hash",
            algorithm: "SHA-256",
            provider: "ring",
            operation: "digest",
            symbol: "ring::digest::digest",
            finding: None,
        })
    } else if normalized.ends_with("Aes256Gcm::new_from_slice")
        || normalized.ends_with("aes_gcm::Aes256Gcm::new_from_slice")
        || normalized.ends_with("aes_gcm::aead::KeyInit::new_from_slice")
    {
        Some(StableCryptoRule {
            kind: "aead",
            algorithm: "AES-GCM",
            provider: "aes_gcm",
            operation: "key-init",
            symbol: "aes_gcm::aead::KeyInit::new_from_slice",
            finding: None,
        })
    } else if normalized.ends_with("ChaCha20Poly1305::new_from_slice")
        || normalized.ends_with("chacha20poly1305::ChaCha20Poly1305::new_from_slice")
        || normalized.ends_with("chacha20poly1305::aead::KeyInit::new_from_slice")
    {
        Some(StableCryptoRule {
            kind: "aead",
            algorithm: "ChaCha20-Poly1305",
            provider: "chacha20poly1305",
            operation: "key-init",
            symbol: "chacha20poly1305::aead::KeyInit::new_from_slice",
            finding: None,
        })
    } else if normalized.ends_with("ring::aead::UnboundKey::new")
        || normalized.ends_with("UnboundKey::new")
    {
        Some(StableCryptoRule {
            kind: "aead",
            algorithm: "Ring-AEAD",
            provider: "ring",
            operation: "key-init",
            symbol: "ring::aead::UnboundKey::new",
            finding: None,
        })
    } else if (normalized.contains("Hmac<") || normalized.ends_with("Hmac::new_from_slice"))
        && normalized.ends_with("new_from_slice")
    {
        Some(StableCryptoRule {
            kind: "mac",
            algorithm: if normalized.contains("Sha256") {
                "HMAC-SHA256"
            } else {
                "HMAC"
            },
            provider: "hmac",
            operation: "key-init",
            symbol: "hmac::Mac::new_from_slice",
            finding: None,
        })
    } else if normalized == "pbkdf2_hmac"
        || normalized.ends_with("::pbkdf2_hmac")
        || normalized.starts_with("pbkdf2_hmac::<")
    {
        Some(StableCryptoRule {
            kind: "kdf",
            algorithm: if normalized.contains("Sha256") {
                "PBKDF2-HMAC-SHA256"
            } else {
                "PBKDF2"
            },
            provider: "pbkdf2",
            operation: "derive",
            symbol: "pbkdf2::pbkdf2_hmac",
            finding: None,
        })
    } else if normalized.ends_with("EncodingKey::from_secret")
        || normalized.ends_with("jsonwebtoken::EncodingKey::from_secret")
    {
        Some(StableCryptoRule {
            kind: "token",
            algorithm: "JWT",
            provider: "jsonwebtoken",
            operation: "encode-key",
            symbol: "jsonwebtoken::EncodingKey::from_secret",
            finding: None,
        })
    } else if normalized.ends_with("ClientConfig::builder")
        || normalized.ends_with("ServerConfig::builder")
        || normalized.ends_with("rustls::ClientConfig::builder")
        || normalized.ends_with("rustls::ServerConfig::builder")
    {
        Some(StableCryptoRule {
            kind: "protocol",
            algorithm: "TLS",
            provider: "rustls",
            operation: "config-builder",
            symbol: "rustls::ClientConfig::builder",
            finding: None,
        })
    } else if normalized.ends_with("rsa::RsaPrivateKey::new")
        || normalized.ends_with("RsaPrivateKey::new")
    {
        Some(StableCryptoRule {
            kind: "asymmetric",
            algorithm: "RSA",
            provider: "rsa",
            operation: "keygen",
            symbol: "rsa::RsaPrivateKey::new",
            finding: None,
        })
    } else if normalized.ends_with("ed25519_dalek::SigningKey::from_bytes")
        || normalized.ends_with("SigningKey::from_bytes")
    {
        Some(StableCryptoRule {
            kind: "asymmetric",
            algorithm: "Ed25519",
            provider: "ed25519_dalek",
            operation: "key-init",
            symbol: "ed25519_dalek::SigningKey::from_bytes",
            finding: None,
        })
    } else if normalized == "hash_password"
        && (receiver.contains("Argon2::default()")
            || receiver.contains("argon2::Argon2::default()"))
    {
        Some(StableCryptoRule {
            kind: "kdf",
            algorithm: "Argon2",
            provider: "argon2",
            operation: "hash-password",
            symbol: "argon2::Argon2::hash_password",
            finding: None,
        })
    } else {
        None
    }
}

fn looks_like_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "key", "secret", "password", "token", "nonce", "salt", "iv", "seed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn classify_secret_name_kind(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("nonce") || lower.contains("salt") || lower == "iv" {
        "nonce"
    } else if lower.contains("key")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("token")
    {
        "key"
    } else {
        "material"
    }
}

fn built_in_sanitizer_patterns() -> &'static [&'static str] {
    &[
        "ammonia::clean",
        "clean",
        "html_escape::encode_safe",
        "encode_safe",
        "html_escape::encode_text",
        "v_htmlescape::escape",
        "bind",
        "push_bind",
        "push_values",
        "params",
        "params_from_iter",
    ]
}

fn is_sanitizer_call(callee: &str) -> bool {
    let normalized = normalize_pattern_text(callee);
    built_in_sanitizer_patterns()
        .iter()
        .any(|pattern| pattern_matches_callee(&normalized, pattern))
}

fn method_call_callee(receiver: &Expr, method: &str) -> String {
    let receiver_text = receiver.to_token_stream().to_string().replace(' ', "");
    if method == "body" && receiver_text.contains("HttpResponse") {
        return "HttpResponse::body".to_string();
    }
    if method == "body"
        && (receiver_text.contains("Response::builder")
            || receiver_text.contains("http::Response::builder"))
    {
        return "Response::body".to_string();
    }
    if method == "html" && receiver_text.contains("warp::reply") {
        return "warp::reply::html".to_string();
    }
    method.to_string()
}

/// Extract `(tx_name, rx_name)` from a 2-element tuple pattern, when both
/// elements are simple identifiers (the `let (tx, rx) = ...` shape). Used
/// by the channel-pair discovery in P4.2.
fn channel_pair_names(pat: &syn::PatTuple) -> Option<(String, String)> {
    let mut elems = pat.elems.iter();
    let tx = match elems.next()? {
        Pat::Ident(ident) => ident.ident.to_string(),
        _ => return None,
    };
    let rx = match elems.next()? {
        Pat::Ident(ident) => ident.ident.to_string(),
        _ => return None,
    };
    if elems.next().is_some() {
        return None;
    }
    Some((tx, rx))
}

/// True when the local initializer looks like a channel construction:
/// `channel()`, `mpsc::channel()`, `unbounded()`, `sync_channel(...)`, etc.
/// Conservative — only matches the bare-call shape whose callee last
/// segment is one of the recognized constructor names.
fn channel_construction(init: &syn::LocalInit) -> bool {
    let expr = &init.expr;
    let callee = match expr.as_ref() {
        Expr::Call(ExprCall { func, .. }) => callee_text_from_expr(func),
        _ => return false,
    };
    let last = last_segment(&callee);
    matches!(
        last,
        "channel" | "sync_channel" | "unbounded_channel" | "unbounded" | "bounded"
    )
}

fn signature_text(sig: &Signature) -> String {
    let mut text = sig.to_token_stream().to_string();
    if let ReturnType::Default = sig.output {
        text = text.replace(" ->", "");
    }
    text
}

fn qualify_name(file_ctx: &FileContext, receiver: Option<&str>, name: &str) -> String {
    let mut segments = vec![file_ctx.crate_path.clone()];
    segments.extend(file_ctx.module_path.clone());
    if let Some(receiver) = receiver {
        segments.push(receiver.to_string());
    }
    segments.push(name.to_string());
    segments.join("::")
}

pub(crate) fn position_from_span(file_path: &str, span: Span) -> Position {
    let start = span.start();
    Position {
        filename: file_path.to_string(),
        line: start.line,
        column: start.column + 1,
    }
}

fn span_key(span: Span) -> String {
    let start = span.start();
    format!("{}:{}", start.line, start.column + 1)
}

fn simple_expr(expr: &Expr) -> SimpleExpr {
    match expr {
        Expr::Path(ExprPath { path, .. }) => SimpleExpr::Var(path_to_string(path)),
        Expr::Call(ExprCall { func, args, .. }) => {
            let span = func.span();
            let start = span.start();
            SimpleExpr::Call {
                callee: callee_text_from_expr(func),
                args: args.iter().map(simple_expr).collect(),
                position: Position {
                    filename: String::new(),
                    line: start.line,
                    column: start.column + 1,
                },
            }
        }
        Expr::MethodCall(ExprMethodCall {
            receiver,
            method,
            args,
            ..
        }) => {
            let span = method.span();
            let start = span.start();
            let callee_name = method_call_callee(receiver, &method.to_string());
            let all_args = args.iter().map(simple_expr).collect::<Vec<_>>();
            SimpleExpr::MethodCall {
                receiver: Box::new(simple_expr(receiver)),
                method: callee_name.clone(),
                args: all_args,
                position: Position {
                    filename: String::new(),
                    line: start.line,
                    column: start.column + 1,
                },
            }
        }
        Expr::Reference(ExprReference {
            expr, mutability, ..
        }) => SimpleExpr::Reference {
            expr: Box::new(simple_expr(expr)),
            mutable: mutability.is_some(),
        },
        Expr::Paren(ExprParen { expr, .. }) => simple_expr(expr),
        Expr::Field(ExprField { base, member, .. }) => SimpleExpr::Field {
            base: Box::new(simple_expr(base)),
            field: member_from_expr(member),
        },
        Expr::Return(ExprReturn {
            expr: Some(expr), ..
        }) => simple_expr(expr),
        Expr::Block(ExprBlock { block, .. }) => block
            .stmts
            .last()
            .map(stmt_tail_expr)
            .unwrap_or(SimpleExpr::Unknown),
        Expr::Tuple(ExprTuple { elems, .. }) if elems.len() == 1 => simple_expr(&elems[0]),
        Expr::Tuple(ExprTuple { elems, .. }) => {
            SimpleExpr::Compose(elems.iter().map(simple_expr).collect())
        }
        Expr::Macro(expr_macro) => parse_macro_like_call(expr_macro).unwrap_or(SimpleExpr::Unknown),
        Expr::Lit(_) => SimpleExpr::Literal,
        Expr::If(syn::ExprIf {
            cond,
            then_branch,
            else_branch,
            ..
        }) => {
            let mut items = vec![
                simple_expr(cond),
                then_branch
                    .stmts
                    .last()
                    .map(stmt_tail_expr)
                    .unwrap_or(SimpleExpr::Unknown),
            ];
            if let Some((_, else_expr)) = else_branch {
                items.push(simple_expr(else_expr));
            }
            SimpleExpr::Compose(items)
        }
        Expr::Match(syn::ExprMatch { expr, arms, .. }) => {
            let mut items = vec![simple_expr(expr)];
            items.extend(arms.iter().map(|arm| simple_expr(&arm.body)));
            SimpleExpr::Compose(items)
        }
        Expr::Try(syn::ExprTry { expr, .. }) => simple_expr(expr),
        Expr::Binary(syn::ExprBinary { left, right, .. }) => {
            SimpleExpr::Compose(vec![simple_expr(left), simple_expr(right)])
        }
        Expr::Cast(syn::ExprCast { expr, .. }) => simple_expr(expr),
        Expr::Index(syn::ExprIndex { expr, .. }) => simple_expr(expr),
        Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Deref(_),
            expr,
            ..
        }) => simple_expr(expr),
        Expr::Unary(syn::ExprUnary { expr, .. }) => simple_expr(expr),
        Expr::Assign(syn::ExprAssign { left, right, .. }) => {
            if let Expr::Field(field_expr) = &**left
                && let Some(_base) = extract_path_name(&field_expr.base)
            {
                let _result = simple_expr(right);
                SimpleExpr::Compose(vec![
                    SimpleExpr::Field {
                        base: Box::new(simple_expr(&field_expr.base)),
                        field: member_from_expr(&field_expr.member),
                    },
                    simple_expr(right),
                ])
            } else {
                SimpleExpr::Compose(vec![simple_expr(left), simple_expr(right)])
            }
        }
        Expr::Group(syn::ExprGroup { expr, .. }) => simple_expr(expr),
        Expr::Struct(syn::ExprStruct { fields, .. }) => {
            let items: Vec<SimpleExpr> = fields
                .iter()
                .map(|field| simple_expr(&field.expr))
                .collect();
            if items.len() == 1 {
                items.into_iter().next().unwrap_or(SimpleExpr::Unknown)
            } else {
                SimpleExpr::Compose(items)
            }
        }
        _ => SimpleExpr::Unknown,
    }
}

fn stmt_tail_expr(stmt: &Stmt) -> SimpleExpr {
    match stmt {
        Stmt::Expr(expr, _) => simple_expr(expr),
        _ => SimpleExpr::Unknown,
    }
}

fn block_tail_expr(block: &syn::Block) -> Option<SimpleExpr> {
    match block.stmts.last() {
        Some(Stmt::Expr(expr, _)) if !matches!(expr, Expr::Return(_)) => Some(simple_expr(expr)),
        _ => None,
    }
}

fn callee_text_from_expr(expr: &Expr) -> String {
    match expr {
        Expr::Path(ExprPath { path, .. }) => path_to_string(path),
        other => other.to_token_stream().to_string(),
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn extract_path_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(ExprPath { path, .. }) => path.get_ident().map(|ident| ident.to_string()),
        Expr::Field(ExprField { base, .. }) => extract_path_name(base),
        _ => None,
    }
}

fn qualified_target_name(
    struct_field_names: &HashMap<String, Vec<String>>,
    target_var: &str,
    field: &str,
) -> String {
    for (key, fields) in struct_field_names {
        if (key.ends_with(&format!("::{}", target_var)) || key == target_var)
            && fields.iter().any(|f| f == field)
        {
            return format!("{}:{}", target_var, field);
        }
    }
    format!("{}:{}", target_var, field)
}

fn member_from_expr(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(ident) => ident.to_string(),
        syn::Member::Unnamed(index) => format!("field_{}", index.index),
    }
}

fn build_trait_impl_index(analyzed_files: &[AnalyzedFile]) -> TraitImplIndex {
    let mut trait_to_impl_methods: HashMap<String, Vec<String>> = HashMap::new();
    let mut method_to_impls: HashMap<String, Vec<String>> = HashMap::new();
    let mut blanket_method_to_impls: HashMap<String, Vec<String>> = HashMap::new();

    for file in analyzed_files {
        for record in &file.trait_impl_records {
            let trait_key = record.trait_name.clone();
            for (method_id, method_name) in record.method_ids.iter().zip(record.method_names.iter())
            {
                trait_to_impl_methods
                    .entry(trait_key.clone())
                    .or_default()
                    .push(method_id.clone());
                method_to_impls
                    .entry(last_segment(method_name).to_string())
                    .or_default()
                    .push(method_id.clone());
                method_to_impls
                    .entry(method_name.clone())
                    .or_default()
                    .push(method_id.clone());
                if record.is_blanket {
                    blanket_method_to_impls
                        .entry(last_segment(method_name).to_string())
                        .or_default()
                        .push(method_id.clone());
                }
            }
        }
    }

    TraitImplIndex {
        trait_to_impl_methods,
        method_to_impls,
        blanket_method_to_impls,
    }
}

fn build_call_graph(
    functions: &[FunctionRecord],
    trait_index: &TraitImplIndex,
    field_types: &HashMap<String, String>,
    local_types: &HashSet<String>,
    max_call_candidates: usize,
) -> CallGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut diagnostics = Vec::new();
    // Ambiguous call sites whose candidate list was truncated, reported once in
    // aggregate: one diagnostic per site would itself be tens of thousands of
    // records on a large workspace.
    let mut truncated_sites = 0usize;
    let mut truncated_candidates = 0usize;
    let local_index = build_local_function_index(functions);
    let return_types = ReturnTypeIndex::build(functions);
    let mut seen_nodes = HashSet::new();
    // Per-function receiver-type bindings cache (P1.2). Computed lazily inside
    // the loop because most functions never benefit (no method calls).
    let mut type_bindings_cache: HashMap<String, HashMap<String, String>> = HashMap::new();
    // Resolve a candidate's decl id back to its qualified name so edges carry
    // human-readable `target_name`s (not raw `decl-*` ids). Built once.
    let id_to_qualified: HashMap<&str, &str> = functions
        .iter()
        .map(|f| {
            (
                f.declaration.id.as_str(),
                f.declaration.qualified_name.as_str(),
            )
        })
        .collect();
    let context = ResolutionContext {
        local_index: &local_index,
        trait_index,
        id_to_qualified: &id_to_qualified,
        field_types,
        return_types: &return_types,
        local_types,
    };

    // Helper closures borrow `nodes`/`seen_nodes` mutably, so they live inline.
    for function in functions {
        if seen_nodes.insert(function.declaration.id.clone()) {
            nodes.push(CallGraphNode {
                id: function.declaration.id.clone(),
                name: function.declaration.name.clone(),
                qualified_name: function.declaration.qualified_name.clone(),
                canonical_name: rusi_schema::canonical_name(&function.declaration.qualified_name),
                kind: function.declaration.kind.clone(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                file_path: function.file_path.clone(),
                local: true,
                external: false,
                receiver: function.declaration.receiver.clone(),
                position: function.declaration.position.clone(),
            });
        }

        let bindings = type_bindings_cache
            .entry(function.declaration.id.clone())
            .or_insert_with(|| infer_type_bindings(function, field_types, &return_types));

        for call in &function.direct_calls {
            let candidates = resolve_call_targets(call, &function.package_path, &context, bindings);

            if candidates.is_empty() {
                // Truly external — preserve the legacy synthetic node + diagnostic
                // so consumers still see the call (e.g. for reachability matching).
                let synthetic_id = stable_id("cg-node", &["external", &call.callee_text]);
                if seen_nodes.insert(synthetic_id.clone()) {
                    nodes.push(CallGraphNode {
                        id: synthetic_id.clone(),
                        name: last_segment(&call.callee_text).to_string(),
                        qualified_name: call.callee_text.clone(),
                        canonical_name: rusi_schema::canonical_name(&call.callee_text),
                        kind: "external-function".to_string(),
                        package_path: inferred_package_path(&call.callee_text),
                        purl: String::new(),
                        file_path: String::new(),
                        local: false,
                        external: true,
                        receiver: None,
                        position: call.position.clone(),
                    });
                }
                diagnostics.push(Diagnostic {
                    kind: "resolution".to_string(),
                    message: format!("unresolved or external call target {}", call.callee_text),
                    package_path: Some(function.package_path.clone()),
                    file_path: Some(function.file_path.clone()),
                    position: Some(call.position.clone()),
                });
                edges.push(CallGraphEdge {
                    id: stable_id(
                        "cg-edge",
                        &[
                            &function.declaration.id,
                            &synthetic_id,
                            &call.position.line.to_string(),
                            &call.position.column.to_string(),
                            call.receiver_text.as_deref().unwrap_or_default(),
                        ],
                    ),
                    source_id: function.declaration.id.clone(),
                    target_id: synthetic_id,
                    call_type: CallProvenance::External.call_type().to_string(),
                    line: call.position.line,
                    column: call.position.column,
                    callee_text: Some(call.callee_text.clone()),
                    receiver: call.receiver_text.clone(),
                    method: call.method_name.clone(),
                    candidate_count: None,
                    emitted_candidate_count: None,
                    properties: IndexMap::new(),
                });
                continue;
            }

            // Over-approx path: emit one edge per candidate, capped for
            // ambiguous sites. The edge id is disambiguated by the candidate id
            // so duplicates don't collapse.
            let candidate_count = candidates.len();
            let emitted = truncate_candidates(
                &candidates,
                max_call_candidates,
                &function.declaration.qualified_name,
                &id_to_qualified,
            );
            let emitted_count = emitted.len();
            if emitted_count < candidate_count {
                truncated_sites += 1;
                truncated_candidates += candidate_count - emitted_count;
            }
            for candidate in emitted {
                edges.push(CallGraphEdge {
                    id: stable_id(
                        "cg-edge",
                        &[
                            &function.declaration.id,
                            &candidate.target_id,
                            &call.position.line.to_string(),
                            &call.position.column.to_string(),
                            // Every link of a method chain shares the chain's
                            // start position; the receiver text is what tells
                            // `a.f(..).f(..)`'s two calls apart.
                            call.receiver_text.as_deref().unwrap_or_default(),
                        ],
                    ),
                    source_id: function.declaration.id.clone(),
                    target_id: candidate.target_id.clone(),
                    call_type: candidate.provenance.call_type().to_string(),
                    line: call.position.line,
                    column: call.position.column,
                    callee_text: Some(call.callee_text.clone()),
                    receiver: call.receiver_text.clone(),
                    method: call.method_name.clone(),
                    candidate_count: (candidate_count > 1).then_some(candidate_count),
                    // Present only for a truncated site, so its presence marks
                    // the emitted edges as a sample.
                    emitted_candidate_count: (emitted_count < candidate_count)
                        .then_some(emitted_count),
                    properties: IndexMap::new(),
                });
            }
        }
    }

    if truncated_sites > 0 {
        diagnostics.push(Diagnostic {
            kind: "resolution".to_string(),
            message: format!(
                "{truncated_sites} ambiguous call sites were truncated to at most \
                 {max_call_candidates} candidate edges each, dropping {truncated_candidates} \
                 over-approximated edges; affected edges carry candidateCount and \
                 candidatesTruncated. Raise --max-call-candidates (0 disables the cap) to emit \
                 the full candidate set"
            ),
            package_path: None,
            file_path: None,
            position: None,
        });
    }

    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    // Collapse edges that are identical in every field. A repeated identical
    // edge carries no information, and some source shapes (a closure body
    // reachable by more than one traversal path) still emit one call twice.
    // Sorting by id first puts any duplicates adjacent.
    edges.dedup_by(|left, right| left == right);
    diagnostics.sort_by(|left, right| left.message.cmp(&right.message));

    CallGraph {
        mode: "static".to_string(),
        stats: GraphStats {
            node_count: nodes.len(),
            edge_count: edges.len(),
        },
        nodes,
        edges,
        diagnostics,
    }
}

/// Picks which candidates of an ambiguous call site to emit edges for.
///
/// Exactly-resolved sites (a single candidate, or any provenance other than the
/// over-approximating ones) are returned untouched: the cap exists to bound
/// guesswork, not to drop resolved calls. For an over-approximated site the
/// candidates are ordered most-plausible-first and truncated:
///
/// 1. targets in the caller's own crate before targets elsewhere — a bare
///    method name is far more likely to mean something in the same crate,
/// 2. then by qualified name, so the surviving sample is stable across runs and
///    independent of file iteration order.
///
/// The caller is identified by its own qualified name rather than its package
/// path, because qualified names are rooted at the crate (target) a file
/// belongs to: inside a `bin` or `example` target the package path is not a
/// prefix of any qualified name, and every candidate then ranked as "elsewhere".
fn truncate_candidates<'a>(
    candidates: &'a [ResolvedCall],
    max_call_candidates: usize,
    caller_qualified_name: &str,
    id_to_qualified: &HashMap<&str, &str>,
) -> Vec<&'a ResolvedCall> {
    let uncapped = max_call_candidates == 0 || candidates.len() <= max_call_candidates;
    let over_approximated = candidates.iter().any(|candidate| {
        matches!(
            candidate.provenance,
            CallProvenance::StaticOverapprox | CallProvenance::TraitOverapprox
        )
    });
    if uncapped || !over_approximated {
        return candidates.iter().collect();
    }

    let crate_prefix = format!(
        "{}::",
        caller_qualified_name
            .split("::")
            .next()
            .unwrap_or(caller_qualified_name)
    );
    let mut ordered: Vec<&ResolvedCall> = candidates.iter().collect();
    ordered.sort_by_cached_key(|candidate| {
        let qualified = id_to_qualified
            .get(candidate.target_id.as_str())
            .copied()
            .unwrap_or_default();
        // `false` sorts first, so same-crate candidates lead.
        let other_crate = !qualified.starts_with(&crate_prefix);
        (other_crate, qualified.to_string())
    });
    ordered.truncate(max_call_candidates);
    ordered
}

fn build_local_function_index(functions: &[FunctionRecord]) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    for function in functions {
        let qualified_name = function.declaration.qualified_name.clone();
        index
            .entry(qualified_name.clone())
            .or_default()
            .push(function.declaration.id.clone());
        index
            .entry(last_segment(&qualified_name).to_string())
            .or_default()
            .push(function.declaration.id.clone());
        if let Some(stripped) = qualified_name.strip_prefix(&(function.package_path.clone() + "::"))
        {
            index
                .entry(stripped.to_string())
                .or_default()
                .push(function.declaration.id.clone());
        }
    }
    index
}

fn resolve_call_target(
    callee: &str,
    package_path: &str,
    local_index: &HashMap<String, Vec<String>>,
    trait_index: Option<&TraitImplIndex>,
) -> Option<String> {
    let normalized = normalize_local_path(callee, package_path);
    if let Some(ids) = local_index.get(&normalized)
        && ids.len() == 1
    {
        return ids.first().cloned();
    }
    if let Some(ids) = local_index.get(callee)
        && ids.len() == 1
    {
        return ids.first().cloned();
    }
    if let Some(ids) = local_index.get(last_segment(callee))
        && ids.len() == 1
    {
        return ids.first().cloned();
    }
    if let Some(trait_index) = trait_index {
        let last = last_segment(callee);
        if let Some(impl_ids) = trait_index.method_to_impls.get(last)
            && impl_ids.len() == 1
        {
            return impl_ids.first().cloned();
        }
        if let Some(impl_ids) = trait_index.method_to_impls.get(callee)
            && impl_ids.len() == 1
        {
            return impl_ids.first().cloned();
        }
    }
    None
}

/// Resolution provenance for a single call-graph edge.
///
/// Every value except `External` represents a real local target the resolver
/// managed to anchor. `External` is reserved for the synthetic node emitted
/// by [`build_call_graph`] when *no* candidate is known — those edges keep
/// the legacy `external` call_type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallProvenance {
    /// Single fully-qualified or unique-name local match.
    Static,
    /// Multiple local candidates; emitted as a sound over-approximation
    /// (one edge per candidate) rather than dropping the callsite.
    StaticOverapprox,
    /// Single trait-impl match resolved through the trait index.
    TraitImpl,
    /// Multiple trait impls visible; emitted as a sound over-approximation
    /// (one edge per impl) instead of dropping the callsite.
    TraitOverapprox,
    /// Receiver-type-aware resolution: candidates were filtered by the
    /// statically-known receiver type inferred from local bindings.
    ReceiverTyped,
    /// Closure / higher-order edge (combinator -> closure body).
    #[allow(dead_code)]
    HigherOrder,
    /// No local candidate found; synthetic external node.
    External,
}

impl CallProvenance {
    fn call_type(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::StaticOverapprox => "static-overapprox",
            Self::TraitImpl => "trait-impl",
            Self::TraitOverapprox => "trait-overapprox",
            Self::ReceiverTyped => "receiver-typed",
            Self::HigherOrder => "higher-order",
            Self::External => "external",
        }
    }
}

/// A single resolved target for a callsite, tagged with how it was resolved.
#[derive(Debug, Clone)]
struct ResolvedCall {
    target_id: String,
    provenance: CallProvenance,
}

/// The workspace-wide indexes call resolution consults.
///
/// Grouped because they are always used together and always live as long as one
/// call-graph build: a resolver needs all of them to answer a single call site.
struct ResolutionContext<'a> {
    /// Function name (qualified, stripped, and bare) -> declaration ids.
    local_index: &'a HashMap<String, Vec<String>>,
    trait_index: &'a TraitImplIndex,
    /// Declaration id -> qualified name.
    id_to_qualified: &'a HashMap<&'a str, &'a str>,
    /// `"<TypeToken>::<field>" -> field's type token`.
    field_types: &'a HashMap<String, String>,
    return_types: &'a ReturnTypeIndex,
    /// Type names declared in the analyzed code. Membership is what lets a
    /// missing method be read as "this call leaves the analyzed code" rather
    /// than "we do not know".
    local_types: &'a HashSet<String>,
}

/// Receiver-type-aware multi-candidate resolver (P1.1 + P1.2 + P1.3).
///
/// Returns every local candidate the callsite could resolve to, tagged with
/// a provenance/confidence so downstream consumers can filter. The list is
/// non-empty only when at least one real local target exists; an empty
/// return tells [`build_call_graph`] to fall back to the synthetic external
/// node (we never silently drop a real local call to external).
///
/// Resolution order (sound-leaning: prefer exact, over-approximate when
/// ambiguous, filter by receiver type where the binding is known):
/// 1. Fully-qualified / normalized local match (single → Static,
///    multiple → StaticOverapprox — qualified keys rarely collide, but
///    two same-named items in different modules can both index under the
///    same normalized key when the qualifier was elided at the call site).
/// 2. Method call with a receiver (method_name present), in order:
///    - If receiver type is known and filters local same-name candidates to
///      one → ReceiverTyped.
///    - Single local same-name match → Static.
///    - Multiple local matches → StaticOverapprox.
///    - Trait dispatch via method_to_impls, with the same receiver-type
///      filter attempted first; one impl → TraitImpl, many →
///      TraitOverapprox.
/// 3. Free function with a bare-name collision (no method_name):
///    over-approximate via last-segment index.
fn resolve_call_targets(
    call: &SimplifiedCall,
    package_path: &str,
    context: &ResolutionContext<'_>,
    type_bindings: &HashMap<String, String>,
) -> Vec<ResolvedCall> {
    let ResolutionContext {
        local_index,
        trait_index,
        id_to_qualified,
        field_types,
        return_types,
        local_types,
    } = context;
    let callee = call.callee_text.as_str();
    let normalized = normalize_local_path(callee, package_path);

    // 0. Higher-order edge: combinator passed an inline closure. These
    //    resolve to exactly one local closure body, so we emit a single
    //    high-confidence edge tagged HigherOrder so consumers can filter.
    //    Run this first so the closure edge isn't routed through the
    //    generic over-approx path.
    if call.is_higher_order {
        if let Some(ids) = local_index.get(&normalized)
            && !ids.is_empty()
        {
            return resolutions(ids, CallProvenance::HigherOrder);
        }
        if callee.contains("::")
            && let Some(ids) = local_index.get(callee)
            && !ids.is_empty()
        {
            return resolutions(ids, CallProvenance::HigherOrder);
        }
        if let Some(ids) = local_index.get(callee)
            && !ids.is_empty()
        {
            return resolutions(ids, CallProvenance::HigherOrder);
        }
    }

    // 1. Fully-qualified / normalized match. Qualified keys only collide
    //    across modules with identical names; treat as StaticOverapprox
    //    in that rare case rather than silently picking one.
    if let Some(ids) = local_index.get(&normalized)
        && !ids.is_empty()
    {
        return match ids.len() {
            1 => resolutions(ids, CallProvenance::Static),
            _ => resolutions(ids, CallProvenance::StaticOverapprox),
        };
    }
    // An exact-text match only fires for fully-qualified callee strings
    // (since the index stores qualified_name entries). Bare names fall
    // through to the method_name / last-segment branches below so they get
    // the right over-approx semantics.
    if callee.contains("::")
        && let Some(ids) = local_index.get(callee)
        && !ids.is_empty()
    {
        return match ids.len() {
            1 => resolutions(ids, CallProvenance::Static),
            _ => resolutions(ids, CallProvenance::StaticOverapprox),
        };
    }

    // 2. Method call with a receiver — apply receiver-type inference.
    if let Some(method) = call.method_name.as_deref() {
        let local_candidates = local_index.get(method).cloned().unwrap_or_default();
        let trait_candidates = trait_index
            .method_to_impls
            .get(method)
            .cloned()
            .unwrap_or_default();

        // Try to filter by the receiver's inferred type. This is the
        // highest-leverage disambiguator we have without typeck.
        if let Some(receiver_type) = call.receiver_text.as_deref().and_then(|receiver| {
            resolve_receiver_type(
                receiver,
                call.receiver_expr.as_ref(),
                type_bindings,
                field_types,
                return_types,
            )
        }) {
            let receiver_type = &receiver_type;
            // Combine local + trait candidates so the filter sees every
            // possible impl of this method, regardless of where it lives.
            let mut combined: Vec<String> = local_candidates.clone();
            for id in &trait_candidates {
                if !combined.contains(id) {
                    combined.push(id.clone());
                }
            }
            if !combined.is_empty() {
                let filtered =
                    filter_by_receiver_type(&combined, id_to_qualified, receiver_type, method);
                if !filtered.is_empty() {
                    return resolutions(&filtered, CallProvenance::ReceiverTyped);
                }
            }

            // A `&dyn Trait` / `impl Trait` receiver reduces to the trait's
            // name, and such a call dispatches to that trait's impls — not to
            // an impl of a type called `Trait`.
            if let Some(trait_method_ids) = trait_index.trait_to_impl_methods.get(receiver_type) {
                let dispatched: Vec<String> = trait_candidates
                    .iter()
                    .filter(|id| trait_method_ids.contains(id))
                    .cloned()
                    .collect();
                match dispatched.len() {
                    0 => {}
                    1 => return resolutions(&dispatched, CallProvenance::TraitImpl),
                    _ => return resolutions(&dispatched, CallProvenance::TraitOverapprox),
                }
            }

            // A blanket impl (`impl<T> Ext for T`) applies to a receiver of any
            // type, so it stays a candidate whatever the receiver turned out to
            // be.
            let blanket_candidates = trait_index
                .blanket_method_to_impls
                .get(method)
                .cloned()
                .unwrap_or_default();
            if !blanket_candidates.is_empty() {
                return match blanket_candidates.len() {
                    1 => resolutions(&blanket_candidates, CallProvenance::TraitImpl),
                    _ => resolutions(&blanket_candidates, CallProvenance::TraitOverapprox),
                };
            }

            // Now the decisive question: do we *know* this receiver's type is a
            // concrete type with no local method of this name? Only two things
            // count as evidence. A locally declared type: we have seen all of
            // its impls, so if none carries the method, the call leaves the
            // analyzed code. Or a standard-library type, whose impls are never
            // local by definition.
            //
            // Over-approximating in those cases is not conservative, it is
            // wrong: `nodes.push(..)` on a `Vec` cannot reach a local
            // `Remap::push`, and claiming it can asserts a call the program
            // cannot make. That single fallback produced 19,592 `push` edges on
            // wasm-tools 1.247.0 — 14% of the whole graph — none of them real.
            //
            // Anything else (a generic parameter, a type alias, a foreign type
            // we have not modelled) is genuinely unknown, so those keep the
            // over-approximation below.
            if local_types.contains(receiver_type) || is_std_type(receiver_type) {
                return Vec::new();
            }
        }

        // The receiver's type is unknown, so every same-named candidate is
        // still possible. Emit one edge per candidate, preferring local statics
        // over trait impls when both exist (a local method is more likely the
        // intended target than a trait-method-family explosion).
        if local_candidates.len() == 1 {
            return resolutions(&local_candidates, CallProvenance::Static);
        }
        if !local_candidates.is_empty() {
            return resolutions(&local_candidates, CallProvenance::StaticOverapprox);
        }
        if trait_candidates.len() == 1 {
            return resolutions(&trait_candidates, CallProvenance::TraitImpl);
        }
        if !trait_candidates.is_empty() {
            return resolutions(&trait_candidates, CallProvenance::TraitOverapprox);
        }
        return Vec::new();
    }

    // 3. Free function with a bare-name collision (no method_name).
    //
    // Only for a callee written as a bare name. A qualified path that reached
    // this point failed both exact lookups above, which means it names something
    // outside this workspace — matching it on its last segment alone let
    // `std::process::Command::new` resolve to any local `new`, inventing an edge
    // to an unrelated type.
    if !callee.contains("::")
        && let Some(ids) = local_index.get(last_segment(callee))
        && !ids.is_empty()
    {
        return match ids.len() {
            1 => resolutions(ids, CallProvenance::Static),
            _ => resolutions(ids, CallProvenance::StaticOverapprox),
        };
    }
    if let Some(impl_ids) = trait_index.method_to_impls.get(callee)
        && !impl_ids.is_empty()
    {
        return match impl_ids.len() {
            1 => resolutions(impl_ids, CallProvenance::TraitImpl),
            _ => resolutions(impl_ids, CallProvenance::TraitOverapprox),
        };
    }

    Vec::new()
}

fn resolutions(ids: &[String], provenance: CallProvenance) -> Vec<ResolvedCall> {
    ids.iter()
        .map(|id| ResolvedCall {
            target_id: id.clone(),
            provenance,
        })
        .collect()
}

/// Methods that yield their receiver's type.
///
/// Typing a binding through them is what makes `connect()?.query(..)` and
/// `make().unwrap().run()` resolve. `?` itself is not represented — `syn`'s
/// `Expr::Try` is flattened to the inner call — which is the other half of why
/// return types are indexed already unwrapped.
const TYPE_PRESERVING_METHODS: &[&str] = &[
    "as_mut",
    "as_ref",
    "borrow",
    "borrow_mut",
    "clone",
    "to_owned",
];

/// Methods that yield their receiver's type *with one `Result`/`Option` layer
/// removed.
///
/// Kept apart from [`TYPE_PRESERVING_METHODS`] because the distinction matters
/// whenever the receiver is bound as the wrapper itself — a parameter or an
/// annotated `let` of type `Option<Client>`, where treating `x.unwrap()` as an
/// `Option` types the call site wrong and, since `Option` is a known std type,
/// then concludes the following call leaves the crate.
const UNWRAPPING_METHODS: &[&str] = &[
    "expect",
    "into_inner",
    "unwrap",
    "unwrap_or_default",
    "unwrap_or_else",
];

/// Standard-library constructors whose result type is worth knowing, since the
/// value they produce is often what a sink is called on.
///
/// The second element is the type produced *after* unwrapping any `Result` or
/// `Option`, matching how return types are indexed.
const STD_CONSTRUCTOR_RETURNS: &[(&str, &str)] = &[
    ("Command::new", "Command"),
    ("File::create", "File"),
    ("File::open", "File"),
    ("OsString::from", "OsString"),
    ("PathBuf::from", "PathBuf"),
    ("String::from", "String"),
    ("String::new", "String"),
    ("TcpListener::bind", "TcpListener"),
    ("TcpStream::connect", "TcpStream"),
    ("Vec::new", "Vec"),
    ("Vec::with_capacity", "Vec"),
];

/// Reduce a return type to the type a caller actually goes on to use.
///
/// A function returning `Result<Client, Error>` gives its caller a `Client`:
/// the wrapper is removed by `?` or `unwrap` before any method is called on the
/// value. Indexing the unwrapped type is what lets `let c = connect()?;` type
/// `c`, and costs nothing when the wrapper is kept, because `Result` and
/// `Option` are standard types whose own methods never resolve locally anyway.
/// Whether a type token is one of the wrappers [`unwrap_typing_wrapper`] peels.
fn is_typing_wrapper(token: &str) -> bool {
    matches!(last_segment_of_path(token), "Result" | "Option")
}

fn unwrap_typing_wrapper(return_type: &str) -> Option<String> {
    let trimmed = return_type.trim();
    let open = trimmed.find('<')?;
    if !trimmed.trim_end().ends_with('>') {
        return None;
    }
    let head = last_segment_of_path(&trimmed[..open]);
    if !matches!(head, "Result" | "Option") {
        return None;
    }
    let inner = &trimmed[open + 1..trimmed.trim_end().len() - 1];
    let first = split_generic_arguments(inner)
        .into_iter()
        .find(|argument| !argument.trim_start().starts_with('\''))?;
    // The inner type may itself be wrapped (`Result<Option<T>, E>`).
    unwrap_typing_wrapper(first).or_else(|| bare_type_token(first))
}

/// Return types of the workspace's own functions, for propagating a type
/// through `let x = f()` and through a method chain.
///
/// A key is dropped when candidates disagree: guessing between two same-named
/// functions with different return types would type a binding wrongly, which is
/// worse than leaving it unknown.
#[derive(Debug, Default)]
struct ReturnTypeIndex {
    /// `(receiver type token, method name) -> return type token`.
    by_type_method: HashMap<(String, String), String>,
    /// Free function, by bare name.
    by_name: HashMap<String, String>,
    /// Free function, by qualified name.
    by_qualified: HashMap<String, String>,
}

impl ReturnTypeIndex {
    fn build(functions: &[FunctionRecord]) -> Self {
        let mut index = Self::default();
        // Keys seen with conflicting return types, tracked so a later agreeing
        // entry cannot resurrect them.
        let mut poisoned_type_method: HashSet<(String, String)> = HashSet::new();
        let mut poisoned_name: HashSet<String> = HashSet::new();

        for function in functions {
            let Some(returns) = unwrap_typing_wrapper(&function.return_type)
                .or_else(|| bare_type_token(&function.return_type))
            else {
                continue;
            };
            let name = function.declaration.name.clone();
            match function
                .receiver_type
                .as_deref()
                .and_then(bare_type_token)
                .filter(|token| token != "Self")
            {
                Some(receiver) => {
                    let key = (receiver, name);
                    if poisoned_type_method.contains(&key) {
                        continue;
                    }
                    match index.by_type_method.get(&key) {
                        Some(existing) if existing != &returns => {
                            index.by_type_method.remove(&key);
                            poisoned_type_method.insert(key);
                        }
                        Some(_) => {}
                        None => {
                            index.by_type_method.insert(key, returns);
                        }
                    }
                }
                None => {
                    index
                        .by_qualified
                        .insert(function.declaration.qualified_name.clone(), returns.clone());
                    if poisoned_name.contains(&name) {
                        continue;
                    }
                    match index.by_name.get(&name) {
                        Some(existing) if existing != &returns => {
                            index.by_name.remove(&name);
                            poisoned_name.insert(name);
                        }
                        Some(_) => {}
                        None => {
                            index.by_name.insert(name, returns);
                        }
                    }
                }
            }
        }
        index
    }

    fn free_function(&self, callee: &str) -> Option<&str> {
        self.by_qualified
            .get(callee)
            .or_else(|| self.by_name.get(last_segment(callee)))
            .map(String::as_str)
    }

    fn method(&self, receiver_type: &str, method: &str) -> Option<&str> {
        self.by_type_method
            .get(&(receiver_type.to_string(), method.to_string()))
            .map(String::as_str)
    }
}

/// Infers the type of a simplified expression.
///
/// This is the structural counterpart to the name-keyed bindings: it follows
/// field accesses, references, constructor calls, local function returns, and
/// method-call returns, which is what types the receiver of a chained call.
fn infer_expr_type(
    expr: &SimpleExpr,
    bindings: &HashMap<String, String>,
    field_types: &HashMap<String, String>,
    return_types: &ReturnTypeIndex,
) -> Option<String> {
    match expr {
        SimpleExpr::Var(name) => bindings
            .get(name.as_str())
            .cloned()
            // A bare capitalized path is a type, not a binding (`Config::load`
            // arrives here as `Config`).
            .or_else(|| bare_type_token(name)),
        SimpleExpr::Reference { expr, .. } => {
            infer_expr_type(expr, bindings, field_types, return_types)
        }
        SimpleExpr::Field { base, field } => {
            let base_type = infer_expr_type(base, bindings, field_types, return_types)?;
            field_types.get(&format!("{base_type}::{field}")).cloned()
        }
        SimpleExpr::Call { callee, .. } => std_constructor_return(callee)
            .map(str::to_string)
            .or_else(|| constructor_type(callee))
            .or_else(|| return_types.free_function(callee).map(str::to_string)),
        SimpleExpr::MethodCall {
            receiver, method, ..
        } => {
            let receiver_type = infer_expr_type(receiver, bindings, field_types, return_types)?;
            // A pass-through method hands back what it was called on, so the
            // receiver's type carries through the call.
            let method_name = last_segment(method);
            if TYPE_PRESERVING_METHODS.contains(&method_name) {
                return Some(receiver_type);
            }
            // Unwrapping peels one `Result`/`Option` layer.
            if UNWRAPPING_METHODS.contains(&method_name) {
                return match unwrap_typing_wrapper(&receiver_type) {
                    Some(inner) => Some(inner),
                    // The receiver is a bare `Option`/`Result` token: it was
                    // bound from a type whose argument the binding table does
                    // not keep, so the unwrapped type is genuinely unknown.
                    // Reporting the wrapper instead would name a std type and
                    // so conclude — wrongly — that the next call leaves the
                    // crate; unknown over-approximates instead.
                    None if is_typing_wrapper(&receiver_type) => None,
                    // Anything else is already unwrapped (return types are
                    // indexed that way) and carries through.
                    None => Some(receiver_type),
                };
            }
            return_types
                .method(&receiver_type, method)
                .map(str::to_string)
        }
        SimpleExpr::Compose(_) | SimpleExpr::Literal | SimpleExpr::Unknown => None,
    }
}

/// Type of the expression a method is called on.
///
/// Handles the two shapes the collector produces as plain token text: a bare
/// binding (`store`, `self`) and a field access chain (`self . sink`,
/// `self . inner . cache`). A chain walks the field table one hop at a time, so
/// it resolves only while every hop's owning type is known.
fn resolve_receiver_type(
    receiver: &str,
    receiver_expr: Option<&SimpleExpr>,
    type_bindings: &HashMap<String, String>,
    field_types: &HashMap<String, String>,
    return_types: &ReturnTypeIndex,
) -> Option<String> {
    // The structured form can express a call result, which the text form
    // cannot, so it is tried first.
    if let Some(expr) = receiver_expr
        && let Some(inferred) = infer_expr_type(expr, type_bindings, field_types, return_types)
    {
        return Some(inferred);
    }
    let receiver = receiver.trim();
    if let Some(direct) = type_bindings.get(receiver) {
        return Some(direct.clone());
    }
    // Only a pure dotted path of identifiers can be walked; anything with a
    // call, index, or operator in it is out of scope here.
    let mut hops = receiver.split('.').map(str::trim);
    let base = hops.next()?;
    if base.is_empty() {
        return None;
    }
    let mut current = type_bindings.get(base)?.clone();
    for field in hops {
        if field.is_empty() || !field.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        current = field_types.get(&format!("{current}::{field}"))?.clone();
    }
    Some(current)
}

/// Keeps the candidates whose declaring type matches the receiver's type.
///
/// The id -> qualified-name lookup is passed in rather than searched for. It
/// used to be recovered by scanning the whole local function index per
/// candidate, which made call-graph construction quadratic in the workspace
/// size: on wasm-tools 1.247.0 that single scan was 24 of the 28 seconds a full
/// run took.
fn filter_by_receiver_type(
    candidates: &[String],
    id_to_qualified: &HashMap<&str, &str>,
    receiver_type: &str,
    method: &str,
) -> Vec<String> {
    let target_token = last_segment(receiver_type);
    let mut kept: Vec<String> = Vec::new();
    for id in candidates {
        if let Some(qname) = id_to_qualified.get(id.as_str())
            && type_qualified_name_matches(qname, target_token, method)
        {
            kept.push(id.clone());
        }
    }
    kept
}

fn type_qualified_name_matches(qname: &str, type_token: &str, method: &str) -> bool {
    // Compare generic-free segments: a method on a generic type is qualified
    // `Expander<'a>::expand`, and matching that raw against the receiver token
    // `Expander` failed, which sent every `self.method()` on a generic type
    // back to over-approximation.
    if !split_qualified_segments(qname).any(|segment| segment == type_token) {
        return false;
    }
    last_segment(qname) == method
}

/// Split a qualified name on `::` that sit outside generic arguments, yielding
/// each segment with its generic arguments and lifetimes removed.
fn split_qualified_segments(qname: &str) -> impl Iterator<Item = &str> {
    let mut segments = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = qname.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && qname[index..].starts_with("::") => {
                segments.push(&qname[start..index]);
                index += 2;
                start = index;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    segments.push(&qname[start..]);
    segments
        .into_iter()
        .map(|segment| match segment.find('<') {
            Some(open) => segment[..open].trim(),
            None => segment.trim(),
        })
        .filter(|segment| !segment.is_empty())
}

/// Best-effort, function-local receiver-type inference (P1.2).
///
/// Walks the function's operations looking for the small set of patterns
/// that unambiguously reveal a variable's type without running typeck:
/// * `let x: T = ...;`                → x:T
/// * `let x = T::new(...);`           → x:T   (T capitalized, simple ident)
/// * `let x = path::Type::new(...);`  → x:Type
/// * `let mut x = ...;` parameters    → x:param_type
///
/// Plus the function's parameter types seed bindings for `&self`/params.
///
/// Returned map keys are variable names (identifiers, not field accesses),
/// values are bare type tokens (e.g. `FileStore`, `Config`) suitable for the
/// resolver's path-segment match in [`filter_by_receiver_type`].
fn infer_type_bindings(
    function: &FunctionRecord,
    field_types: &HashMap<String, String>,
    return_types: &ReturnTypeIndex,
) -> HashMap<String, String> {
    let mut bindings = HashMap::new();

    // `self` is the impl's own type, known exactly. Without this, every
    // `self.method()` inside an impl fell back to over-approximation even
    // though its receiver type was never in doubt.
    let self_type = function
        .receiver_type
        .as_deref()
        .and_then(bare_type_token)
        .filter(|token| token != "Self");

    // Parameters: name -> declared type (last segment, stripped of & / mut).
    for (name, ty) in function.params.iter().zip(function.param_types.iter()) {
        if name.is_empty() || ty.is_empty() {
            continue;
        }
        // The receiver parameter's type renders as `Self`, which would shadow
        // the impl type resolved above with a token that matches no impl.
        if name == "self" {
            continue;
        }
        if let Some(token) = bare_type_token(ty) {
            // A parameter written `Self` means the impl type.
            let token = match (token.as_str(), self_type.as_deref()) {
                ("Self", Some(self_type)) => self_type.to_string(),
                _ => token,
            };
            bindings.insert(name.clone(), token);
        }
    }

    if let Some(self_type) = self_type {
        bindings.insert("self".to_string(), self_type);
    }

    // An explicit annotation outranks every inference above it.
    for (name, declared) in &function.declared_types {
        bindings.insert(name.clone(), declared.clone());
    }

    // Walk assignments to harvest `let x: T = ...`, `let x = T::new(...)`, and
    // — via the return-type index — `let x = f()` and `let x = a.b().c()`.
    //
    // Repeated because a binding can depend on an earlier one that is itself
    // inferred (`let a = make(); let b = a.next();`), and the operations are in
    // source order but a type can also flow backwards through a later
    // reassignment. Three passes settle every chain we can type at all; a
    // longer chain gains nothing from more passes because each pass resolves at
    // least one more hop.
    for _ in 0..3 {
        let mut changed = false;
        for op in &function.operations {
            let Operation::Assign { target, value } = op else {
                continue;
            };
            let Some(var) = bare_ident(target) else {
                continue;
            };
            let inferred = binding_from_simple_expr(target, value)
                .map(|(_, ty)| ty)
                .or_else(|| infer_expr_type(value, &bindings, field_types, return_types));
            if let Some(ty) = inferred
                && bindings.get(&var) != Some(&ty)
            {
                bindings.insert(var, ty);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    bindings
}

fn binding_from_simple_expr(target: &str, value: &SimpleExpr) -> Option<(String, String)> {
    let var = bare_ident(target)?;
    match value {
        SimpleExpr::Call { callee, .. } => {
            // T::new(...) or path::Type::new(...) — type is the segment before
            // the final `::new`-style constructor.
            if let Some(ty) = constructor_type(callee) {
                return Some((var, ty));
            }
            None
        }
        SimpleExpr::Var(name) => {
            // `let x = y;` propagates y's type if it's a simple type-ident
            // that looks like a capitalized type.
            if let Some(token) = bare_type_token(name) {
                return Some((var, token));
            }
            None
        }
        _ => None,
    }
}

fn bare_ident(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.chars().next()?;
    if !first.is_alphabetic() && first != '_' {
        return None;
    }
    // Reject `x.y` / `x[0]` / `&x` — only plain identifiers count as bindings.
    if trimmed.chars().any(|c| !(c.is_alphanumeric() || c == '_')) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Wrappers a method call sees through by `Deref` coercion.
///
/// `arc.method()` can mean `Arc::method` or, far more often, a method of the
/// pointee, so resolving the receiver type has to look inside these. Containers
/// with methods of their own (`Vec`, `Option`, `HashMap`, ...) are deliberately
/// absent: `vec.push(..)` means `Vec::push`, not a method of the element type.
const DEREF_TRANSPARENT_WRAPPERS: &[&str] = &[
    "Arc",
    "Box",
    "Cow",
    "MappedMutexGuard",
    "MappedRwLockReadGuard",
    "MappedRwLockWriteGuard",
    "MutexGuard",
    "Pin",
    "Rc",
    "Ref",
    "RefMut",
    "RwLockReadGuard",
    "RwLockWriteGuard",
];

/// Standard-library and core types rusi models by name.
///
/// Used as positive evidence that a receiver's impls are *not* local: a method
/// call on a `Vec` cannot land on a local `push`. The list only needs the types
/// that commonly receive method calls; anything absent simply stays unknown,
/// which is the conservative direction.
const KNOWN_STD_TYPES: &[&str] = &[
    "Arc",
    "BTreeMap",
    "BTreeSet",
    "BinaryHeap",
    "Box",
    "Cell",
    "Command",
    "Cow",
    "Duration",
    "File",
    "HashMap",
    "HashSet",
    "Instant",
    "IpAddr",
    "Mutex",
    "OsStr",
    "OsString",
    "Option",
    "Path",
    "PathBuf",
    "RefCell",
    "Result",
    "Rc",
    "RwLock",
    "SocketAddr",
    "String",
    "TcpListener",
    "TcpStream",
    "Vec",
    "VecDeque",
    "str",
];

/// Whether `token` names a type from the standard library.
fn is_std_type(token: &str) -> bool {
    KNOWN_STD_TYPES.contains(&token)
}

/// The type a known standard-library constructor produces, already unwrapped.
fn std_constructor_return(callee: &str) -> Option<&'static str> {
    // Match on the last two path segments so `std::fs::File::open` and `File::open`
    // both hit.
    let segments: Vec<&str> = callee.rsplit("::").take(2).collect();
    if segments.len() < 2 {
        return None;
    }
    let suffix = format!("{}::{}", segments[1], segments[0]);
    STD_CONSTRUCTOR_RETURNS
        .iter()
        .find(|(pattern, _)| *pattern == suffix)
        .map(|(_, returns)| *returns)
}

/// Reduce a type as written to the bare type token a method call dispatches on.
///
/// Strips references and `mut`, then peels `Deref`-transparent wrappers so
/// `&mut Arc<db::Client>` resolves to `Client`. Returns `None` for primitives
/// and anything that does not look like a user-defined type; the resolver only
/// uses this to disambiguate between same-named methods.
fn bare_type_token(ty: &str) -> Option<String> {
    let mut current = ty.trim();
    loop {
        // Peel references, `mut`, `dyn`, and `impl` markers.
        let peeled = current
            .trim()
            .trim_start_matches('&')
            .trim()
            .strip_prefix("mut ")
            .unwrap_or_else(|| {
                current
                    .trim()
                    .trim_start_matches('&')
                    .trim()
                    .strip_prefix("dyn ")
                    .or_else(|| {
                        current
                            .trim()
                            .trim_start_matches('&')
                            .trim()
                            .strip_prefix("impl ")
                    })
                    .unwrap_or_else(|| current.trim().trim_start_matches('&').trim())
            })
            .trim();
        if peeled == current {
            break;
        }
        current = peeled;
    }

    // A generic application: decide whether to look inside it.
    if let Some(open) = current.find('<')
        && current.trim_end().ends_with('>')
    {
        let head = last_segment_of_path(&current[..open]);
        if DEREF_TRANSPARENT_WRAPPERS.contains(&head) {
            let inner = &current[open + 1..current.trim_end().len() - 1];
            // `Cow<'a, T>` and `Pin<Box<T>>`: the pointee is the last argument
            // that is not a lifetime.
            let argument = split_generic_arguments(inner)
                .into_iter()
                .rev()
                .find(|argument| !argument.trim_start().starts_with('\''))?;
            return bare_type_token(argument);
        }
        current = &current[..open];
    }

    let last = last_segment_of_path(current);
    let first = last.chars().next()?;
    // Capitalized = conventionally a type name. This intentionally misses
    // primitive types (lowercase) — we only need it to disambiguate
    // user-defined types in method dispatch.
    if first.is_uppercase() && last.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(last.to_string())
    } else {
        None
    }
}

/// Last `::` segment of a path, ignoring whitespace the token stream inserts.
fn last_segment_of_path(path: &str) -> &str {
    path.trim()
        .rsplit("::")
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches(|c: char| c == '>' || c.is_whitespace())
        .trim()
}

/// Split generic arguments on top-level commas.
fn split_generic_arguments(inner: &str) -> Vec<&str> {
    let mut arguments = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (index, ch) in inner.char_indices() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                arguments.push(&inner[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    arguments.push(&inner[start..]);
    arguments
}

fn constructor_type(callee: &str) -> Option<String> {
    let parts: Vec<&str> = callee.split("::").collect();
    if parts.len() < 2 {
        return None;
    }
    let final_seg = parts.last().copied()?;
    // Convention: `new`, `default`, `from`, `with_` are constructors.
    let is_constructor = matches!(
        final_seg,
        "new" | "default" | "from" | "with_capacity" | "with_rows"
    );
    if !is_constructor {
        return None;
    }
    // Type is the segment immediately before the constructor.
    let candidate = parts[parts.len() - 2];
    bare_type_token(candidate)
}

fn normalize_local_path(callee: &str, package_path: &str) -> String {
    if callee.starts_with("crate::") {
        format!("{}::{}", package_path, callee.trim_start_matches("crate::"))
    } else if callee.contains("::") {
        if callee.starts_with(package_path) {
            callee.to_string()
        } else {
            format!("{package_path}::{callee}")
        }
    } else {
        format!("{package_path}::{callee}")
    }
}

fn last_segment(value: &str) -> &str {
    value.rsplit("::").next().unwrap_or(value)
}

fn inferred_package_path(callee: &str) -> String {
    if callee.contains("::") {
        callee.split("::").next().unwrap_or(callee).to_string()
    } else {
        String::new()
    }
}

fn build_data_flow(
    mode: &str,
    functions: &[FunctionRecord],
    patterns: DataFlowPatternSet,
    field_types: &HashMap<String, String>,
) -> DataFlowEvidence {
    // Body-less records (a dependency at the lighter tier) are excluded: their
    // empty operation lists would summarize as "taint stops here" and delete
    // real flows through them. A call to one stays unresolved for data-flow
    // purposes, which is the conservative reading.
    let functions: Vec<FunctionRecord> = functions
        .iter()
        .filter(|function| function.has_body)
        .cloned()
        .collect();
    let functions = functions.as_slice();
    let local_index = build_local_function_index(functions);
    let function_map: HashMap<String, &FunctionRecord> = functions
        .iter()
        .map(|function| (function.declaration.id.clone(), function))
        .collect();
    let return_types = ReturnTypeIndex::build(functions);
    let summaries = infer_summaries(
        functions,
        &local_index,
        &patterns,
        field_types,
        &return_types,
    );
    let partials = parallel_map_collect(functions, |function| {
        let mut builder = DataFlowBuilder::new(
            mode,
            &patterns,
            &summaries,
            &local_index,
            &function_map,
            field_types,
            &return_types,
        );
        builder.materialize_function(function);
        builder
    });
    let mut builder = DataFlowBuilder::new(
        mode,
        &patterns,
        &summaries,
        &local_index,
        &function_map,
        field_types,
        &return_types,
    );
    for partial in partials {
        builder.merge_materialized(partial);
    }
    builder.finish()
}

/// Built-in packs focused on stable-Rust APIs that are both common and
/// semantically meaningful for review-oriented slicing.
pub fn built_in_dataflow_patterns() -> DataFlowPatternSet {
    DataFlowPatternSet {
        sources: vec![
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::var".to_string(),
                category: "env".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::var_os".to_string(),
                category: "env".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::var".to_string(),
                category: "env".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::args".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::args".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::args_os".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::args_os".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::fs::read_to_string".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "fs::read_to_string".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::fs::read".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "fs::read".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::io::stdin".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "stdin".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
                receiver_type: None,
            },
        ],
        sinks: vec![
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::process::Command::new".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Command::new".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            // Receiver-typed sinks. `Command::new(x)` was already a sink, but
            // `Command::new("sh").arg(tainted)` — the more common injection
            // shape — was not, because the tainted value never reaches the
            // constructor. Matching on the bare method name alone would fire on
            // every builder in the workspace that happens to have an `arg`, so
            // these are restricted to the receiver's resolved type. Argument 0
            // of a method call is the receiver, so the first real argument is 1.
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "arg".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![1],
                receiver_type: Some("Command".to_string()),
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "args".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![1],
                receiver_type: Some("Command".to_string()),
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "env".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![1, 2],
                receiver_type: Some("Command".to_string()),
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "write_all".to_string(),
                category: "filesystem-write".to_string(),
                relevant_arguments: vec![1],
                receiver_type: Some("File".to_string()),
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "write_all".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: Some("TcpStream".to_string()),
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::fs::write".to_string(),
                category: "filesystem-write".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fs::write".to_string(),
                category: "filesystem-write".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::fs::remove_file".to_string(),
                category: "filesystem-delete".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fs::remove_file".to_string(),
                category: "filesystem-delete".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::net::TcpStream::connect".to_string(),
                category: "network-connect".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "TcpStream::connect".to_string(),
                category: "network-connect".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_one".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_all".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_optional".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "load".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "load_iter".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get_result".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get_results".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "first".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_one".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_opt".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_map".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_row".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_and_then".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_drop".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_first".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_iter".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "simple_query".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "batch_execute".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute_batch".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute_unprepared".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "prepare".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "prepare_cached".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "exec".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "exec_drop".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "reqwest::blocking::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "reqwest::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "put".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "patch".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "delete".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "request".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![2],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "send".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "surf::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "surf::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "ureq::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "ureq::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "isahc::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "isahc::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "hyper::Client::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "hyper::Client::request".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "format!#html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Response::with".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "warp::reply::html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "HttpResponse::body".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Response::body".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "RawHtml".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
        ],
        passthroughs: vec![
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "Ok".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "Some".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or_else".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or_default".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "expect".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "nth".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "next".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "map".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "and_then".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_string".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_owned".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_owned".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "clone".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_inner".to_string(),
                category: "extractor-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_str".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_ref".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "query".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "path".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "uri".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "param".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "query_string".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "match_info".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "format!".to_string(),
                category: "string-format".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "format!#html".to_string(),
                category: "string-format".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "CString::new".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query_as".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query_scalar".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "diesel::dsl::sql_query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sql_query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sea_orm::Statement::from_sql_and_values".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sea_query::Query::from_string".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "std::ffi::CString::new".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_ptr".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "deref".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_raw".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "offset".to_string(),
                category: "pointer-arithmetic".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "add".to_string(),
                category: "pointer-arithmetic".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sub".to_string(),
                category: "pointer-arithmetic".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "wrapping_add".to_string(),
                category: "pointer-arithmetic".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "wrapping_offset".to_string(),
                category: "pointer-arithmetic".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "lock".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "borrow".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "borrow_mut".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "get_mut".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "read".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "write".to_string(),
                category: "lock-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "Arc::new".to_string(),
                category: "smart-pointer".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "Rc::new".to_string(),
                category: "smart-pointer".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "Mutex::new".to_string(),
                category: "smart-pointer".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "RefCell::new".to_string(),
                category: "smart-pointer".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "send".to_string(),
                category: "channel-io".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "recv".to_string(),
                category: "channel-io".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_bytes".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_os_str".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_string_lossy".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "encode_b64".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "url".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_token_stream".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "collect".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "filter".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "fold".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0, 1],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "flat_map".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_lowercase".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_uppercase".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_ascii_lowercase".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_ascii_uppercase".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            // Standard-library text and container methods that hand their
            // receiver's data back out. Omitting one is not a missed
            // convenience: taint stops dead at the call, so every sink
            // downstream of it goes unreported. Kept in step with the
            // standard library for that reason.
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "split_once".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "rsplit_once".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "splitn".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "rsplitn".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "split".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "rsplit".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "split_terminator".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "split_whitespace".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "lines".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "chars".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "bytes".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "strip_prefix".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "strip_suffix".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "strip_circumfix".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_start".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_end".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_matches".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_start_matches".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_end_matches".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_ascii".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_ascii_start".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim_ascii_end".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "replace".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "replacen".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "repeat".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "escape_debug".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "escape_default".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "join".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "concat".to_string(),
                category: "string-transform".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_str".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_string".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_bytes".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_vec".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_vec".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_path_buf".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_os_string".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_path".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_slice".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_mut_slice".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_deref".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_deref_mut".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_encoded_bytes".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_boxed_str".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "leak".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "get".to_string(),
                category: "collection-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "first".to_string(),
                category: "collection-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "last".to_string(),
                category: "collection-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "iter".to_string(),
                category: "collection-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_iter".to_string(),
                category: "collection-accessor".to_string(),
                relevant_arguments: vec![0],
                receiver_type: None,
            },
        ],
    }
}

fn infer_summaries(
    functions: &[FunctionRecord],
    local_index: &HashMap<String, Vec<String>>,
    patterns: &DataFlowPatternSet,
    field_types: &HashMap<String, String>,
    return_types: &ReturnTypeIndex,
) -> BTreeMap<String, FunctionSummary> {
    let mut summaries = BTreeMap::<String, FunctionSummary>::new();
    for function in functions {
        summaries.insert(function.declaration.id.clone(), FunctionSummary::default());
    }

    let mut dirty: HashSet<String> = functions.iter().map(|f| f.declaration.id.clone()).collect();
    let mut callee_map: HashMap<String, Vec<String>> = HashMap::new();
    for function in functions {
        for call in &function.direct_calls {
            if let Some(resolved) =
                resolve_call_target(&call.callee_text, &function.package_path, local_index, None)
            {
                callee_map
                    .entry(resolved.clone())
                    .or_default()
                    .push(function.declaration.id.clone());
            }
        }
    }

    for _ in 0..6 {
        if dirty.is_empty() {
            break;
        }
        let current_dirty: Vec<String> = dirty.drain().collect();
        let funcs_to_update: Vec<&FunctionRecord> = functions
            .iter()
            .filter(|f| current_dirty.contains(&f.declaration.id))
            .collect();
        let next_entries = parallel_map_collect(&funcs_to_update, |function| {
            (
                function.declaration.id.clone(),
                summarize_function(
                    function,
                    &summaries,
                    local_index,
                    patterns,
                    field_types,
                    return_types,
                ),
            )
        });
        for (function_id, next) in next_entries {
            let entry = summaries.entry(function_id.clone()).or_default();
            if *entry != next {
                *entry = next;
                if let Some(callers) = callee_map.get(&function_id) {
                    for caller in callers {
                        dirty.insert(caller.clone());
                    }
                }
            }
        }
    }
    summaries
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractOrigin {
    Param(usize),
    Source(String),
}

fn summarize_function(
    function: &FunctionRecord,
    summaries: &BTreeMap<String, FunctionSummary>,
    local_index: &HashMap<String, Vec<String>>,
    patterns: &DataFlowPatternSet,
    field_types: &HashMap<String, String>,
    return_types: &ReturnTypeIndex,
) -> FunctionSummary {
    // Same type bindings the concrete pass uses, so a receiver-typed sink
    // pattern (`Command::arg`) is visible here too. Without them a wrapper
    // function whose whole body is `cmd.arg(value)` summarized as reaching no
    // sink, and taint flowing into it through a parameter was lost.
    let type_bindings = infer_type_bindings(function, field_types, return_types);
    let mut env: HashMap<String, BTreeSet<AbstractOrigin>> = HashMap::new();
    for (idx, param) in function.params.iter().enumerate() {
        let mut origins = BTreeSet::from([AbstractOrigin::Param(idx)]);
        if let Some(category) = function.param_source_categories.get(&idx) {
            origins.insert(AbstractOrigin::Source(category.clone()));
        }
        env.insert(param.clone(), origins);
    }

    let mut summary = FunctionSummary::default();
    for operation in &function.operations {
        match operation {
            Operation::Assign { target, value } => {
                let value_taint = eval_abstract_expr(
                    value,
                    &env,
                    summaries,
                    &function.package_path,
                    local_index,
                    patterns,
                );
                env.insert(target.clone(), value_taint);
            }
            Operation::AssignField {
                target,
                field,
                value,
            } => {
                let value_taint = eval_abstract_expr(
                    value,
                    &env,
                    summaries,
                    &function.package_path,
                    local_index,
                    patterns,
                );
                let key = format!("{}.{}", target, field);
                env.insert(key, value_taint);
            }
            Operation::LoopBody(loop_ops) => {
                let mut loop_env = env.clone();
                for _iter in 0..3 {
                    let mut changed = false;
                    for op in loop_ops {
                        match op {
                            Operation::Assign { target, value } => {
                                let value_taint = eval_abstract_expr(
                                    value,
                                    &loop_env,
                                    summaries,
                                    &function.package_path,
                                    local_index,
                                    patterns,
                                );
                                if loop_env.get(target) != Some(&value_taint) {
                                    changed = true;
                                }
                                loop_env.insert(target.clone(), value_taint);
                            }
                            Operation::AssignField {
                                target,
                                field,
                                value,
                            } => {
                                let value_taint = eval_abstract_expr(
                                    value,
                                    &loop_env,
                                    summaries,
                                    &function.package_path,
                                    local_index,
                                    patterns,
                                );
                                let key = format!("{}.{}", target, field);
                                loop_env.insert(key, value_taint);
                            }
                            _ => {}
                        }
                    }
                    if !changed {
                        break;
                    }
                }
                for (key, taint) in loop_env {
                    if key.starts_with(&format!("{}.", "")) || !key.contains('.') {
                        env.entry(key).or_insert(taint);
                    }
                }
            }
            Operation::Expr(expr) | Operation::Return(expr) => {
                let value_taint = eval_abstract_expr(
                    expr,
                    &env,
                    summaries,
                    &function.package_path,
                    local_index,
                    patterns,
                );
                if matches!(operation, Operation::Return(_)) {
                    for origin in &value_taint {
                        match origin {
                            AbstractOrigin::Param(index) => {
                                summary.param_to_return.insert(*index);
                            }
                            AbstractOrigin::Source(category) => {
                                summary.returns_source_categories.insert(category.clone());
                            }
                        }
                    }
                }
                // A method call is a sink candidate too. Its receiver is
                // argument 0, matching how the concrete pass and the pattern
                // set's `relevant_arguments` index them.
                let call_parts = match expr {
                    SimpleExpr::Call { callee, args, .. } => {
                        Some((callee.clone(), args.clone(), None))
                    }
                    SimpleExpr::MethodCall {
                        method,
                        receiver,
                        args,
                        ..
                    } => {
                        let all_args = std::iter::once(receiver.as_ref())
                            .chain(args.iter())
                            .cloned()
                            .collect::<Vec<_>>();
                        let receiver_type =
                            infer_expr_type(receiver, &type_bindings, field_types, return_types);
                        Some((method.clone(), all_args, receiver_type))
                    }
                    _ => None,
                };
                if let Some((callee, args, receiver_type)) = call_parts {
                    let callee = &callee;
                    let args = args.as_slice();
                    if let Some(sink_match) =
                        find_sink_pattern(callee, args, receiver_type.as_deref(), &patterns.sinks)
                    {
                        for index in &sink_match.relevant_arguments {
                            if let Some(arg) = args.get(*index) {
                                let arg_taint = eval_abstract_expr(
                                    arg,
                                    &env,
                                    summaries,
                                    &function.package_path,
                                    local_index,
                                    patterns,
                                );
                                for origin in arg_taint {
                                    if let AbstractOrigin::Param(param_index) = origin {
                                        summary
                                            .param_to_sink
                                            .entry(sink_match.category.clone())
                                            .or_default()
                                            .insert(param_index);
                                    }
                                }
                            }
                        }
                    }

                    // Free calls only: a method's parameter indexes are shifted
                    // by the receiver, and resolving a bare method name here
                    // would propagate through any same-named function.
                    if matches!(expr, SimpleExpr::Call { .. })
                        && let Some(resolved) =
                            resolve_call_target(callee, &function.package_path, local_index, None)
                        && let Some(callee_summary) = summaries.get(&resolved).cloned()
                    {
                        for (sink_category, parameter_indexes) in callee_summary.param_to_sink {
                            for parameter_index in parameter_indexes {
                                if let Some(arg) = args.get(parameter_index) {
                                    let arg_taint = eval_abstract_expr(
                                        arg,
                                        &env,
                                        summaries,
                                        &function.package_path,
                                        local_index,
                                        patterns,
                                    );
                                    for origin in arg_taint {
                                        if let AbstractOrigin::Param(param_index) = origin {
                                            summary
                                                .param_to_sink
                                                .entry(sink_category.clone())
                                                .or_default()
                                                .insert(param_index);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    summary
}

fn eval_abstract_expr(
    expr: &SimpleExpr,
    env: &HashMap<String, BTreeSet<AbstractOrigin>>,
    summaries: &BTreeMap<String, FunctionSummary>,
    package_path: &str,
    local_index: &HashMap<String, Vec<String>>,
    patterns: &DataFlowPatternSet,
) -> BTreeSet<AbstractOrigin> {
    match expr {
        SimpleExpr::Var(name) => {
            // P3.5: whole-object read. Sound-leaning with respect to
            // per-field writes — a read of `x` sees taint from any
            // `x.<field>` access path so writes to fields continue to
            // flow through subsequent whole-object reads. The
            // asymmetric direction (field reads do NOT inherit sibling
            // field taints) is handled in the `SimpleExpr::Field` arm.
            let mut taint = env.get(name).cloned().unwrap_or_default();
            let prefix = format!("{}.", name);
            for (key, value) in env {
                if key.starts_with(&prefix) {
                    taint.extend(value.iter().cloned());
                }
            }
            taint
        }
        SimpleExpr::Call { callee, args, .. } => {
            if let Some(source_match) = find_source_pattern(callee, &patterns.sources) {
                return BTreeSet::from([AbstractOrigin::Source(source_match.category.to_string())]);
            }
            if is_sanitizer_call(callee) {
                return BTreeSet::new();
            }
            if has_passthrough_pattern(callee, &patterns.passthroughs) {
                let mut taint = BTreeSet::new();
                for arg in args {
                    taint.extend(eval_abstract_expr(
                        arg,
                        env,
                        summaries,
                        package_path,
                        local_index,
                        patterns,
                    ));
                }
                return taint;
            }

            let mut taint = BTreeSet::new();
            if let Some(resolved) = resolve_call_target(callee, package_path, local_index, None)
                && let Some(summary) = summaries.get(&resolved).cloned()
            {
                for category in summary.returns_source_categories {
                    taint.insert(AbstractOrigin::Source(category.clone()));
                }
                for param_index in summary.param_to_return {
                    if let Some(arg) = args.get(param_index) {
                        taint.extend(eval_abstract_expr(
                            arg,
                            env,
                            summaries,
                            package_path,
                            local_index,
                            patterns,
                        ));
                    }
                }
            }
            taint
        }
        SimpleExpr::Compose(items) => {
            let mut taint = BTreeSet::new();
            for item in items {
                taint.extend(eval_abstract_expr(
                    item,
                    env,
                    summaries,
                    package_path,
                    local_index,
                    patterns,
                ));
            }
            taint
        }
        SimpleExpr::Field { base, field } => {
            // P3.5: access-path-aware field read. Reads of `x.a` consult
            // the `x.a` access-path key first, then fall back to the
            // whole-object taint on `x` (sound-leaning — a whole-object
            // write still flows to field reads). Critically, sibling
            // fields (`x.b`) are NOT consulted, so writes to one field
            // do not pollute reads of another.
            if let SimpleExpr::Var(name) = base.as_ref() {
                let key = format!("{}.{}", name, field);
                let mut taint = env.get(&key).cloned().unwrap_or_default();
                if let Some(whole) = env.get(name) {
                    taint.extend(whole.iter().cloned());
                }
                taint
            } else {
                // Nested or non-var base (e.g. `x.y.a`): fall back to
                // whole-base read. Nested access paths are tracked at
                // P3.1 (compiler side); stable keeps the conservative
                // join here.
                eval_abstract_expr(base, env, summaries, package_path, local_index, patterns)
            }
        }
        SimpleExpr::MethodCall {
            method,
            receiver,
            args,
            ..
        } => {
            let callee = method.clone();
            let all_args = std::iter::once(receiver.as_ref())
                .chain(args.iter())
                .cloned()
                .collect::<Vec<_>>();
            if let Some(source_match) = find_source_pattern(&callee, &patterns.sources) {
                return BTreeSet::from([AbstractOrigin::Source(source_match.category.to_string())]);
            }
            if is_sanitizer_call(&callee) {
                return BTreeSet::new();
            }
            if has_passthrough_pattern(&callee, &patterns.passthroughs) {
                let mut taint = BTreeSet::new();
                for arg in &all_args {
                    taint.extend(eval_abstract_expr(
                        arg,
                        env,
                        summaries,
                        package_path,
                        local_index,
                        patterns,
                    ));
                }
                return taint;
            }
            let mut taint = BTreeSet::new();
            if let Some(resolved) = resolve_call_target(&callee, package_path, local_index, None)
                && let Some(summary) = summaries.get(&resolved).cloned()
            {
                for category in summary.returns_source_categories {
                    taint.insert(AbstractOrigin::Source(category.clone()));
                }
                for param_index in summary.param_to_return {
                    if let Some(arg) = all_args.get(param_index) {
                        taint.extend(eval_abstract_expr(
                            arg,
                            env,
                            summaries,
                            package_path,
                            local_index,
                            patterns,
                        ));
                    }
                }
            }
            taint
        }
        SimpleExpr::Reference { expr, .. } => {
            // P4.1: a reference evaluates to its pointee's taint. The
            // mutable flag is consulted by the out-param propagation
            // heuristic in the concrete pass; here it does not change
            // the read semantics.
            eval_abstract_expr(expr, env, summaries, package_path, local_index, patterns)
        }
        SimpleExpr::Literal | SimpleExpr::Unknown => BTreeSet::new(),
    }
}

struct DataFlowBuilder<'a> {
    mode: &'a str,
    // Borrowed rather than owned: the parallel data-flow pass constructs one
    // builder per function, and cloning the whole pattern set + per-function
    // summary map into every builder was an O(n²) allocation that dominated
    // peak memory on large whole-program targets (RC-4/RC-5). Sharing immutable
    // references keeps a single copy across all workers.
    patterns: &'a DataFlowPatternSet,
    summaries: &'a BTreeMap<String, FunctionSummary>,
    local_index: &'a HashMap<String, Vec<String>>,
    function_map: &'a HashMap<String, &'a FunctionRecord>,
    /// Type indexes, so a receiver-typed sink pattern can be evaluated: a
    /// pattern restricted to `Command::arg` must know what `cmd` is.
    field_types: &'a HashMap<String, String>,
    return_types: &'a ReturnTypeIndex,
    /// Type bindings of the function currently being materialized.
    current_bindings: HashMap<String, String>,
    nodes: IndexMap<String, DataFlowNode>,
    edges: IndexMap<String, DataFlowEdge>,
    slices: IndexMap<String, DataFlowSlice>,
    missing_passthrough_call_counts: HashMap<String, usize>,
}

impl<'a> DataFlowBuilder<'a> {
    fn new(
        mode: &'a str,
        patterns: &'a DataFlowPatternSet,
        summaries: &'a BTreeMap<String, FunctionSummary>,
        local_index: &'a HashMap<String, Vec<String>>,
        function_map: &'a HashMap<String, &'a FunctionRecord>,
        field_types: &'a HashMap<String, String>,
        return_types: &'a ReturnTypeIndex,
    ) -> Self {
        Self {
            mode,
            patterns,
            summaries,
            local_index,
            function_map,
            field_types,
            return_types,
            current_bindings: HashMap::new(),
            nodes: IndexMap::new(),
            edges: IndexMap::new(),
            slices: IndexMap::new(),
            missing_passthrough_call_counts: HashMap::new(),
        }
    }

    fn materialize_function(&mut self, function: &FunctionRecord) {
        self.current_bindings = infer_type_bindings(function, self.field_types, self.return_types);
        let mut env: HashMap<String, ConcreteTaint> = HashMap::new();
        for (idx, param) in function.params.iter().enumerate() {
            let category = function
                .param_source_categories
                .get(&idx)
                .cloned()
                .unwrap_or_else(|| format!("param-{}", idx));
            let path = self.new_source_path(
                function,
                param,
                &category,
                function.declaration.position.clone(),
                Some(idx),
            );
            env.insert(param.clone(), ConcreteTaint { paths: vec![path] });
        }
        for operation in &function.operations {
            match operation {
                Operation::Assign { target, value } => {
                    let mut taint = self.eval_concrete_expr(function, value, &env);
                    if !taint.paths.is_empty() {
                        let mut pos = function.declaration.position.clone();
                        if pos.filename.is_empty() {
                            pos.filename = function.file_path.clone();
                        }
                        let node_id = stable_id(
                            "df-node",
                            &[
                                &function.declaration.id,
                                target,
                                "local",
                                &pos.line.to_string(),
                                &pos.column.to_string(),
                            ],
                        );
                        let target_node = DataFlowNode {
                            id: node_id.clone(),
                            kind: "local".to_string(),
                            name: target.clone(),
                            package_path: function.package_path.clone(),
                            purl: String::new(),
                            function: function.declaration.qualified_name.clone(),
                            position: pos.clone(),
                            source: false,
                            sink: false,
                            category: String::new(),
                            parameter_index: None,
                            type_name: None,
                            properties: IndexMap::new(),
                        };
                        self.nodes.insert(node_id.clone(), target_node.clone());
                        for path in &mut taint.paths {
                            if let Some(last_step) = path.steps.last() {
                                let edge_id =
                                    stable_id("df-edge", &[&last_step.node.id, &node_id, "assign"]);
                                let edge = DataFlowEdge {
                                    id: edge_id.clone(),
                                    source_id: last_step.node.id.clone(),
                                    target_id: node_id.clone(),
                                    kind: "assign".to_string(),
                                    properties: IndexMap::new(),
                                };
                                self.edges.insert(edge_id.clone(), edge.clone());
                                path.steps.push(TaintStep {
                                    node: target_node.clone(),
                                    edge: Some(edge),
                                });
                            } else {
                                path.steps.push(TaintStep {
                                    node: target_node.clone(),
                                    edge: None,
                                });
                            }
                        }
                        env.insert(target.clone(), taint);
                    }
                }
                Operation::AssignField {
                    target,
                    field,
                    value,
                } => {
                    let taint = self.eval_concrete_expr(function, value, &env);
                    if !taint.paths.is_empty() {
                        let key = format!("{}.{}", target, field);
                        env.insert(key, taint);
                    }
                }
                Operation::LoopBody(loop_ops) => {
                    let mut loop_env = env.clone();
                    for _iter in 0..4 {
                        let mut changed = false;
                        for op in loop_ops {
                            match op {
                                Operation::Assign { target, value } => {
                                    let taint = self.eval_concrete_expr(function, value, &loop_env);
                                    if !taint.paths.is_empty() {
                                        if loop_env.get(target).is_none_or(|prev| {
                                            prev.paths.len() != taint.paths.len()
                                        }) {
                                            changed = true;
                                        }
                                        loop_env.insert(target.clone(), taint);
                                    }
                                }
                                Operation::AssignField {
                                    target,
                                    field,
                                    value,
                                } => {
                                    let taint = self.eval_concrete_expr(function, value, &loop_env);
                                    if !taint.paths.is_empty() {
                                        let key = format!("{}.{}", target, field);
                                        loop_env.insert(key, taint);
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !changed {
                            break;
                        }
                    }
                    for (key, taint) in loop_env {
                        env.entry(key).or_insert(taint);
                    }
                }
                Operation::Expr(expr) | Operation::Return(expr) => {
                    let (callee, args, position, receiver_type) = match expr {
                        SimpleExpr::Call {
                            callee,
                            args,
                            position,
                        } => (callee.clone(), args.clone(), position.clone(), None),
                        SimpleExpr::MethodCall {
                            method,
                            receiver,
                            args,
                            position,
                        } => {
                            let all_args = std::iter::once(receiver.as_ref())
                                .chain(args.iter())
                                .cloned()
                                .collect::<Vec<_>>();
                            let receiver_type = infer_expr_type(
                                receiver,
                                &self.current_bindings,
                                self.field_types,
                                self.return_types,
                            );
                            (method.clone(), all_args, position.clone(), receiver_type)
                        }
                        _ => continue,
                    };
                    let callee = &callee;
                    let args = &args;
                    let position = &position;
                    {
                        if let Some(sink_match) = find_sink_pattern(
                            callee,
                            args,
                            receiver_type.as_deref(),
                            &self.patterns.sinks,
                        ) {
                            for index in &sink_match.relevant_arguments {
                                if let Some(arg) = args.get(*index) {
                                    let taint = self.eval_concrete_expr(function, arg, &env);
                                    self.emit_sink_slices(
                                        function,
                                        &taint,
                                        callee,
                                        &sink_match.category,
                                        position,
                                    );
                                }
                            }
                        }
                        // P4.1 out-parameter mutation: only propagate
                        // taint into arguments that are *mutable
                        // references* (`&mut x`). The previous heuristic
                        // unioned every call's taint onto every Var arg,
                        // which manufactured cross-arg FPs whenever a
                        // tainted value happened to share a callsite
                        // with an unrelated sink-shaped argument.
                        // Mutability is detected via the preserved
                        // SimpleExpr::Reference{mutable:true} marker.
                        let mut union_taint = ConcreteTaint::default();
                        for arg in args {
                            union_taint
                                .paths
                                .extend(self.eval_concrete_expr(function, arg, &env).paths);
                        }
                        let union_taint = union_taint.bounded();
                        if !union_taint.paths.is_empty() {
                            for arg in args {
                                if let SimpleExpr::Reference {
                                    expr,
                                    mutable: true,
                                } = arg
                                    && let SimpleExpr::Var(var_name) = expr.as_ref()
                                {
                                    // Confirmed &mut arg: the callee may
                                    // write into it. Conservative union.
                                    if var_name != "tx" && var_name != "rx" {
                                        let mut target_taint =
                                            env.get(var_name).cloned().unwrap_or_default();
                                        target_taint.paths.extend(union_taint.paths.clone());
                                        env.insert(var_name.clone(), target_taint.bounded());
                                    }
                                }
                            }
                        }

                        // P4.2 channel send/recv: per-channel taint slot
                        // keyed by the paired receiver identity. Falls
                        // back to a global slot only when no pairing is
                        // known (e.g. channel constructed outside this
                        // function). The previous global `__channel_taint`
                        // slot let an unrelated `rx.recv()` pick up taint
                        // from a different channel's `tx.send()`.
                        if callee.ends_with("send")
                            && let Some(val_arg) = args.get(1)
                        {
                            let val_taint = self.eval_concrete_expr(function, val_arg, &env);
                            if !val_taint.paths.is_empty() {
                                // Channel identity: prefer the paired
                                // receiver name when we know it, so
                                // `rx.recv()` can find this taint
                                // without consulting the global slot.
                                let channel_key = match args.first() {
                                    Some(SimpleExpr::Var(tx_name)) => {
                                        match function
                                            .channel_pairs
                                            .iter()
                                            .find(|(tx, _)| tx == tx_name)
                                        {
                                            Some((_, rx_name)) => {
                                                format!("__channel:{rx_name}")
                                            }
                                            None => format!("__channel:{tx_name}"),
                                        }
                                    }
                                    _ => "__channel_taint".to_string(),
                                };
                                let mut channel_taint =
                                    env.get(&channel_key).cloned().unwrap_or_default();
                                channel_taint.paths.extend(val_taint.paths);
                                env.insert(channel_key, channel_taint.bounded());
                            }
                        }

                        if let Some(resolved) = resolve_call_target(
                            callee,
                            &function.package_path,
                            self.local_index,
                            None,
                        ) && let Some(summary) = self.summaries.get(&resolved).cloned()
                        {
                            for (sink_category, parameter_indexes) in summary.param_to_sink {
                                for parameter_index in parameter_indexes {
                                    if let Some(arg) = args.get(parameter_index) {
                                        let taint = self.eval_concrete_expr(function, arg, &env);
                                        self.emit_sink_slices(
                                            function,
                                            &taint,
                                            callee,
                                            &sink_category,
                                            position,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Evaluate `expr`'s taint and bound the resulting witness set (RC-1).
    /// Every recursive sub-evaluation flows through here, so each intermediate
    /// taint set stays capped and propagation never blows up combinatorially.
    fn eval_concrete_expr(
        &mut self,
        function: &FunctionRecord,
        expr: &SimpleExpr,
        env: &HashMap<String, ConcreteTaint>,
    ) -> ConcreteTaint {
        self.eval_concrete_expr_inner(function, expr, env).bounded()
    }

    fn eval_concrete_expr_inner(
        &mut self,
        function: &FunctionRecord,
        expr: &SimpleExpr,
        env: &HashMap<String, ConcreteTaint>,
    ) -> ConcreteTaint {
        match expr {
            SimpleExpr::Var(name) => {
                // P3.5: whole-object read — include per-field writes so a
                // subsequent sink on the whole object still slices.
                let mut taint = env
                    .get(name)
                    .cloned()
                    .unwrap_or(ConcreteTaint { paths: vec![] });
                let prefix = format!("{}.", name);
                for (key, value) in env {
                    if key.starts_with(&prefix) {
                        taint.paths.extend(value.paths.iter().cloned());
                    }
                }
                taint.bounded()
            }
            SimpleExpr::Call {
                callee,
                args,
                position,
            } => {
                if callee.ends_with("recv")
                    && let Some(taint) = env.get("__channel_taint")
                {
                    return taint.clone();
                }
                if let Some(source_match) = find_source_pattern(callee, &self.patterns.sources) {
                    let path = self.new_source_path(
                        function,
                        callee,
                        &source_match.category,
                        position.clone(),
                        None,
                    );
                    return ConcreteTaint { paths: vec![path] };
                }
                if is_sanitizer_call(callee) {
                    return ConcreteTaint { paths: vec![] };
                }
                if has_passthrough_pattern(callee, &self.patterns.passthroughs) {
                    let mut paths = Vec::new();
                    for arg in args {
                        let arg_taint = self.eval_concrete_expr(function, arg, env);
                        for mut path in arg_taint.paths {
                            let mut pos = position.clone();
                            if pos.filename.is_empty() {
                                pos.filename = function.file_path.clone();
                            }
                            let node_id = stable_id(
                                "df-node",
                                &[
                                    &function.declaration.id,
                                    callee,
                                    "passthrough",
                                    &pos.line.to_string(),
                                    &pos.column.to_string(),
                                ],
                            );
                            let passthrough_node = DataFlowNode {
                                id: node_id.clone(),
                                kind: "passthrough".to_string(),
                                name: callee.to_string(),
                                package_path: function.package_path.clone(),
                                purl: String::new(),
                                function: function.declaration.qualified_name.clone(),
                                position: pos.clone(),
                                source: false,
                                sink: false,
                                category: String::new(),
                                parameter_index: None,
                                type_name: None,
                                properties: IndexMap::new(),
                            };
                            self.nodes.insert(node_id.clone(), passthrough_node.clone());
                            if let Some(last_step) = path.steps.last() {
                                let edge_id = stable_id(
                                    "df-edge",
                                    &[&last_step.node.id, &node_id, "passthrough"],
                                );
                                let edge = DataFlowEdge {
                                    id: edge_id.clone(),
                                    source_id: last_step.node.id.clone(),
                                    target_id: node_id.clone(),
                                    kind: "passthrough".to_string(),
                                    properties: IndexMap::new(),
                                };
                                self.edges.insert(edge_id, edge.clone());
                                path.steps.push(TaintStep {
                                    node: passthrough_node,
                                    edge: Some(edge),
                                });
                            }
                            paths.push(path);
                        }
                    }
                    return ConcreteTaint { paths };
                }
                if let Some(resolved) =
                    resolve_call_target(callee, &function.package_path, self.local_index, None)
                    && let Some(summary) = self.summaries.get(&resolved).cloned()
                {
                    let mut paths = Vec::new();
                    for category in &summary.returns_source_categories {
                        let callee_name = self
                            .function_map
                            .get(&resolved)
                            .map(|f| f.declaration.qualified_name.clone())
                            .unwrap_or_else(|| callee.to_string());
                        paths.push(self.new_source_path(
                            function,
                            &callee_name,
                            category,
                            position.clone(),
                            None,
                        ));
                    }
                    for param_index in &summary.param_to_return {
                        if let Some(arg) = args.get(*param_index) {
                            let arg_taint = self.eval_concrete_expr(function, arg, env);
                            for mut path in arg_taint.paths {
                                let callee_name = self
                                    .function_map
                                    .get(&resolved)
                                    .map(|f| f.declaration.qualified_name.clone())
                                    .unwrap_or_else(|| callee.to_string());
                                let mut pos = position.clone();
                                if pos.filename.is_empty() {
                                    pos.filename = function.file_path.clone();
                                }
                                let node_id = stable_id(
                                    "df-node",
                                    &[
                                        &function.declaration.id,
                                        &callee_name,
                                        &format!("param-to-return-{}", param_index),
                                        &pos.line.to_string(),
                                        &pos.column.to_string(),
                                    ],
                                );
                                let call_node = DataFlowNode {
                                    id: node_id.clone(),
                                    kind: "call_return".to_string(),
                                    name: callee_name.clone(),
                                    package_path: function.package_path.clone(),
                                    purl: String::new(),
                                    function: function.declaration.qualified_name.clone(),
                                    position: pos.clone(),
                                    source: false,
                                    sink: false,
                                    category: String::new(),
                                    parameter_index: Some(*param_index),
                                    type_name: None,
                                    properties: IndexMap::new(),
                                };
                                self.nodes.insert(node_id.clone(), call_node.clone());
                                if let Some(last_step) = path.steps.last() {
                                    let edge_id = stable_id(
                                        "df-edge",
                                        &[&last_step.node.id, &node_id, "call_return"],
                                    );
                                    let edge = DataFlowEdge {
                                        id: edge_id.clone(),
                                        source_id: last_step.node.id.clone(),
                                        target_id: node_id.clone(),
                                        kind: "call_return".to_string(),
                                        properties: IndexMap::new(),
                                    };
                                    self.edges.insert(edge_id, edge.clone());
                                    path.steps.push(TaintStep {
                                        node: call_node,
                                        edge: Some(edge),
                                    });
                                }
                                paths.push(path);
                            }
                        }
                    }
                    return ConcreteTaint { paths };
                }
                // Record missing passthrough if args have taint
                let mut arg_taint_count = 0usize;
                for arg in args {
                    let arg_paths = self.eval_concrete_expr(function, arg, env).paths;
                    arg_taint_count += arg_paths.len();
                }
                if arg_taint_count > 0 {
                    let entry = self
                        .missing_passthrough_call_counts
                        .entry(callee.clone())
                        .or_default();
                    *entry += 1;
                }
                ConcreteTaint { paths: vec![] }
            }
            SimpleExpr::MethodCall {
                method,
                receiver,
                args,
                position,
            } => {
                if method.ends_with("recv") {
                    // P4.2: look up the per-channel taint slot keyed by
                    // the receiver variable (e.g. `__channel:rx`). Falls
                    // back to the global slot for non-Var receivers so we
                    // don't lose flows through `arc.lock().recv()`-style
                    // chains.
                    let channel_key = match receiver.as_ref() {
                        SimpleExpr::Var(name) => format!("__channel:{name}"),
                        _ => "__channel_taint".to_string(),
                    };
                    if let Some(taint) = env.get(&channel_key) {
                        return taint.clone();
                    }
                }
                if let Some(source_match) = find_source_pattern(method, &self.patterns.sources) {
                    let path = self.new_source_path(
                        function,
                        method,
                        &source_match.category,
                        position.clone(),
                        None,
                    );
                    return ConcreteTaint { paths: vec![path] };
                }
                if is_sanitizer_call(method) {
                    return ConcreteTaint { paths: vec![] };
                }
                let all_args = std::iter::once(receiver.as_ref())
                    .chain(args.iter())
                    .cloned()
                    .collect::<Vec<_>>();
                if has_passthrough_pattern(method, &self.patterns.passthroughs) {
                    let mut paths = Vec::new();
                    for arg in &all_args {
                        let arg_taint = self.eval_concrete_expr(function, arg, env);
                        paths.extend(arg_taint.paths);
                    }
                    return ConcreteTaint { paths };
                }
                if let Some(resolved) =
                    resolve_call_target(method, &function.package_path, self.local_index, None)
                    && let Some(summary) = self.summaries.get(&resolved).cloned()
                {
                    let mut paths = Vec::new();
                    for category in &summary.returns_source_categories {
                        let callee_name = self
                            .function_map
                            .get(&resolved)
                            .map(|f| f.declaration.qualified_name.clone())
                            .unwrap_or_else(|| method.to_string());
                        paths.push(self.new_source_path(
                            function,
                            &callee_name,
                            category,
                            position.clone(),
                            None,
                        ));
                    }
                    for param_index in &summary.param_to_return {
                        if let Some(arg) = all_args.get(*param_index) {
                            let arg_taint = self.eval_concrete_expr(function, arg, env);
                            paths.extend(arg_taint.paths);
                        }
                    }
                    return ConcreteTaint { paths };
                }
                let mut arg_taint_count = 0usize;
                for arg in &all_args {
                    let arg_paths = self.eval_concrete_expr(function, arg, env).paths;
                    arg_taint_count += arg_paths.len();
                }
                if arg_taint_count > 0 {
                    let entry = self
                        .missing_passthrough_call_counts
                        .entry(method.clone())
                        .or_default();
                    *entry += 1;
                }
                ConcreteTaint { paths: vec![] }
            }
            SimpleExpr::Compose(items) => {
                let mut paths = Vec::new();
                for item in items {
                    paths.extend(self.eval_concrete_expr(function, item, env).paths);
                }
                ConcreteTaint { paths }
            }
            SimpleExpr::Field { base, field } => {
                // P3.5: access-path-aware field read. `x.a` consults the
                // `x.a` access-path key first, then falls back to whole-
                // object taint on `x` (sound-leaning). Sibling fields
                // (`x.b`) are NOT consulted — that's the whole point.
                if let SimpleExpr::Var(name) = base.as_ref() {
                    let key = format!("{}.{}", name, field);
                    let mut taint = env
                        .get(&key)
                        .cloned()
                        .unwrap_or(ConcreteTaint { paths: vec![] });
                    if let Some(whole) = env.get(name) {
                        taint.paths.extend(whole.paths.iter().cloned());
                    }
                    taint.bounded()
                } else {
                    self.eval_concrete_expr(function, base, env)
                }
            }
            SimpleExpr::Reference { expr, .. } => self.eval_concrete_expr(function, expr, env),
            SimpleExpr::Literal | SimpleExpr::Unknown => ConcreteTaint { paths: vec![] },
        }
    }

    fn new_source_path(
        &mut self,
        function: &FunctionRecord,
        name: &str,
        category: &str,
        position: Position,
        parameter_index: Option<usize>,
    ) -> TaintPath {
        let mut pos = position.clone();
        if pos.filename.is_empty() {
            pos.filename = function.file_path.clone();
        }
        let node_id = stable_id(
            "df-node",
            &[
                &function.declaration.id,
                name,
                category,
                &pos.line.to_string(),
                &pos.column.to_string(),
            ],
        );
        let node = DataFlowNode {
            id: node_id.clone(),
            kind: "source".to_string(),
            name: name.to_string(),
            package_path: function.package_path.clone(),
            purl: String::new(),
            function: function.declaration.qualified_name.clone(),
            position: pos.clone(),
            source: true,
            sink: false,
            category: category.to_string(),
            parameter_index,
            type_name: None,
            properties: IndexMap::new(),
        };
        self.nodes.insert(node_id.clone(), node.clone());
        TaintPath {
            origin_key: format!("{}:{}:{}", function.declaration.id, name, category),
            category: category.to_string(),
            steps: vec![TaintStep { node, edge: None }],
        }
    }

    fn emit_sink_slices(
        &mut self,
        function: &FunctionRecord,
        taint: &ConcreteTaint,
        sink_name: &str,
        sink_category: &str,
        position: &Position,
    ) {
        if taint.paths.is_empty() {
            return;
        }
        let mut pos = position.clone();
        if pos.filename.is_empty() {
            pos.filename = function.file_path.clone();
        }
        let sink_node_id = stable_id(
            "df-node",
            &[
                &function.declaration.id,
                sink_name,
                sink_category,
                &pos.line.to_string(),
                &pos.column.to_string(),
            ],
        );
        let sink_node = DataFlowNode {
            id: sink_node_id.clone(),
            kind: "sink".to_string(),
            name: sink_name.to_string(),
            package_path: function.package_path.clone(),
            purl: String::new(),
            function: function.declaration.qualified_name.clone(),
            position: pos.clone(),
            source: false,
            sink: true,
            category: sink_category.to_string(),
            parameter_index: None,
            type_name: None,
            properties: IndexMap::new(),
        };
        self.nodes.insert(sink_node_id.clone(), sink_node.clone());

        for path in &taint.paths {
            let mut final_path = path.clone();
            if let Some(last_step) = final_path.steps.last() {
                let edge_id = stable_id(
                    "df-edge",
                    &[&last_step.node.id, &sink_node_id, sink_category],
                );
                let edge = DataFlowEdge {
                    id: edge_id.clone(),
                    source_id: last_step.node.id.clone(),
                    target_id: sink_node_id.clone(),
                    kind: "taint".to_string(),
                    properties: IndexMap::new(),
                };
                final_path.steps.push(TaintStep {
                    node: sink_node.clone(),
                    edge: Some(edge),
                });
            } else {
                final_path.steps.push(TaintStep {
                    node: sink_node.clone(),
                    edge: None,
                });
            }

            // Register all nodes and edges in the final path to self.nodes and self.edges
            for step in &final_path.steps {
                self.nodes.insert(step.node.id.clone(), step.node.clone());
                if let Some(edge) = &step.edge {
                    self.edges.insert(edge.id.clone(), edge.clone());
                }
            }

            let slice_id = stable_id(
                "df-slice",
                &[&final_path.origin_key, &sink_node_id, sink_category],
            );
            let first_node = &final_path.steps[0].node;
            let node_ids = final_path
                .steps
                .iter()
                .map(|s| s.node.id.clone())
                .collect::<Vec<_>>();
            let edge_ids = final_path
                .steps
                .iter()
                .filter_map(|s| s.edge.as_ref().map(|e| e.id.clone()))
                .collect::<Vec<_>>();
            let path_length = edge_ids.len();

            self.slices
                .entry(slice_id.clone())
                .or_insert_with(|| DataFlowSlice {
                    id: slice_id,
                    source_id: first_node.id.clone(),
                    sink_id: sink_node_id.clone(),
                    source_name: first_node.name.clone(),
                    sink_name: sink_name.to_string(),
                    source_function: first_node.function.clone(),
                    sink_function: function.declaration.qualified_name.clone(),
                    source_package_path: first_node.package_path.clone(),
                    sink_package_path: function.package_path.clone(),
                    source_purl: String::new(),
                    target_purl: String::new(),
                    purls: Vec::new(),
                    source_category: final_path.category.clone(),
                    sink_category: sink_category.to_string(),
                    node_ids,
                    edge_ids,
                    path_length,
                    source_parameter_index: first_node.parameter_index,
                    sink_parameter_index: None,
                    source_type_name: None,
                    sink_type_name: None,
                    rule_name: format!("{}-to-{}", final_path.category, sink_category),
                    description: format!(
                        "{} data can flow from {} to {}",
                        final_path.category, first_node.name, sink_name
                    ),
                    properties: IndexMap::new(),
                });
        }
    }

    fn finish(self) -> DataFlowEvidence {
        let mut summaries = Vec::new();
        for (function_id, summary) in self.summaries {
            let function = self
                .function_map
                .get(function_id)
                .map(|record| record.declaration.qualified_name.clone())
                .unwrap_or_default();
            let package_path = self
                .function_map
                .get(function_id)
                .map(|record| record.package_path.clone())
                .unwrap_or_default();
            summaries.push(DataFlowMethodSummary {
                function_id: function_id.clone(),
                function,
                package_path,
                purl: String::new(),
                parameter_names: self
                    .function_map
                    .get(function_id)
                    .map(|record| record.params.clone())
                    .unwrap_or_default(),
                parameter_types: self
                    .function_map
                    .get(function_id)
                    .map(|record| record.param_types.clone())
                    .unwrap_or_default(),
                return_type: self
                    .function_map
                    .get(function_id)
                    .map(|record| record.return_type.clone())
                    .unwrap_or_else(|| "()".to_string()),
                param_to_return: summary.param_to_return.iter().copied().collect(),
                param_to_sink: summary
                    .param_to_sink
                    .iter()
                    .map(|(key, value)| (key.clone(), value.iter().copied().collect()))
                    .collect(),
                source_returns: summary.returns_source_categories.iter().cloned().collect(),
                properties: IndexMap::new(),
            });
        }
        summaries.sort_by(|left, right| left.function_id.cmp(&right.function_id));

        let nodes = self.nodes.into_values().collect::<Vec<_>>();
        let edges = self.edges.into_values().collect::<Vec<_>>();
        let slices = self.slices.into_values().collect::<Vec<_>>();
        let mut result = DataFlowEvidence {
            mode: self.mode.to_string(),
            patterns: self.patterns.clone(),
            stats: DataFlowStats {
                source_count: nodes.iter().filter(|node| node.source).count(),
                sink_count: nodes.iter().filter(|node| node.sink).count(),
                slice_count: slices.len(),
                node_count: nodes.len(),
                edge_count: edges.len(),
                summary_count: summaries.len(),
            },
            nodes,
            edges,
            slices,
            summaries,
            diagnostics: Vec::new(),
        };
        if !self.missing_passthrough_call_counts.is_empty() {
            let mut entries: Vec<_> = self.missing_passthrough_call_counts.iter().collect();
            // Sort by count descending, breaking ties by callee name so both the
            // selected top-20 and their order are deterministic across runs
            // (the source map is a HashMap with non-deterministic iteration).
            entries.sort_by(|(callee_a, count_a), (callee_b, count_b)| {
                count_b.cmp(count_a).then_with(|| callee_a.cmp(callee_b))
            });
            for (callee, count) in entries.iter().take(20) {
                result.diagnostics.push(Diagnostic {
                    kind: "missing-passthrough".to_string(),
                    message: format!(
                        "taint may be lost at '{}' (observed {} times); consider adding it as a passthrough pattern",
                        callee, count
                    ),
                    package_path: None,
                    file_path: None,
                    position: None,
                });
            }
        }
        result
    }

    fn merge_materialized(&mut self, other: DataFlowBuilder<'a>) {
        for (key, value) in other.nodes {
            self.nodes.entry(key).or_insert(value);
        }
        for (key, value) in other.edges {
            self.edges.entry(key).or_insert(value);
        }
        for (key, value) in other.slices {
            self.slices.entry(key).or_insert(value);
        }
        for (callee, count) in other.missing_passthrough_call_counts {
            *self
                .missing_passthrough_call_counts
                .entry(callee)
                .or_default() += count;
        }
    }
}

fn find_source_pattern(callee: &str, patterns: &[DataFlowPattern]) -> Option<SourcePatternMatch> {
    let normalized = normalize_pattern_text(callee);
    patterns
        .iter()
        .find(|pattern| pattern_matches_callee(&normalized, &pattern.pattern))
        .map(|pattern| SourcePatternMatch {
            category: pattern.category.clone(),
        })
}

fn find_sink_pattern(
    callee: &str,
    args: &[SimpleExpr],
    receiver_type: Option<&str>,
    patterns: &[DataFlowPattern],
) -> Option<SinkPatternMatch> {
    let normalized = normalize_pattern_text(callee);
    patterns
        .iter()
        .find(|pattern| {
            pattern_matches_callee(&normalized, &pattern.pattern)
                && receiver_type_matches(pattern, receiver_type)
                && sink_pattern_context_confident(&normalized, args, pattern)
        })
        .map(|pattern| SinkPatternMatch {
            category: pattern.category.clone(),
            relevant_arguments: pattern.relevant_arguments.clone(),
        })
}

/// Whether a pattern's receiver-type restriction is satisfied.
///
/// A pattern without one matches on the callee alone, as before. A pattern with
/// one matches only when the receiver's type was actually resolved to it —
/// never when the type is unknown, because a sink that fires on an unresolved
/// receiver is exactly the false positive the restriction exists to prevent.
fn receiver_type_matches(pattern: &DataFlowPattern, receiver_type: Option<&str>) -> bool {
    match pattern.receiver_type.as_deref() {
        None => true,
        Some(required) => receiver_type == Some(required),
    }
}

fn sink_pattern_context_confident(
    normalized_callee: &str,
    args: &[SimpleExpr],
    pattern: &DataFlowPattern,
) -> bool {
    if pattern.category != "sql-query" {
        return true;
    }
    if sqlish_symbol(normalized_callee) {
        return true;
    }
    let candidate = normalize_pattern_text(&pattern.pattern);
    if normalized_callee == candidate && normalized_callee.contains("::") {
        return true;
    }
    args.iter().any(simple_expr_looks_sqlish)
}

fn sqlish_symbol(symbol: &str) -> bool {
    let normalized = normalize_pattern_text(symbol).to_ascii_lowercase();
    [
        "sqlx::",
        "diesel::",
        "tokio_postgres",
        "tokio-postgres",
        "postgres",
        "rusqlite",
        "mysql_async",
        "mysql::",
        "tiberius",
        "sea_orm",
        "sea_query",
        "sql_query",
    ]
    .iter()
    .any(|token| normalized.contains(token))
}

fn simple_expr_looks_sqlish(expr: &SimpleExpr) -> bool {
    match expr {
        SimpleExpr::Var(name) => {
            let lower = name.to_ascii_lowercase();
            ["sql", "query", "stmt", "statement"]
                .iter()
                .any(|needle| lower.contains(needle))
        }
        SimpleExpr::Call { callee, args, .. } => {
            let normalized = normalize_pattern_text(callee);
            sqlish_symbol(&normalized)
                || matches!(
                    last_segment(&normalized),
                    "query"
                        | "query_as"
                        | "query_scalar"
                        | "sql_query"
                        | "prepare"
                        | "prepare_cached"
                )
                || args.iter().any(simple_expr_looks_sqlish)
        }
        SimpleExpr::Compose(items) => items.iter().any(simple_expr_looks_sqlish),
        SimpleExpr::Field { base, .. } => simple_expr_looks_sqlish(base),
        SimpleExpr::MethodCall { receiver, args, .. } => {
            simple_expr_looks_sqlish(receiver) || args.iter().any(simple_expr_looks_sqlish)
        }
        SimpleExpr::Reference { expr, .. } => simple_expr_looks_sqlish(expr),
        SimpleExpr::Literal | SimpleExpr::Unknown => false,
    }
}

fn has_passthrough_pattern(callee: &str, patterns: &[DataFlowPattern]) -> bool {
    let normalized = normalize_pattern_text(callee);
    patterns
        .iter()
        .any(|pattern| pattern_matches_callee(&normalized, &pattern.pattern))
}

/// Path-segment-aware pattern matching (P4.4).
///
/// Replaces the previous `==` or `ends_with` matcher, which produced
/// collisions like `ends_with("send")` matching `listen`/`suspend`, or
/// `ends_with("open")` matching `reopen`/`uncover`. The new matcher splits
/// both callee and pattern on `::` and compares trailing segments:
///   * Single-segment pattern (e.g. `bind`, `recv`): matches iff the
///     callee's *last* `::`-segment equals the pattern. So `bind` matches
///     `sqlx::query::bind` and the bare `bind`, but NOT `push_bind` or
///     `ammonia::clean` (different last segment).
///   * Multi-segment pattern (e.g. `std::env::var`): matches iff the
///     callee's trailing N segments equal the pattern's segments. So
///     `std::env::var` matches `crate::std::env::var` but NOT
///     `my::env::var::user` (different last-3 segments).
///   * Exact-match fallback for patterns containing no separator but
///     appearing as substrings of the callee string is intentionally
///     NOT supported — the segment boundary is the contract.
fn pattern_matches_callee(normalized_callee: &str, pattern: &str) -> bool {
    let pat = normalize_pattern_text(pattern);
    if normalized_callee == pat {
        return true;
    }
    let callee_segs: Vec<&str> = normalized_callee.split("::").collect();
    let pat_segs: Vec<&str> = pat.split("::").collect();
    if pat_segs.len() > callee_segs.len() {
        return false;
    }
    // Compare trailing segments: callee's last pat_segs.len() segments
    // must equal pat_segs in order.
    let offset = callee_segs.len() - pat_segs.len();
    callee_segs[offset..] == pat_segs[..]
}

fn normalize_pattern_text(value: &str) -> String {
    value.replace(' ', "")
}

fn enrich_graph_component_purls(report: &mut Report) {
    let package_purls = package_purl_index(&report.packages);

    for package in &mut report.packages {
        package.purl = resolve_package_purl(&package.package_path, &package_purls);
    }
    for file in &mut report.files {
        file.purl = resolve_package_purl(&file.package_path, &package_purls);
        // The flattened top-level collections below are the canonical, enriched
        // copies; drop the per-file duplicates so the report carries each item
        // exactly once (file association is preserved via each item's
        // `file_path`/`position.filename`).
        file.imports.clear();
        file.declarations.clear();
        file.usages.clear();
        file.security_signals.clear();
    }
    for import in &mut report.imports {
        import.purl = resolve_package_purl(&import.package_path, &package_purls);
    }
    for declaration in &mut report.declarations {
        declaration.purl = resolve_package_purl(&declaration.package_path, &package_purls);
    }
    for usage in &mut report.usages {
        usage.purl = resolve_package_purl(&usage.package_path, &package_purls);
    }
    for signal in &mut report.security_signals {
        signal.purl = resolve_package_purl(&signal.package_path, &package_purls);
    }

    if let Some(call_graph) = &mut report.call_graph {
        for node in &mut call_graph.nodes {
            node.purl = resolve_package_purl(&node.package_path, &package_purls);
            if node.purl.is_empty() {
                // A synthetic external node has no package of its own; infer the
                // owning crate from its qualified name so consumers can still
                // attribute the call.
                node.purl = resolve_package_purl(
                    &inferred_package_path(&node.qualified_name),
                    &package_purls,
                );
            }
        }
        // Edges deliberately carry no purls: both endpoints' purls live on the
        // nodes the edge references.
    }

    if let Some(data_flow) = &mut report.data_flow {
        for node in &mut data_flow.nodes {
            node.purl = resolve_package_purl(&node.package_path, &package_purls);
        }
        for summary in &mut data_flow.summaries {
            summary.purl = resolve_package_purl(&summary.package_path, &package_purls);
        }
        for slice in &mut data_flow.slices {
            slice.source_purl = resolve_package_purl(&slice.source_package_path, &package_purls);
            slice.target_purl = resolve_package_purl(&slice.sink_package_path, &package_purls);
            slice.purls = combined_purls(&slice.source_purl, &slice.target_purl);
        }
    }
}

fn package_purl_index(packages: &[PackageEvidence]) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for package in packages {
        let purl = build_cargo_purl(&package.name, Some(package.module.version.as_str()));
        for key in [
            package.package_path.clone(),
            package.name.clone(),
            package.name.replace('-', "_"),
            package.module.name.clone(),
            package.module.name.replace('-', "_"),
        ] {
            if !key.is_empty() {
                index.entry(key).or_insert_with(|| purl.clone());
            }
        }
    }
    index
}

fn resolve_package_purl(package_path: &str, package_purls: &HashMap<String, String>) -> String {
    let key = package_path
        .split("::")
        .next()
        .unwrap_or(package_path)
        .trim();
    if key.is_empty() {
        return String::new();
    }
    if let Some(purl) = package_purls.get(key) {
        return purl.clone();
    }
    let normalized = key.replace('_', "-");
    if matches!(
        normalized.as_str(),
        "std" | "core" | "alloc" | "proc-macro" | "proc_macro" | "test"
    ) {
        String::new()
    } else {
        build_cargo_purl(&normalized, None)
    }
}

fn build_cargo_purl(package_name: &str, version: Option<&str>) -> String {
    let encoded_name = percent_encode_purl_segment(package_name);
    match version.filter(|value| !value.is_empty()) {
        Some(version) => format!(
            "pkg:cargo/{encoded_name}@{}",
            percent_encode_purl_segment(version)
        ),
        None => format!("pkg:cargo/{encoded_name}"),
    }
}

fn percent_encode_purl_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '~') {
            encoded.push(ch);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn combined_purls(source_purl: &str, target_purl: &str) -> Vec<String> {
    let mut purls = BTreeSet::new();
    if !source_purl.is_empty() {
        purls.insert(source_purl.to_string());
    }
    if !target_purl.is_empty() {
        purls.insert(target_purl.to_string());
    }
    purls.into_iter().collect()
}

fn normalize_report(report: &mut Report) {
    enrich_graph_component_purls(report);
    report
        .modules
        .sort_by(|left, right| left.name.cmp(&right.name));
    report
        .packages
        .sort_by(|left, right| left.id.cmp(&right.id));
    report
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    report
        .imports
        .sort_by(|left, right| left.path.cmp(&right.path));
    report
        .declarations
        .sort_by(|left, right| left.id.cmp(&right.id));
    report.usages.sort_by(|left, right| left.id.cmp(&right.id));
    report
        .security_signals
        .sort_by(|left, right| left.id.cmp(&right.id));
    report
        .api_endpoints
        .sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(crypto) = &mut report.crypto {
        crypto
            .libraries
            .sort_by(|left, right| left.id.cmp(&right.id));
        crypto
            .components
            .sort_by(|left, right| left.id.cmp(&right.id));
        crypto
            .materials
            .sort_by(|left, right| left.id.cmp(&right.id));
        crypto
            .findings
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
    report
        .diagnostics
        .sort_by(|left, right| left.message.cmp(&right.message));
    if let Some(call_graph) = &mut report.call_graph {
        call_graph
            .nodes
            .sort_by(|left, right| left.id.cmp(&right.id));
        call_graph
            .edges
            .sort_by(|left, right| left.id.cmp(&right.id));
        call_graph
            .diagnostics
            .sort_by(|left, right| left.message.cmp(&right.message));
        call_graph.stats = GraphStats {
            node_count: call_graph.nodes.len(),
            edge_count: call_graph.edges.len(),
        };
    }
    if let Some(data_flow) = &mut report.data_flow {
        data_flow
            .nodes
            .sort_by(|left, right| left.id.cmp(&right.id));
        data_flow
            .edges
            .sort_by(|left, right| left.id.cmp(&right.id));
        data_flow
            .slices
            .sort_by(|left, right| left.id.cmp(&right.id));
        data_flow
            .summaries
            .sort_by(|left, right| left.function_id.cmp(&right.function_id));
        data_flow
            .diagnostics
            .sort_by(|left, right| left.message.cmp(&right.message));
        // Patterns (especially auto-discovered passthroughs) are collected via
        // hash-based sets; sort them so report output is byte-reproducible.
        sort_data_flow_patterns(&mut data_flow.patterns);
        data_flow.stats = DataFlowStats {
            source_count: data_flow.nodes.iter().filter(|node| node.source).count(),
            sink_count: data_flow.nodes.iter().filter(|node| node.sink).count(),
            slice_count: data_flow.slices.len(),
            node_count: data_flow.nodes.len(),
            edge_count: data_flow.edges.len(),
            summary_count: data_flow.summaries.len(),
        };
    }
}

/// Deterministically order a pattern set by (category, target, pattern,
/// relevant_arguments). Pattern collections include hash-derived,
/// auto-discovered entries whose insertion order varies between runs.
fn sort_data_flow_patterns(patterns: &mut DataFlowPatternSet) {
    let key = |pattern: &DataFlowPattern| {
        (
            pattern.category.clone(),
            pattern.target.clone(),
            pattern.pattern.clone(),
            pattern.relevant_arguments.clone(),
        )
    };
    patterns.sources.sort_by_key(&key);
    patterns.sinks.sort_by_key(&key);
    patterns.passthroughs.sort_by_key(&key);
}

fn compute_stats(report: &Report) -> Stats {
    Stats {
        package_count: report.packages.len(),
        file_count: report.files.len(),
        import_count: report.imports.len(),
        declaration_count: report.declarations.len(),
        usage_count: report.usages.len(),
        security_signal_count: report.security_signals.len(),
        crypto_library_count: report
            .crypto
            .as_ref()
            .map(|crypto| crypto.libraries.len())
            .unwrap_or(0),
        crypto_component_count: report
            .crypto
            .as_ref()
            .map(|crypto| crypto.components.len())
            .unwrap_or(0),
        crypto_material_count: report
            .crypto
            .as_ref()
            .map(|crypto| crypto.materials.len())
            .unwrap_or(0),
        crypto_finding_count: report
            .crypto
            .as_ref()
            .map(|crypto| crypto.findings.len())
            .unwrap_or(0),
        call_graph_node_count: report
            .call_graph
            .as_ref()
            .map(|graph| graph.nodes.len())
            .unwrap_or(0),
        call_graph_edge_count: report
            .call_graph
            .as_ref()
            .map(|graph| graph.edges.len())
            .unwrap_or(0),
        data_flow_node_count: report
            .data_flow
            .as_ref()
            .map(|flow| flow.nodes.len())
            .unwrap_or(0),
        data_flow_edge_count: report
            .data_flow
            .as_ref()
            .map(|flow| flow.edges.len())
            .unwrap_or(0),
        data_flow_slice_count: report
            .data_flow
            .as_ref()
            .map(|flow| flow.slices.len())
            .unwrap_or(0),
        api_endpoint_count: report.api_endpoints.len(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use pretty_assertions::assert_eq;

    use rusi_schema::{
        CallGraph, CryptoComponent, CryptoEvidence, DataFlowPattern, DataFlowPatternSet,
        Declaration, Diagnostic, FileEvidence, Position, SecuritySignal,
    };

    use super::{
        AnalysisScope, AnalyzeOptionsInput, BACKEND_COMPILER, CompilerBackendPayload, analyze,
        analyze_with_optional_compiler,
    };

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rusi-{prefix}-{timestamp}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    fn create_dir_symlink(src: &std::path::Path, dst: &std::path::Path) {
        std::os::unix::fs::symlink(src, dst).expect("create directory symlink");
    }

    #[test]
    fn basic_fixture_collects_source_evidence() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        assert_eq!(report.packages.len(), 1);
        assert!(
            report
                .declarations
                .iter()
                .any(|decl| decl.qualified_name.ends_with("helper::read_secret"))
        );
        assert!(
            report
                .security_signals
                .iter()
                .any(|signal| signal.category == "unsafe-code")
        );
        assert!(
            report
                .usages
                .iter()
                .any(|usage| usage.name.contains("Command::new"))
        );
    }

    #[test]
    fn report_does_not_duplicate_collections_in_files() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // The flattened top-level collections carry the data...
        assert!(!report.usages.is_empty());
        assert!(!report.declarations.is_empty());
        // ...and the per-file copies are cleared to avoid duplicating it.
        for file in &report.files {
            assert!(file.imports.is_empty(), "file imports should be cleared");
            assert!(
                file.declarations.is_empty(),
                "file declarations should be cleared"
            );
            assert!(file.usages.is_empty(), "file usages should be cleared");
            assert!(
                file.security_signals.is_empty(),
                "file security signals should be cleared"
            );
        }
        // File association is still recoverable from each item's file_path.
        assert!(
            report
                .usages
                .iter()
                .all(|usage| !usage.position.filename.is_empty())
        );
    }

    #[test]
    fn report_output_is_deterministic_across_runs() {
        let run = || {
            let report = analyze(AnalyzeOptionsInput {
                dir: fixture_path("vulnerable-web-app"),
                call_graph_mode: "static".to_string(),
                data_flow_mode: "security".to_string(),
                ..AnalyzeOptionsInput::default()
            })
            .expect("analysis succeeds");
            serde_json::to_string(&report).expect("serialize report")
        };
        // The previously non-deterministic fields (auto-discovered passthrough
        // ordering, missing-passthrough diagnostics) are now sorted, so two runs
        // must produce byte-identical output.
        assert_eq!(run(), run());
    }

    #[test]
    fn data_flow_patterns_are_sorted() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("vulnerable-web-app"),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");
        let patterns = report.data_flow.expect("data flow emitted").patterns;
        let key = |p: &DataFlowPattern| {
            (
                p.category.clone(),
                p.target.clone(),
                p.pattern.clone(),
                p.relevant_arguments.clone(),
            )
        };
        for set in [&patterns.sources, &patterns.sinks, &patterns.passthroughs] {
            assert!(
                set.windows(2).all(|w| key(&w[0]) <= key(&w[1])),
                "pattern set must be sorted"
            );
        }
    }

    #[test]
    fn basic_fixture_builds_call_graph_and_dataflow() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let call_graph = report.call_graph.expect("callgraph emitted");
        assert!(
            call_graph
                .edges
                .iter()
                .any(|edge| call_graph.source_name(edge).ends_with("main")
                    && edge.callee_text.as_deref() == Some("basic_app::helper::read_secret"))
        );
        assert!(
            call_graph
                .edges
                .iter()
                .any(|edge| edge.callee_text.as_deref() == Some("basic_app::helper::run_command"))
        );

        let data_flow = report.data_flow.expect("dataflow emitted");
        let matching_slice = data_flow
            .slices
            .iter()
            .find(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
            .expect("matching slice exists");

        assert!(
            matching_slice.node_ids.len() >= 3,
            "Expected path to have at least 3 nodes, got: {:?}",
            matching_slice.node_ids
        );
        assert_eq!(matching_slice.path_length, 2);
    }

    #[test]
    fn multi_file_fixture_links_cross_file_calls() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("multi-file-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.callee_text.as_deref() == Some("multi_file_app::util::compute"))
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.callee_text.as_deref() == Some("render"))
        );
    }

    /// Builds an ambiguous call site: `count` same-named methods on distinct
    /// types, called through a bare method name the resolver cannot pin down.
    fn ambiguous_workspace(count: usize) -> PathBuf {
        let root = temp_dir("fanout");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fanout-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("write Cargo.toml");
        fs::create_dir_all(root.join("src")).expect("create src");
        // The receiver must be genuinely untypeable for the site to stay
        // ambiguous: it comes from a call rusi cannot see the return type of.
        // `pick()` is kept as a locally-resolved call for the companion test.
        let mut source = String::from(
            "fn main() {\n    let _ready = pick();\n    let value = elsewhere::unknown_source();\n    value.render();\n}\n\nfn pick() -> Widget0 {\n    Widget0\n}\n",
        );
        for index in 0..count {
            source.push_str(&format!(
                "pub struct Widget{index};\nimpl Widget{index} {{\n    pub fn render(&self) {{}}\n}}\n"
            ));
        }
        fs::write(root.join("src").join("main.rs"), source).expect("write main.rs");
        root
    }

    fn render_edges(report: &rusi_schema::Report) -> Vec<rusi_schema::CallGraphEdge> {
        report
            .call_graph
            .as_ref()
            .expect("callgraph emitted")
            .edges
            .iter()
            .filter(|edge| edge.method.as_deref() == Some("render"))
            .cloned()
            .collect()
    }

    #[test]
    fn ambiguous_call_sites_are_capped_and_marked() {
        let root = ambiguous_workspace(40);
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            max_call_candidates: 8,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let edges = render_edges(&report);
        assert_eq!(
            edges.len(),
            8,
            "fan-out is capped at the configured ceiling"
        );
        for edge in &edges {
            // The true ambiguity is still reported, so a consumer can tell this
            // is a sample rather than the whole candidate set.
            assert_eq!(edge.candidate_count, Some(40));
            // Presence of the emitted count is what marks the site truncated.
            assert_eq!(edge.emitted_candidate_count, Some(8));
        }
        assert!(
            report
                .call_graph
                .as_ref()
                .expect("callgraph emitted")
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic
                    .message
                    .contains("ambiguous call sites were truncated"))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zero_disables_the_cap() {
        let root = ambiguous_workspace(40);
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            max_call_candidates: 0,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let edges = render_edges(&report);
        assert_eq!(edges.len(), 40);
        assert!(
            edges
                .iter()
                .all(|edge| edge.emitted_candidate_count.is_none())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn capping_is_deterministic_and_does_not_touch_resolved_sites() {
        let root = ambiguous_workspace(40);
        let options = || AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            max_call_candidates: 8,
            ..AnalyzeOptionsInput::default()
        };
        let first = analyze(options()).expect("analysis succeeds");
        let second = analyze(options()).expect("analysis succeeds");

        let names = |report: &rusi_schema::Report| {
            let mut names: Vec<String> = render_edges(report)
                .iter()
                .map(|edge| {
                    report
                        .call_graph
                        .as_ref()
                        .map(|graph| graph.target_name(edge).to_string())
                        .unwrap_or_default()
                })
                .collect();
            names.sort();
            names
        };
        assert_eq!(
            names(&first),
            names(&second),
            "the surviving sample is stable across runs"
        );

        // `pick()` resolves to exactly one target, so it keeps its single
        // uncapped, untruncated edge.
        let pick_edges: Vec<&rusi_schema::CallGraphEdge> = first
            .call_graph
            .as_ref()
            .expect("callgraph emitted")
            .edges
            .iter()
            .filter(|edge| edge.callee_text.as_deref() == Some("pick"))
            .collect();
        assert_eq!(pick_edges.len(), 1);
        assert!(pick_edges[0].emitted_candidate_count.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cfg_evaluation_drops_inactive_code_and_records_active_gates() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cfg-modtree-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let names: Vec<&str> = report
            .declarations
            .iter()
            .map(|declaration| declaration.qualified_name.as_str())
            .collect();

        // Behind a feature Cargo did not resolve: not part of this build.
        assert!(!names.contains(&"cfg_modtree_app::ldap_sink"));
        // `#[cfg(test)]` modules are excluded unless tests are requested.
        assert!(
            !names
                .iter()
                .any(|name| name.contains("tests::") || name.ends_with("::tests"))
        );
        // Behind an enabled feature: kept, and the gate is reported so consumers
        // can qualify the finding.
        let tls_sink = report
            .declarations
            .iter()
            .find(|declaration| declaration.qualified_name == "cfg_modtree_app::tls_sink")
            .expect("enabled feature-gated function is collected");
        assert_eq!(tls_sink.cfg_gate.as_deref(), Some("feature = \"tls\""));
        // An unconditional declaration carries no gate.
        assert!(
            report
                .declarations
                .iter()
                .find(|declaration| declaration.qualified_name == "cfg_modtree_app::main")
                .expect("main is collected")
                .cfg_gate
                .is_none()
        );
    }

    #[test]
    fn module_paths_follow_mod_declarations_rather_than_the_file_layout() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cfg-modtree-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // `#[path = "generated/handlers_v2.rs"] mod handlers;`: the module path
        // is `handlers`, not the `generated::handlers_v2` the file layout
        // suggests.
        assert!(
            report.declarations.iter().any(
                |declaration| declaration.qualified_name == "cfg_modtree_app::handlers::handle"
            )
        );
        assert!(
            !report
                .declarations
                .iter()
                .any(|declaration| declaration.qualified_name.contains("handlers_v2"))
        );

        // A file only a cfg-disabled `mod` declaration would have reached is
        // still reported, but flagged as unreachable rather than silently
        // attributed to an active module path.
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == "module-resolution"
                && diagnostic.file_path.as_deref() == Some("src/platform.rs")
        }));
    }

    /// Writes a fixture crate and returns its root.
    fn fixture_crate(name: &str, source: &str) -> PathBuf {
        let root = temp_dir(name);
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n"
            ),
        )
        .expect("write Cargo.toml");
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::write(root.join("src").join("lib.rs"), source).expect("write lib.rs");
        root
    }

    fn resolved_edges(
        report: &rusi_schema::Report,
        method: &str,
    ) -> Vec<rusi_schema::CallGraphEdge> {
        report
            .call_graph
            .as_ref()
            .expect("callgraph emitted")
            .edges
            .iter()
            .filter(|edge| edge.method.as_deref() == Some(method))
            .cloned()
            .collect()
    }

    #[test]
    fn self_calls_resolve_to_the_impl_type() {
        // Two types define `helper`; a `self.helper()` inside one impl can only
        // mean that impl's method.
        let root = fixture_crate(
            "self-receiver",
            r#"
pub struct Expander<'a> { pub name: &'a str }

impl<'a> Expander<'a> {
    pub fn expand(&mut self) { self.helper(); }
    pub fn helper(&mut self) {}
}

pub struct Other;
impl Other {
    pub fn helper(&self) {}
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "helper");
        assert_eq!(edges.len(), 1, "self.helper() must resolve to one target");
        assert_eq!(edges[0].call_type, "receiver-typed");
        assert!(
            graph.target_name(&edges[0]).contains("Expander"),
            "resolved to {}",
            graph.target_name(&edges[0])
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn field_receivers_resolve_through_declared_field_types() {
        let root = fixture_crate(
            "field-receiver",
            r#"
pub struct Sink;
impl Sink {
    pub fn emit(&self) {}
}

pub struct Decoy;
impl Decoy {
    pub fn emit(&self) {}
}

pub struct Holder { pub sink: Sink }

impl Holder {
    pub fn run(&self) { self.sink.emit(); }
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "emit");
        assert_eq!(
            edges.len(),
            1,
            "self.sink.emit() must resolve to one target"
        );
        assert!(graph.target_name(&edges[0]).contains("Sink::emit"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dependency_call_is_external_until_dependencies_are_analyzed() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("deps-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text.as_deref() == Some("dep_helper_lib::run_command"))
            .expect("the dependency call is recorded");
        assert_eq!(edge.call_type, "external");
        assert_eq!(report.packages.len(), 1, "only the workspace is analyzed");
    }

    #[test]
    fn dependency_analysis_resolves_calls_into_dependencies() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("deps-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_dependencies: true,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text.as_deref() == Some("dep_helper_lib::run_command"))
            .expect("the dependency call is recorded");
        assert_eq!(
            edge.call_type, "static",
            "the call should resolve into the dependency"
        );
        assert!(graph.target_name(edge).ends_with("::run_command"));

        // The dependency is reported as a package, marked as not a workspace
        // member so a consumer can tell whose code it is.
        let dependency = report
            .packages
            .iter()
            .find(|package| package.name == "dep-helper-lib")
            .expect("the dependency package is reported");
        assert!(!dependency.module.workspace_member);

        // At this tier the dependency contributes declarations but no bodies, so
        // workspace taint findings are unchanged rather than swallowed by a
        // body-less summary.
        let workspace_only = analyze(AnalyzeOptionsInput {
            dir: fixture_path("deps-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("workspace analysis succeeds");
        assert_eq!(
            report.data_flow.as_ref().map(|flow| flow.slices.len()),
            workspace_only
                .data_flow
                .as_ref()
                .map(|flow| flow.slices.len()),
            "the lighter dependency tier must not change workspace flows"
        );
    }

    #[test]
    fn security_deps_carries_taint_through_a_dependency() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("deps-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: crate::DATAFLOW_SECURITY_DEPS.to_string(),
            include_dependencies: true,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        // `main` reads an env var and hands it to a function that lives in the
        // dependency, which execs it. The flow only exists if the dependency's
        // body was analyzed and summarized.
        assert!(
            data_flow.slices.iter().any(|slice| {
                slice.source_category == "env" && slice.sink_category == "process-exec"
            }),
            "expected an env -> process-exec flow through the dependency, got {:?}",
            data_flow
                .slices
                .iter()
                .map(|slice| (&slice.source_category, &slice.sink_category))
                .collect::<Vec<_>>()
        );
        assert!(
            data_flow.summaries.iter().any(|summary| {
                summary.function.starts_with("dep_helper_lib::")
                    && summary.param_to_sink.contains_key("process-exec")
            }),
            "expected a dependency-side sink summary"
        );
    }

    #[test]
    fn dependency_bins_and_tests_are_not_analyzed() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("deps-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            include_dependencies: true,
            include_tests: true,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // A dependency ships only its library into this build.
        let dependency_files: Vec<&str> = report
            .packages
            .iter()
            .filter(|package| !package.module.workspace_member)
            .flat_map(|package| package.files.iter().map(String::as_str))
            .collect();
        assert!(
            !dependency_files.is_empty(),
            "the dependency should contribute files"
        );
        assert!(
            dependency_files
                .iter()
                .all(|path| !path.contains("/bin/") && !path.contains("tests/")),
            "dependency bins and tests must be skipped, got {dependency_files:?}"
        );
    }

    #[test]
    fn a_type_annotated_let_still_propagates_taint() {
        let root = fixture_crate(
            "annotated-let",
            r#"
pub fn annotated() {
    let secret: String = std::env::var("TOKEN").unwrap_or_default();
    let _ = std::process::Command::new(secret);
}
pub fn unannotated() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    let _ = std::process::Command::new(secret);
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // `let x: T = ..` wraps the pattern in `Pat::Type`, which used to match
        // no branch at all: the binding recorded nothing and taint stopped
        // there, so only the unannotated twin was reported.
        let data_flow = report.data_flow.expect("dataflow emitted");
        let functions: std::collections::BTreeSet<&str> = data_flow
            .slices
            .iter()
            .filter(|slice| slice.sink_category == "process-exec")
            .map(|slice| slice.sink_function.as_str())
            .collect();
        assert!(
            functions.iter().any(|name| name.ends_with("::annotated")),
            "an annotated binding must propagate taint, got {functions:?}"
        );
        assert!(functions.iter().any(|name| name.ends_with("::unannotated")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_annotation_outranks_inference() {
        let root = fixture_crate(
            "annotation-priority",
            r#"
pub struct Real;
impl Real { pub fn act(&self) {} }
pub struct Other;
impl Other { pub fn act(&self) {} }

pub fn make() -> Other { Other }

pub fn run() {
    // The annotation contradicts what the initializer would suggest; the
    // written type is the one that holds.
    let value: Real = unsafe { std::mem::transmute(make()) };
    value.act();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "act");
        assert_eq!(edges.len(), 1);
        assert!(
            graph.target_name(&edges[0]).ends_with("Real::act"),
            "resolved to {}",
            graph.target_name(&edges[0])
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_known_receiver_type_with_no_local_impl_is_external() {
        let root = fixture_crate(
            "std-receiver",
            r#"
pub struct Remap;
impl Remap { pub fn push(&mut self, value: u32) { let _ = value; } }
pub struct TypeList;
impl TypeList { pub fn push(&mut self, value: u32) { let _ = value; } }

pub fn run() {
    let mut nodes = Vec::new();
    nodes.push(1u32);
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let push_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.method.as_deref() == Some("push"))
            .collect();
        // `Vec::push` cannot reach a local `push`; claiming it can asserts a
        // call the program cannot make.
        assert_eq!(push_edges.len(), 1, "expected a single external edge");
        assert_eq!(push_edges[0].call_type, "external");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_blanket_impl_still_applies_to_a_std_receiver() {
        let root = fixture_crate(
            "blanket-impl",
            r#"
pub trait Ext { fn shout(&self); }
impl<T> Ext for T { fn shout(&self) {} }

pub fn run() {
    let nodes: Vec<u32> = Vec::new();
    nodes.shout();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // A blanket impl's self type is a generic parameter, so it applies to
        // any receiver — including one whose type has no local impl.
        let edges = resolved_edges(&report, "shout");
        assert_eq!(edges.len(), 1, "the blanket impl must still resolve");
        assert_eq!(edges[0].call_type, "trait-impl");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dyn_trait_receiver_dispatches_to_the_traits_impls() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("dyn-dispatch-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // `&dyn Store` reduces to the trait name; the call dispatches to the
        // trait's impls, not to an impl of a type named `Store`.
        let edges = resolved_edges(&report, "persist");
        assert_eq!(edges.len(), 2, "expected both Store impls");
        for edge in &edges {
            assert_eq!(edge.call_type, "trait-overapprox");
        }
    }

    #[test]
    fn result_and_option_returns_are_typed_through_the_wrapper() {
        let root = fixture_crate(
            "wrapper-typing",
            r#"
pub struct Client;
impl Client { pub fn query(&self, sql: &str) { let _ = sql; } }
pub struct Decoy;
impl Decoy { pub fn query(&self, sql: &str) { let _ = sql; } }

pub fn connect() -> Result<Client, std::io::Error> { Ok(Client) }
pub fn maybe() -> Option<Client> { Some(Client) }

pub fn via_question() -> Result<(), std::io::Error> {
    let client = connect()?;
    client.query("a");
    Ok(())
}
pub fn via_unwrap() {
    connect().unwrap().query("b");
}
pub fn via_expect() {
    maybe().expect("present").query("c");
}
pub fn via_clone() {
    let client = connect().unwrap().clone();
    client.query("d");
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "query");
        assert_eq!(edges.len(), 4, "every wrapper shape should resolve");
        for edge in &edges {
            assert_eq!(edge.call_type, "receiver-typed");
            assert!(
                graph.target_name(edge).ends_with("Client::query"),
                "resolved to {}",
                graph.target_name(edge)
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn receiver_typed_sinks_are_reached_through_a_wrapper_function() {
        let root = fixture_crate(
            "receiver-typed-sink-summary",
            r#"
use std::process::Command;

// The sink is a method call in a callee, so it is only found if the
// interprocedural summary pass evaluates receiver-typed patterns too.
pub fn add_argument(command: &mut Command, value: String) {
    command.arg(value);
}

pub fn exec_tainted() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    let mut command = Command::new("sh");
    add_argument(&mut command, secret);
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(
                |slice| slice.source_category == "env" && slice.sink_category == "process-exec"
            ),
            "expected env -> process-exec through the wrapper, got {:?}",
            data_flow
                .slices
                .iter()
                .map(|slice| (&slice.source_category, &slice.sink_category))
                .collect::<Vec<_>>()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unwrapping_an_option_binding_does_not_type_the_call_as_option() {
        // `Option` is a known std type, so typing `held.unwrap()` as `Option`
        // used to conclude that the following call left the crate entirely.
        assert_eq!(
            crate::infer_expr_type(
                &crate::SimpleExpr::MethodCall {
                    method: "unwrap".to_string(),
                    receiver: Box::new(crate::SimpleExpr::Var("held".to_string())),
                    args: Vec::new(),
                    position: Position::default(),
                },
                &std::collections::HashMap::from([("held".to_string(), "Option".to_string())]),
                &std::collections::HashMap::new(),
                &crate::ReturnTypeIndex::default(),
            ),
            None
        );
        // An already-unwrapped receiver type still carries through.
        assert_eq!(
            crate::infer_expr_type(
                &crate::SimpleExpr::MethodCall {
                    method: "unwrap".to_string(),
                    receiver: Box::new(crate::SimpleExpr::Var("held".to_string())),
                    args: Vec::new(),
                    position: Position::default(),
                },
                &std::collections::HashMap::from([("held".to_string(), "Client".to_string())]),
                &std::collections::HashMap::new(),
                &crate::ReturnTypeIndex::default(),
            )
            .as_deref(),
            Some("Client")
        );
    }

    #[test]
    fn receiver_typed_sinks_fire_only_for_the_right_receiver() {
        let root = fixture_crate(
            "receiver-typed-sink",
            r#"
use std::process::Command;

// Our own builder that also has `arg`.
pub struct Query;
impl Query { pub fn arg(&self, value: String) -> &Self { let _ = value; self } }

pub fn exec_tainted() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    let mut command = Command::new("sh");
    command.arg(secret);
}

pub fn unrelated_builder() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    let query = Query;
    query.arg(secret);
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let exec_slices: Vec<_> = data_flow
            .slices
            .iter()
            .filter(|slice| slice.sink_category == "process-exec")
            .collect();
        // `Command::new(x).arg(tainted)` is the common injection shape and used
        // to be missed entirely, because only the constructor argument matched.
        assert_eq!(
            exec_slices.len(),
            1,
            "expected exactly one process-exec flow"
        );
        assert!(exec_slices[0].sink_function.ends_with("exec_tainted"));
        // Matching on the bare method name would have flagged our own builder
        // too; the receiver-type restriction is what prevents that.
        assert!(
            !data_flow
                .slices
                .iter()
                .any(|slice| slice.sink_function.ends_with("unrelated_builder")),
            "a same-named method on another type must not be a sink"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_typed_file_handle_is_a_filesystem_sink() {
        let root = fixture_crate(
            "file-sink",
            r#"
use std::io::Write;

pub fn write_tainted() -> std::io::Result<()> {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    let mut file = std::fs::File::create("/tmp/rusi-test")?;
    file.write_all(secret.as_bytes())?;
    Ok(())
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // Requires `File::create` to be typed through its `Result`, so the
        // receiver-typed `File::write_all` sink can match.
        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(|slice| {
                slice.source_category == "env" && slice.sink_category == "filesystem-write"
            }),
            "expected env -> filesystem-write, got {:?}",
            data_flow
                .slices
                .iter()
                .map(|slice| (&slice.source_category, &slice.sink_category))
                .collect::<Vec<_>>()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn calls_inside_macro_arguments_are_visible() {
        let root = fixture_crate(
            "macro-arguments",
            r#"
pub struct Secrets;
impl Secrets {
    pub fn token(&self) -> String { String::new() }
}

pub fn run() {
    use std::fmt::Write as _;
    let secrets = Secrets;
    let mut buffer = String::new();
    let _ = write!(buffer, "{}", secrets.token());
    println!("{}", secrets.token());
    assert!(!secrets.token().is_empty());
    let _items = vec![secrets.token()];
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // Four macro invocations each call `token()`; every one of them used to
        // be invisible, because a macro's token stream was never walked.
        let edges = resolved_edges(&report, "token");
        assert_eq!(
            edges.len(),
            4,
            "expected one edge per macro argument call, got {}",
            edges.len()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn macro_rules_definitions_are_not_treated_as_code() {
        let root = fixture_crate(
            "macro-rules-skip",
            r#"
macro_rules! never_here {
    () => { danger() };
}

pub fn danger() {}

pub fn run() {}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // A definition body is a transcriber, not code at that location, so it
        // must not produce a call attributed to the defining module.
        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        assert!(
            graph
                .edges
                .iter()
                .all(|edge| !graph.target_name(edge).ends_with("::danger")),
            "a macro_rules body must not become a call"
        );
        // The blind spot is reported rather than left silent.
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "macro"
                    && diagnostic.message.contains("macro_rules!"))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn static_ref_macro_bodies_are_recovered() {
        let root = fixture_crate(
            "static-ref-macro",
            r#"
pub struct Client;
impl Client {
    pub fn new(url: &str) -> Self { let _ = url; Client }
}

lazy_static::lazy_static! {
    static ref SHARED: Client = Client::new("https://example.invalid");
}

pub fn run() { let _ = &*SHARED; }
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // `static ref` is not valid Rust, so the body only parses after that one
        // token is normalized away. The initializer's call is then evidence.
        assert!(
            report
                .usages
                .iter()
                .any(|usage| usage.name == "Client::new"),
            "the static initializer's call should be recorded"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_qualified_external_path_does_not_match_a_local_name() {
        let root = fixture_crate(
            "qualified-external",
            r#"
pub struct Holder;
impl Holder {
    pub fn new() -> Self { Holder }
}

pub fn run() {
    // Two external constructors that share their last segment with the local
    // `Holder::new`.
    let _values: Vec<u8> = Vec::new();
    let _boxed = Box::new(1u8);
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        for edge in &graph.edges {
            let callee = edge.callee_text.as_deref().unwrap_or_default();
            if callee == "Vec::new" || callee == "Box::new" {
                assert_eq!(
                    edge.call_type,
                    "external",
                    "{callee} must stay external, resolved to {}",
                    graph.target_name(edge)
                );
            }
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_bindings_take_the_callee_return_type() {
        let root = fixture_crate(
            "return-type-binding",
            r#"
pub struct Client;
impl Client {
    pub fn send(&self) {}
}

pub struct Decoy;
impl Decoy {
    pub fn send(&self) {}
}

pub fn connect() -> Client { Client }

pub fn run() {
    let client = connect();
    client.send();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "send");
        assert_eq!(
            edges.len(),
            1,
            "`let client = connect()` must type `client`"
        );
        assert!(graph.target_name(&edges[0]).contains("Client::send"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn method_chains_resolve_through_return_types() {
        let root = fixture_crate(
            "return-type-chain",
            r#"
pub struct Builder;
pub struct Request;
pub struct Decoy;

impl Builder {
    pub fn build(&self) -> Request { Request }
}

impl Request {
    pub fn dispatch(&self) {}
}

impl Decoy {
    pub fn dispatch(&self) {}
}

pub fn start() -> Builder { Builder }

pub fn run() {
    start().build().dispatch();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        // `start()` -> Builder, `.build()` -> Request, so `.dispatch()` is
        // Request's, not the same-named method on `Decoy`.
        let edges = resolved_edges(&report, "dispatch");
        assert_eq!(edges.len(), 1, "the chain's receiver must be typed");
        assert!(
            graph.target_name(&edges[0]).contains("Request::dispatch"),
            "resolved to {}",
            graph.target_name(&edges[0])
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn conflicting_return_types_stay_unresolved() {
        let root = fixture_crate(
            "return-type-conflict",
            r#"
pub struct Left;
pub struct Right;

impl Left {
    pub fn act(&self) {}
}
impl Right {
    pub fn act(&self) {}
}

pub mod first {
    pub fn make() -> crate::Left { crate::Left }
}
pub mod second {
    pub fn make() -> crate::Right { crate::Right }
}

pub fn run() {
    let value = make();
    value.act();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // Two `make`s with different return types: guessing one would type the
        // binding wrongly, so the bare name is not indexed and the call site
        // stays an honest over-approximation.
        let edges = resolved_edges(&report, "act");
        assert_eq!(
            edges.len(),
            2,
            "an ambiguous return type must not be guessed"
        );
        for edge in &edges {
            assert!(edge.call_type.ends_with("overapprox"));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn smart_pointer_receivers_resolve_to_the_pointee() {
        let root = fixture_crate(
            "autoderef-receiver",
            r#"
use std::sync::Arc;

pub struct Client;
impl Client {
    pub fn send(&self) {}
}

pub struct Decoy;
impl Decoy {
    pub fn send(&self) {}
}

pub fn dispatch(client: &Arc<Client>) {
    client.send();
}
"#,
        );
        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let edges = resolved_edges(&report, "send");
        assert_eq!(
            edges.len(),
            1,
            "&Arc<Client> receiver must resolve through the wrapper"
        );
        assert!(graph.target_name(&edges[0]).contains("Client::send"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn edges_are_normalized_against_their_nodes() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        assert!(!graph.edges.is_empty());
        for edge in &graph.edges {
            // Every endpoint must exist as a node: that is what makes dropping
            // the duplicated name/purl/file fields from edges lossless.
            let source = graph
                .node(&edge.source_id)
                .unwrap_or_else(|| panic!("source node missing for edge {}", edge.id));
            assert!(
                graph.node(&edge.target_id).is_some(),
                "target node missing for edge {}",
                edge.id
            );
            assert_eq!(graph.source_name(edge), source.qualified_name);
            // The call site is in the caller's file.
            assert_eq!(graph.call_site_file(edge), source.file_path);
            assert!(edge.line > 0 && edge.column > 0);
        }
    }

    #[test]
    fn identities_are_unique_within_a_report() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("dyn-dispatch-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.as_ref().expect("callgraph emitted");
        let mut edge_ids = std::collections::HashSet::new();
        for edge in &graph.edges {
            assert!(
                edge_ids.insert(edge.id.as_str()),
                "duplicate call-graph edge id {}",
                edge.id
            );
        }
        let mut declaration_ids = std::collections::HashSet::new();
        for declaration in &report.declarations {
            assert!(
                declaration_ids.insert(declaration.id.as_str()),
                "duplicate declaration id {} ({})",
                declaration.id,
                declaration.qualified_name
            );
        }
    }

    #[test]
    fn impl_method_bodies_are_analyzed_once() {
        let root = temp_dir("impl-body-once");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"impl-body\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("write Cargo.toml");
        fs::create_dir_all(root.join("src")).expect("create src");
        // A nested item and a nested `fn` inside an impl method body: walking
        // the body twice used to record both again, and re-emit the nested
        // function's calls under the same declaration id.
        fs::write(
            root.join("src").join("lib.rs"),
            r#"
pub struct Holder;

impl Holder {
    pub fn work(&self) -> u32 {
        enum Inner { A }
        fn nested(value: u32) -> u32 {
            value.count_ones()
        }
        let _ = Inner::A;
        nested(7)
    }
}
"#,
        )
        .expect("write lib.rs");

        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let inner_count = report
            .declarations
            .iter()
            .filter(|declaration| declaration.qualified_name.ends_with("::Inner"))
            .count();
        assert_eq!(inner_count, 1, "item in an impl method body recorded twice");
        let nested_count = report
            .declarations
            .iter()
            .filter(|declaration| declaration.qualified_name.ends_with("::nested"))
            .count();
        assert_eq!(nested_count, 1, "fn in an impl method body recorded twice");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trait_impls_of_one_type_get_distinct_identities() {
        let root = temp_dir("trait-impl-identity");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"trait-identity\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("write Cargo.toml");
        fs::create_dir_all(root.join("src")).expect("create src");
        // Same type, same method name, same signature — only the trait differs.
        fs::write(
            root.join("src").join("lib.rs"),
            r#"
pub trait Section { fn id(&self) -> u8; }
pub trait ComponentSection { fn id(&self) -> u8; }

pub struct Holder;

impl Section for Holder {
    fn id(&self) -> u8 { 1 }
}

impl ComponentSection for Holder {
    fn id(&self) -> u8 { 2 }
}
"#,
        )
        .expect("write lib.rs");

        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let ids: std::collections::HashSet<&str> = report
            .declarations
            .iter()
            .filter(|declaration| declaration.kind == "method")
            .map(|declaration| declaration.id.as_str())
            .collect();
        assert_eq!(ids.len(), 2, "the two trait impls must not share one id");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn each_cargo_target_roots_its_own_qualified_names() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("multi-target-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        // Every bin target is a separate crate, so the two crate-root `main`s
        // and `run`s must not share qualified names — and therefore must not
        // share declaration ids.
        let names: std::collections::BTreeSet<&str> = report
            .declarations
            .iter()
            .map(|declaration| declaration.qualified_name.as_str())
            .collect();
        assert!(names.contains("first::main"), "got {names:?}");
        assert!(names.contains("second::main"), "got {names:?}");
        assert!(names.contains("first::run"));
        assert!(names.contains("second::run"));
        assert!(names.contains("multi_target_app::shared_helper"));

        let mut files_per_id: std::collections::HashMap<&str, std::collections::BTreeSet<&str>> =
            std::collections::HashMap::new();
        for declaration in &report.declarations {
            files_per_id
                .entry(declaration.id.as_str())
                .or_default()
                .insert(declaration.file_path.as_str());
        }
        let colliding: Vec<_> = files_per_id
            .iter()
            .filter(|(_, files)| files.len() > 1)
            .collect();
        assert!(
            colliding.is_empty(),
            "declaration ids must not span files: {colliding:?}"
        );

        // The owning package is still the package, so purl resolution and
        // grouping are unaffected by the per-target crate root.
        for declaration in &report.declarations {
            assert_eq!(declaration.package_path, "multi_target_app");
        }
    }

    #[test]
    fn glob_and_reexport_imports_resolve_to_the_declaring_module() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cfg-modtree-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        let callee_texts: Vec<&str> = graph
            .edges
            .iter()
            .filter(|edge| graph.source_name(edge) == "cfg_modtree_app::main")
            .filter_map(|edge| edge.callee_text.as_deref())
            .collect();

        // Called through `use crate::sinks::*`.
        assert!(callee_texts.contains(&"cfg_modtree_app::sinks::glob_sink"));
        // Called through `pub use crate::facade::inner::run_facade_sink`, and
        // resolved past the facade to the module that declares it.
        assert!(callee_texts.contains(&"cfg_modtree_app::facade::inner::run_facade_sink"));
    }

    #[test]
    fn expanded_fixture_emits_filesystem_and_network_slices() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("expanded-packs-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow
                .patterns
                .sources
                .iter()
                .any(|pattern| pattern.category == "cli")
        );
        assert!(
            data_flow
                .patterns
                .sources
                .iter()
                .any(|pattern| pattern.category == "file")
        );
        assert!(
            data_flow
                .patterns
                .sinks
                .iter()
                .any(|pattern| pattern.category == "filesystem-write")
        );
        assert!(
            data_flow
                .patterns
                .sinks
                .iter()
                .any(|pattern| pattern.category == "network-connect")
        );
        assert!(data_flow.slices.iter().any(
            |slice| slice.source_category == "cli" && slice.sink_category == "filesystem-write"
        ));
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "file"
                    && slice.sink_category == "filesystem-write")
        );
        assert!(data_flow.slices.iter().any(
            |slice| slice.source_category == "env" && slice.sink_category == "network-connect"
        ));
        assert!(data_flow.summaries.iter().any(|summary| {
            summary.function.ends_with("io_helpers::load_payload")
                && summary
                    .source_returns
                    .iter()
                    .any(|category| category == "file")
        }));
    }

    #[test]
    fn vulnerable_web_fixture_emits_sql_ssrf_and_html_slices() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("vulnerable-web-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.callee_text.as_deref() == Some("sqlx::query"))
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.callee_text.as_deref() == Some("post"))
        );

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "file" && slice.sink_category == "sql-query")
        );
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "http-request"
                    && slice.sink_category == "network-request")
        );
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "http-request"
                    && slice.sink_category == "html-response")
        );
    }

    #[test]
    fn sanitized_web_fixture_suppresses_html_response_slice() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("sanitized-web-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            !data_flow
                .slices
                .iter()
                .any(|slice| slice.sink_category == "html-response")
        );
    }

    #[test]
    fn http_framework_zoo_emits_handler_flows() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("http-framework-zoo-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        for function_name in [
            "actix_handler",
            "axum_handler",
            "poem_handler",
            "salvo_handler",
            "rocket_handler",
            "tide_handler",
            "iron_handler",
            "gotham_handler",
            "rouille_handler",
            "ntex_handler",
            "dropshot_handler",
            "thruster_handler",
            "nickel_handler",
            "hyper_handler",
        ] {
            assert!(
                data_flow.slices.iter().any(|slice| {
                    slice.sink_category == "html-response"
                        && slice.sink_function.contains(function_name)
                        && slice.source_category == "http-request"
                }),
                "missing flow for {function_name}"
            );
        }
    }

    #[test]
    fn sql_zoo_emits_multi_library_sql_slices() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("sql-zoo-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        for function_name in [
            "sqlx_flow",
            "diesel_flow",
            "postgres_flow",
            "tokio_postgres_flow",
            "rusqlite_flow",
            "mysql_flow",
            "mysql_async_flow",
            "tiberius_flow",
            "sea_orm_flow",
        ] {
            assert!(
                data_flow.slices.iter().any(|slice| {
                    slice.source_category == "file"
                        && slice.sink_category == "sql-query"
                        && slice.sink_function.contains(function_name)
                }),
                "missing SQL flow for {function_name}"
            );
        }
    }

    #[test]
    fn sql_sanitized_fixture_suppresses_sql_flows() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("sql-sanitized-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            !data_flow
                .slices
                .iter()
                .any(|slice| slice.sink_category == "sql-query")
        );
    }

    #[test]
    fn sql_generic_methods_fixture_suppresses_false_positive_sql_flows() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("sql-generic-methods-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            !data_flow
                .slices
                .iter()
                .any(|slice| slice.sink_category == "sql-query")
        );
    }

    #[test]
    fn real_cbom_fixture_emits_crypto_evidence() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cbom-real-crates-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let crypto = report.crypto.expect("crypto evidence emitted");
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "sha2")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "aes_gcm")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "argon2")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "jsonwebtoken")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "rustls")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "SHA-256")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "AES-GCM")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "Argon2")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.provider == "pbkdf2")
        );
        assert!(
            crypto
                .materials
                .iter()
                .any(|material| material.kind == "key")
        );
        assert!(
            crypto
                .findings
                .iter()
                .any(|finding| finding.category == "weak-crypto")
        );
    }

    #[test]
    fn modern_cbom_fixture_emits_chacha_and_sha1_evidence() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cbom-real-modern-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let crypto = report.crypto.expect("crypto evidence emitted");
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "chacha20poly1305")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "ring")
        );
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "sha1")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "ChaCha20-Poly1305")
        );
        assert!(
            crypto
                .findings
                .iter()
                .any(|finding| finding.summary.contains("SHA-1 usage"))
        );
    }

    #[test]
    fn asymmetric_cbom_fixture_emits_ring_rsa_and_ed25519_evidence() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cbom-real-asymmetric-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let crypto = report.crypto.expect("crypto evidence emitted");
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "ring")
        );
        assert!(crypto.libraries.iter().any(|library| library.path == "rsa"));
        assert!(
            crypto
                .libraries
                .iter()
                .any(|library| library.path == "ed25519_dalek")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "Ring-AEAD")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "RSA")
        );
        assert!(
            crypto
                .components
                .iter()
                .any(|component| component.algorithm == "Ed25519")
        );
    }

    #[test]
    fn report_enriches_callgraph_edges_and_slices_with_purls() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        let node = graph
            .nodes
            .iter()
            .find(|node| node.qualified_name.ends_with("main"))
            .expect("callgraph node exists");
        assert!(node.purl.starts_with("pkg:cargo/"));
        // An edge's endpoint purls live on the nodes it references.
        let edge = graph
            .edges
            .iter()
            .find(|edge| graph.source_name(edge).ends_with("main"))
            .expect("callgraph edge exists");
        assert!(
            graph
                .node(&edge.source_id)
                .expect("source node exists")
                .purl
                .starts_with("pkg:cargo/")
        );
        assert!(graph.node(&edge.target_id).is_some());

        let data_flow = report.data_flow.expect("dataflow emitted");
        let source_node = data_flow
            .nodes
            .iter()
            .find(|node| node.source && node.category == "env")
            .expect("source dataflow node exists");
        assert!(source_node.purl.starts_with("pkg:cargo/"));
        let slice = data_flow
            .slices
            .iter()
            .find(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
            .expect("env to process slice exists");
        assert!(slice.source_purl.starts_with("pkg:cargo/"));
        assert!(slice.target_purl.starts_with("pkg:cargo/"));
        assert!(!slice.purls.is_empty());
    }

    #[test]
    fn report_records_selected_backend() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            backend: BACKEND_COMPILER.to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        assert_eq!(report.options.backend, BACKEND_COMPILER);
    }

    #[test]
    fn compiler_payload_is_merged_into_report_diagnostics() {
        let compiler_payload = CompilerBackendPayload {
            diagnostics: vec![Diagnostic {
                kind: "backend".to_string(),
                message: "compiler backend scaffold selected for fixture".to_string(),
                package_path: None,
                file_path: None,
                position: Some(Position {
                    filename: fixture_path("basic-app").display().to_string(),
                    line: 0,
                    column: 0,
                }),
            }],
            files: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            crypto: None,
            call_graph: Some(CallGraph::default()),
            data_flow: None,
        };

        let report = analyze_with_optional_compiler(
            AnalyzeOptionsInput {
                include_dependencies: false,
                max_call_candidates: crate::DEFAULT_MAX_CALL_CANDIDATES,
                dir: fixture_path("basic-app"),
                backend: BACKEND_COMPILER.to_string(),
                analysis_scope: AnalysisScope::Default,
                call_graph_mode: "static".to_string(),
                data_flow_mode: "security".to_string(),
                custom_data_flow_patterns: None,
                include_tests: false,
                debug: false,
            },
            Some(compiler_payload),
        )
        .expect("analysis succeeds");

        assert_eq!(report.options.backend, BACKEND_COMPILER);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "backend")
        );
        assert!(report.call_graph.is_some());
        assert!(report.data_flow.is_some());
    }

    #[test]
    fn compiler_payload_merges_source_evidence_into_report() {
        let compiler_payload = CompilerBackendPayload {
            diagnostics: Vec::new(),
            files: vec![FileEvidence {
                path: "src/helper.rs".to_string(),
                package_name: "basic_app".to_string(),
                package_path: "basic_app".to_string(),
                purl: String::new(),
                imports: Vec::new(),
                declarations: Vec::new(),
                usages: Vec::new(),
                security_signals: Vec::new(),
                crypto: None,
            }],
            imports: Vec::new(),
            declarations: vec![Declaration {
                cfg_gate: None,
                id: "decl-compiler-test".to_string(),
                name: "read_secret".to_string(),
                qualified_name: "basic_app::helper::read_secret".to_string(),
                canonical_name: "basic_app::helper::read_secret".to_string(),
                kind: "function".to_string(),
                package_path: "basic_app".to_string(),
                purl: String::new(),
                file_path: "src/helper.rs".to_string(),
                signature: "fn read_secret() -> String".to_string(),
                receiver: None,
                position: Position {
                    filename: "src/helper.rs".to_string(),
                    line: 1,
                    column: 1,
                },
            }],
            usages: Vec::new(),
            security_signals: vec![SecuritySignal {
                cfg_gate: None,
                id: "signal-compiler-test".to_string(),
                category: "unsafe-code".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                description: "compiler source evidence detected unsafe code".to_string(),
                package_path: "basic_app".to_string(),
                purl: String::new(),
                file_path: "src/helper.rs".to_string(),
                position: Position {
                    filename: "src/helper.rs".to_string(),
                    line: 9,
                    column: 1,
                },
            }],
            crypto: Some(CryptoEvidence {
                components: vec![CryptoComponent {
                    id: "crypto-component-compiler-test".to_string(),
                    kind: "hash".to_string(),
                    algorithm: "SHA-256".to_string(),
                    provider: "sha2".to_string(),
                    operation: "digest".to_string(),
                    symbol: "sha2::Sha256::digest".to_string(),
                    package_path: "basic_app".to_string(),
                    file_path: "src/helper.rs".to_string(),
                    position: Position {
                        filename: "src/helper.rs".to_string(),
                        line: 1,
                        column: 1,
                    },
                    properties: Default::default(),
                }],
                ..CryptoEvidence::default()
            }),
            call_graph: None,
            data_flow: None,
        };

        let report = analyze_with_optional_compiler(
            AnalyzeOptionsInput {
                include_dependencies: false,
                max_call_candidates: crate::DEFAULT_MAX_CALL_CANDIDATES,
                dir: fixture_path("basic-app"),
                backend: BACKEND_COMPILER.to_string(),
                analysis_scope: AnalysisScope::Default,
                call_graph_mode: "static".to_string(),
                data_flow_mode: "security".to_string(),
                custom_data_flow_patterns: None,
                include_tests: false,
                debug: false,
            },
            Some(compiler_payload),
        )
        .expect("analysis succeeds");

        assert!(
            report
                .declarations
                .iter()
                .any(|declaration| declaration.id == "decl-compiler-test")
        );
        assert!(report.files.iter().any(|file| file.path == "src/helper.rs"));
        assert!(
            report
                .security_signals
                .iter()
                .any(|signal| signal.id == "signal-compiler-test")
        );
        assert!(report.crypto.as_ref().is_some_and(|crypto| {
            crypto
                .components
                .iter()
                .any(|component| component.id == "crypto-component-compiler-test")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_directories_are_skipped_during_file_discovery() {
        let root = temp_dir("symlink-root");
        let outside = temp_dir("symlink-outside");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"symlink-skip\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write Cargo.toml");
        let outside_src = outside.join("src");
        fs::create_dir_all(&outside_src).expect("create outside src");
        fs::write(outside_src.join("main.rs"), "fn main() {}\n").expect("write external main.rs");
        create_dir_symlink(&outside_src, &root.join("src"));

        let report = analyze(AnalyzeOptionsInput {
            dir: root.clone(),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        assert!(report.files.is_empty());
        assert!(report.declarations.is_empty());
        assert!(
            report
                .packages
                .iter()
                .all(|package| package.files.is_empty())
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn custom_patterns_are_merged_into_data_flow() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            custom_data_flow_patterns: Some(DataFlowPatternSet {
                sources: vec![DataFlowPattern {
                    target: String::new(),
                    pattern: "helper::read_secret".to_string(),
                    category: "custom-source".to_string(),
                    relevant_arguments: vec![],
                    receiver_type: None,
                }],
                sinks: vec![DataFlowPattern {
                    target: String::new(),
                    pattern: "helper::run_command".to_string(),
                    category: "custom-command".to_string(),
                    relevant_arguments: vec![0],
                    receiver_type: None,
                }],
                passthroughs: Vec::new(),
            }),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow
                .patterns
                .sources
                .iter()
                .any(|pattern| pattern.category == "custom-source")
        );
        assert!(
            data_flow
                .patterns
                .sinks
                .iter()
                .any(|pattern| pattern.category == "custom-command")
        );
        assert!(data_flow.slices.iter().any(|slice| {
            slice.source_category == "custom-source" && slice.sink_category == "custom-command"
        }));
    }

    #[test]
    fn cryptos_scope_filters_reports_to_crypto_related_flows() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("async-crypto-app"),
            analysis_scope: AnalysisScope::Cryptos,
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        assert_eq!(report.options.analysis_scope, "cryptos");
        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(!data_flow.slices.is_empty(), "expected crypto slices");
        assert!(data_flow.slices.iter().all(|slice| {
            slice.sink_category.starts_with("crypto")
                || matches!(slice.sink_category.as_str(), "jwt" | "certificate" | "tls")
        }));

        let graph = report.call_graph.expect("callgraph emitted");
        assert!(graph.nodes.iter().any(|node| {
            node.qualified_name.contains("encryptor") || node.qualified_name.contains("main")
        }));
    }

    #[test]
    fn api_discovery_fixture_emits_endpoints_across_frameworks() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("api-discovery-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("api-discovery fixture analyzes cleanly");

        // The fixture is constructed to land exactly these endpoints, one
        // per (method, path, framework). If the assertion fires, look at
        // the diff to decide whether the fixture grew or the discovery
        // pass regressed.
        let mut summary: Vec<String> = report
            .api_endpoints
            .iter()
            .map(|endpoint| {
                format!(
                    "{} {} {} :: {}",
                    endpoint.framework,
                    endpoint.method,
                    endpoint.path,
                    endpoint
                        .handler
                        .rsplit("::")
                        .next()
                        .unwrap_or(&endpoint.handler)
                )
            })
            .collect();
        summary.sort();
        let expected: Vec<String> = [
            "actix-web GET /actix/{name} :: attribute_handler",
            "actix-web GET /api/v1/users :: list_users",
            "actix-web POST /actix/echo :: echo",
            "actix-web POST /api/v1/users :: create_user",
            "axum GET /api/v1/users :: list_users",
            "axum GET /api/v1/users/:id :: get_user",
            "axum GET /health :: health",
            "axum POST /api/v1/users :: create_user",
            "rocket GET /rocket/users/<id> :: get_user",
            "rocket POST /rocket/users :: create_user",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(summary, expected);
        assert_eq!(report.stats.api_endpoint_count, expected.len());

        // Spot-check signature extraction: axum's get_user takes
        // Path<i32> and returns Result<Json<User>, _>, so we should see
        // one path parameter named `id` of type `i32` and a response of
        // `User`.
        let axum_get_user = report
            .api_endpoints
            .iter()
            .find(|endpoint| {
                endpoint.framework == "axum"
                    && endpoint.method == "GET"
                    && endpoint.path == "/api/v1/users/:id"
            })
            .expect("axum get_user endpoint present");
        assert_eq!(axum_get_user.parameters.len(), 1);
        assert_eq!(axum_get_user.parameters[0].name, "id");
        assert_eq!(axum_get_user.parameters[0].location, "path");
        assert_eq!(axum_get_user.parameters[0].type_name, "i32");
        assert_eq!(axum_get_user.response_type.as_deref(), Some("User"));

        // Spot-check actix's POST /api/v1/users body extraction.
        let actix_create = report
            .api_endpoints
            .iter()
            .find(|endpoint| {
                endpoint.framework == "actix-web"
                    && endpoint.method == "POST"
                    && endpoint.path == "/api/v1/users"
            })
            .expect("actix create_user endpoint present");
        assert_eq!(
            actix_create.request_body_type.as_deref(),
            Some("CreateUserRequest")
        );

        // Spot-check rocket: <id> placeholder is picked up as a path
        // parameter via the bare-name convention; body comes from the
        // `data = "<payload>"` binding on the handler attribute.
        let rocket_get = report
            .api_endpoints
            .iter()
            .find(|endpoint| {
                endpoint.framework == "rocket"
                    && endpoint.method == "GET"
                    && endpoint.path == "/rocket/users/<id>"
            })
            .expect("rocket get_user endpoint present");
        assert_eq!(rocket_get.parameters.len(), 1);
        assert_eq!(rocket_get.parameters[0].name, "id");
        assert_eq!(rocket_get.parameters[0].location, "path");
        assert_eq!(rocket_get.parameters[0].type_name, "i32");

        let rocket_post = report
            .api_endpoints
            .iter()
            .find(|endpoint| {
                endpoint.framework == "rocket"
                    && endpoint.method == "POST"
                    && endpoint.path == "/rocket/users"
            })
            .expect("rocket create_user endpoint present");
        assert_eq!(
            rocket_post.request_body_type.as_deref(),
            Some("CreateUserRequest")
        );
    }

    #[test]
    fn api_discovery_emits_no_endpoints_without_http_framework_imports() {
        // basic-app has no HTTP framework imports, so the discovery pass
        // should emit an empty endpoint list — proving the pass is a
        // strict no-op for non-web crates.
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("basic-app analyzes cleanly");
        assert!(
            report.api_endpoints.is_empty(),
            "expected zero endpoints for non-HTTP fixture, got {:?}",
            report.api_endpoints
        );
        assert_eq!(report.stats.api_endpoint_count, 0);
    }

    #[test]
    fn api_discovery_populates_framework_purl_on_each_endpoint() {
        // Each endpoint carries the purl of the framework dependency
        // (axum / actix-web / rocket), NOT of the user's own package.
        // The user's package is still identifiable via the
        // `package_path` field. The fixture declares no real cargo
        // dependencies, so the resolved purl falls back to an
        // unversioned `pkg:cargo/<framework>` form.
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("api-discovery-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("api-discovery fixture analyzes cleanly");
        assert!(!report.api_endpoints.is_empty(), "fixture emits endpoints");
        for endpoint in &report.api_endpoints {
            let expected_prefix = match endpoint.framework.as_str() {
                "axum" => "pkg:cargo/axum",
                "actix-web" => "pkg:cargo/actix-web",
                "rocket" => "pkg:cargo/rocket",
                other => panic!(
                    "unexpected framework {} on endpoint {} {}",
                    other, endpoint.method, endpoint.path
                ),
            };
            assert!(
                endpoint.purl == expected_prefix
                    || endpoint.purl.starts_with(&format!("{}@", expected_prefix)),
                "endpoint {} {} purl {} should match {} or {}@<version>",
                endpoint.method,
                endpoint.path,
                endpoint.purl,
                expected_prefix,
                expected_prefix
            );
            // The user's package is still identifiable via package_path.
            assert_eq!(endpoint.package_path, "api_discovery_app");
        }
    }

    #[test]
    fn api_discovery_runs_in_cryptos_scope() {
        // The api-discovery pass runs for all scopes, including Cryptos.
        // Without this, downstream tooling can't correlate crypto
        // operations (sha2 hashing, JWT signing, etc.) with the API
        // endpoint they participate in. The fixture imports no crypto
        // libraries so the crypto filter retains nothing, but the
        // endpoint set should still be populated.
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("api-discovery-app"),
            analysis_scope: AnalysisScope::Cryptos,
            ..AnalyzeOptionsInput::default()
        })
        .expect("api-discovery fixture analyzes cleanly in cryptos scope");
        assert!(
            !report.api_endpoints.is_empty(),
            "expected api_endpoints to be populated even in cryptos scope, got {:?}",
            report.api_endpoints
        );
        assert!(report.stats.api_endpoint_count > 0);
    }

    #[test]
    fn api_discovery_runs_under_compiler_backend() {
        // The api-discovery pass parses source via `syn` and does not
        // depend on the compiler backend; both `--backend stable` and
        // `--backend compiler` should produce the same endpoint set on
        // the same fixture. We exercise the compiler-backend code path
        // here via a synthetic payload (the real compiler driver needs
        // nightly toolchain components and is exercised by the
        // rusi-cli smoke tests).
        let compiler_payload = CompilerBackendPayload {
            diagnostics: Vec::new(),
            files: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            crypto: None,
            call_graph: Some(CallGraph::default()),
            data_flow: None,
        };

        let stable_report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("api-discovery-app"),
            ..AnalyzeOptionsInput::default()
        })
        .expect("stable backend analyzes cleanly");

        let compiler_report = analyze_with_optional_compiler(
            AnalyzeOptionsInput {
                include_dependencies: false,
                max_call_candidates: crate::DEFAULT_MAX_CALL_CANDIDATES,
                dir: fixture_path("api-discovery-app"),
                backend: BACKEND_COMPILER.to_string(),
                analysis_scope: AnalysisScope::Default,
                call_graph_mode: "static".to_string(),
                data_flow_mode: "security".to_string(),
                custom_data_flow_patterns: None,
                include_tests: false,
                debug: false,
            },
            Some(compiler_payload),
        )
        .expect("compiler backend analyzes cleanly");

        assert_eq!(compiler_report.options.backend, BACKEND_COMPILER);
        assert_eq!(
            compiler_report.stats.api_endpoint_count, stable_report.stats.api_endpoint_count,
            "compiler-backend endpoint count should match stable-backend"
        );
        let stable_keys: Vec<_> = stable_report
            .api_endpoints
            .iter()
            .map(|endpoint| {
                format!(
                    "{} {} {} {}",
                    endpoint.framework, endpoint.method, endpoint.path, endpoint.handler
                )
            })
            .collect();
        let compiler_keys: Vec<_> = compiler_report
            .api_endpoints
            .iter()
            .map(|endpoint| {
                format!(
                    "{} {} {} {}",
                    endpoint.framework, endpoint.method, endpoint.path, endpoint.handler
                )
            })
            .collect();
        assert_eq!(stable_keys, compiler_keys);
    }

    #[test]
    fn full_taint_fixture_reconstructs_multi_hop_path() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("full-taint-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            debug: true,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        println!("Declarations: {:?}", report.declarations);
        println!("All slices: {:?}", data_flow.slices);
        for f in &report.files {
            println!("File parsed: {:?}", f.path);
        }
        let matching_slice = data_flow
            .slices
            .iter()
            .find(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
            .expect("matching slice exists");

        println!("Full-taint node ids: {:?}", matching_slice.node_ids);
        assert!(
            matching_slice.node_ids.len() >= 5,
            "Expected at least 5 nodes in the path, got: {:?}",
            matching_slice.node_ids
        );
        assert!(
            matching_slice.path_length >= 4,
            "Expected path length to be at least 4, got: {}",
            matching_slice.path_length
        );
    }

    #[test]
    fn crypto_flow_fixture_emits_env_to_digest_slices_with_method_chains() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("crypto-flow-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            analysis_scope: AnalysisScope::Cryptos,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let matching_slices: Vec<_> = data_flow
            .slices
            .iter()
            .filter(|slice| {
                slice.source_category == "env" && slice.sink_category.starts_with("crypto")
            })
            .collect();
        assert!(
            matching_slices.len() >= 2,
            "Expected at least 2 crypto slices from env source through method chains, got: {}",
            matching_slices.len()
        );
        for slice in &matching_slices {
            assert!(
                slice.path_length >= 2,
                "Expected path_length >= 2 for slice {:?}, got: {}",
                slice.rule_name,
                slice.path_length
            );
        }
    }

    #[test]
    fn field_taint_app_emits_env_slices_through_struct_fields() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("field-taint-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(
                |slice| slice.source_category == "env" && slice.sink_category == "process-exec"
            ),
            "Expected env-to-process-exec flow through struct field"
        );
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "env"
                    && slice.sink_category == "network-connect"),
            "Expected env-to-network-connect flow through struct field"
        );
        assert!(
            data_flow.summaries.iter().any(|summary| {
                summary.function.ends_with("build_config")
                    && summary
                        .source_returns
                        .iter()
                        .any(|category| category == "env")
            }),
            "Expected build_config summary to return env source category"
        );
    }

    #[test]
    fn field_taint_app_does_not_pollute_sibling_fields() {
        // P3.5 negative case: the fixture builds `Mixed { tainted: env_var,
        // clean: "literal-safe-host" }` and then calls `connect_sink(mixed.clean)`.
        // Pre-P3.5 the stable backend unioned every struct field's taint
        // onto the base binding, producing a spurious env→network-connect
        // slice through `mixed.clean`. Access-path-aware reads/writes
        // eliminate the FP; this test pins the behavior so a regression
        // that re-introduces field-level pollution fails loudly.
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("field-taint-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        // Positive assertion: `run_sink(mixed.tainted)` slices.
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "env"
                    && slice.sink_category == "process-exec"
                    && slice.source_name == "std::env::var"),
            "Expected env->process-exec slice through mixed.tainted"
        );
        // Negative assertion: there must be NO env->network-connect slice
        // sourced from `std::env::var` (USER). The only legitimate
        // env->network-connect slice is via build_config (URL), so a
        // direct env::var->connect_sink slice means `mixed.clean` picked
        // up its sibling's taint.
        let polluted = data_flow.slices.iter().any(|slice| {
            slice.source_category == "env"
                && slice.sink_category == "network-connect"
                && slice.source_name == "std::env::var"
        });
        assert!(
            !polluted,
            "mixed.clean must NOT inherit mixed.tainted's env taint \
             (access-path pollution regression)"
        );
    }

    #[test]
    fn chain_flow_app_emits_flow_through_method_chain() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("chain-flow-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(
                |slice| slice.source_category == "env" && slice.sink_category == "process-exec"
            ),
            "Expected env-to-process-exec flow through trim().to_lowercase().to_owned() chain"
        );
    }

    #[test]
    fn dyn_dispatch_app_emits_trait_impl_methods_in_callgraph() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("dyn-dispatch-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        // P1.1/P1.3 — both trait impls are reached as a sound over-approximation
        // (one edge per candidate) instead of dropping the callsite when the
        // dyn-dispatch receiver can't be pinned to a single impl.
        let persist_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.callee_text.as_deref() == Some("persist"))
            .collect();
        assert!(
            !persist_edges.is_empty(),
            "Expected persist call in callgraph for dyn-dispatch"
        );
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.qualified_name.ends_with("FileStore::persist")),
            "Expected FileStore::persist node"
        );
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.qualified_name.ends_with("NetStore::persist")),
            "Expected NetStore::persist node"
        );
        // The receiver is `&dyn Store` so we can't pin a concrete type —
        // every candidate impl must be reached (over-approximation, not drop).
        assert_eq!(
            persist_edges.len(),
            2,
            "dyn-dispatch should over-approximate to both trait impls, got {}",
            persist_edges.len()
        );
        for edge in &persist_edges {
            assert!(
                edge.call_type == "static-overapprox" || edge.call_type == "trait-overapprox",
                "expected over-approx call_type, got {}",
                edge.call_type
            );
            // Confidence is derived from the call type rather than stored.
            assert_eq!(
                rusi_schema::call_type_confidence(&edge.call_type),
                "low",
                "over-approx edge must be low confidence"
            );
            assert_eq!(
                edge.candidate_count,
                Some(2),
                "over-approx edge must report candidate_count=2"
            );
            // Regression: an edge's target must resolve to the target's
            // qualified name, never leak the raw `decl-*` id.
            let target_name = graph.target_name(edge);
            assert!(
                !target_name.starts_with("decl-"),
                "edge target must resolve to a qualified name, got {target_name}"
            );
            assert!(
                target_name.ends_with("::persist"),
                "edge target should be the resolved impl method, got {target_name}"
            );
        }
    }

    #[test]
    fn name_collision_app_resolves_methods_by_receiver_type() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("name-collision-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        // Both Cache::get and Store::get exist; both must be reached, but
        // each via a receiver-typed edge from `cache.get(...)` / `store.get(...)`
        // rather than the legacy drop-on-ambiguity or wrong-bucket behavior.
        let cache_get_id = graph
            .nodes
            .iter()
            .find(|node| node.qualified_name.ends_with("Cache::get"))
            .expect("Cache::get node exists")
            .id
            .clone();
        let store_get_id = graph
            .nodes
            .iter()
            .find(|node| node.qualified_name.ends_with("Store::get"))
            .expect("Store::get node exists")
            .id
            .clone();

        let cache_edge = graph
            .edges
            .iter()
            .find(|edge| edge.target_id == cache_get_id)
            .expect("edge to Cache::get exists");
        let store_edge = graph
            .edges
            .iter()
            .find(|edge| edge.target_id == store_get_id)
            .expect("edge to Store::get exists");

        assert_eq!(
            cache_edge.call_type, "receiver-typed",
            "cache.get should resolve via receiver-type inference"
        );
        assert_eq!(
            cache_edge.receiver.as_deref(),
            Some("cache"),
            "cache.get edge should record the receiver binding name"
        );
        assert_eq!(
            store_edge.call_type, "receiver-typed",
            "store.get should resolve via receiver-type inference"
        );
        assert_eq!(store_edge.receiver.as_deref(), Some("store"));
        // Distinct targets — the entire point of P1.2.
        assert_ne!(cache_get_id, store_get_id);
    }

    #[test]
    fn higher_order_app_emits_edges_to_closure_bodies() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("higher-order-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "none".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let graph = report.call_graph.expect("callgraph emitted");
        let ho_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.call_type == "higher-order")
            .collect();
        // main passes one closure to `.map` and one to `.for_each` — expect
        // two higher-order edges.
        assert_eq!(
            ho_edges.len(),
            2,
            "expected two higher-order edges (map + for_each closures), got {}: {:?}",
            ho_edges.len(),
            ho_edges
                .iter()
                .map(|e| graph.target_name(e).to_string())
                .collect::<Vec<_>>()
        );
        for edge in &ho_edges {
            assert_eq!(
                rusi_schema::call_type_confidence(&edge.call_type),
                "high",
                "higher-order edge confidence must be high (single target)"
            );
            // The edge's calleeText carries the closure's qualified name
            // (e.g. `higher_order_app::closure_16_50`).
            let callee = edge
                .callee_text
                .as_deref()
                .expect("higher-order edge carries calleeText");
            assert!(
                callee.contains("closure_"),
                "higher-order edge should target a closure body, got {}",
                callee
            );
        }
    }

    #[test]
    fn dataflow_diagnostics_include_missing_passthrough_info() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("crypto-flow-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            analysis_scope: AnalysisScope::Cryptos,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let missing = data_flow
            .diagnostics
            .iter()
            .filter(|d| d.kind == "missing-passthrough");
        assert!(
            missing.count() <= 30,
            "Should emit missing-passthrough diagnostics (got some, bounded)"
        );
    }

    #[test]
    fn projection_flow_app_emits_env_to_process_and_network() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("projection-flow-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(
                |slice| slice.source_category == "env" && slice.sink_category == "process-exec"
            ),
            "Expected env-to-process-exec flow through projection"
        );
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "env"
                    && slice.sink_category == "network-connect"),
            "Expected env-to-network-connect flow through projection"
        );
    }

    #[test]
    fn channel_alias_app_does_not_cross_taint_unrelated_channels() {
        // P4.2: tx_safe.send(literal) and tx_unsafe.send(env_var) must not
        // bleed taint across the two channels. The fixture calls
        // Command::new on rx_safe.recv() (must NOT slice) and on
        // rx_unsafe.recv() (must slice). Pre-P4.2 the global taint slot
        // produced two env->process-exec slices; only one is correct.
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("channel-alias-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let env_to_proc: Vec<_> = data_flow
            .slices
            .iter()
            .filter(|s| s.source_category == "env" && s.sink_category == "process-exec")
            .collect();
        assert_eq!(
            env_to_proc.len(),
            1,
            "expected exactly one env->process-exec slice (only rx_unsafe carries taint), got {}",
            env_to_proc.len()
        );
    }

    #[test]
    fn sanitizer_scope_app_does_not_suppress_adjacent_tainted_string() {
        // P4.3: bind() on one query must NOT sanitize a different,
        // already-tainted concatenated SQL string. The fixture has both
        // a tainted-format! slice (must fire) and a parameterized
        // bind-on-literal (must NOT fire).
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("sanitizer-scope-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let sql_slices: Vec<_> = data_flow
            .slices
            .iter()
            .filter(|s| s.sink_category == "sql-query")
            .collect();
        assert_eq!(
            sql_slices.len(),
            1,
            "expected exactly one sql-query slice (the concatenated string); bind on a \
             literal query must not slice, got {}",
            sql_slices.len()
        );
        assert_eq!(
            sql_slices[0].source_category, "env",
            "the SQL slice must be env-sourced (the concatenated user input)"
        );
    }

    #[test]
    fn auto_discovered_passthroughs_are_present_in_patterns() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("auto-passthrough-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let auto_passthroughs: Vec<_> = data_flow
            .patterns
            .passthroughs
            .iter()
            .filter(|p| p.category == "auto-discovered-passthrough")
            .collect();
        assert!(
            !auto_passthroughs.is_empty(),
            "Expected auto-discovered passthroughs in auto-passthrough-app patterns"
        );
        assert!(
            auto_passthroughs.iter().any(|p| p.pattern == "get"),
            "Expected 'get' to be auto-discovered as passthrough"
        );
    }

    #[test]
    fn crypto_flow_with_as_bytes_produces_slices() {
        let report = analyze(AnalyzeOptionsInput {
            dir: fixture_path("cbom-real-crates-app"),
            call_graph_mode: "none".to_string(),
            data_flow_mode: "security".to_string(),
            analysis_scope: AnalysisScope::Cryptos,
            ..AnalyzeOptionsInput::default()
        })
        .expect("analysis succeeds");

        let data_flow = report.data_flow.expect("dataflow emitted");
        let crypto_slices: Vec<_> = data_flow
            .slices
            .iter()
            .filter(|slice| slice.sink_category.starts_with("crypto"))
            .collect();
        assert!(
            crypto_slices.len() >= 4,
            "Expected at least 4 crypto slices in cbom-real-crates-app with cryptos scope, got: {}",
            crypto_slices.len()
        );

        for slice in &crypto_slices {
            assert!(
                slice.path_length >= 2,
                "Expected path_length >= 2 for crypto slice {:?}, got: {}",
                slice.rule_name,
                slice.path_length
            );
        }
    }
}

#[cfg(test)]
mod receiver_type_tests {
    use super::bare_type_token;

    #[test]
    fn plain_paths_reduce_to_the_last_segment() {
        assert_eq!(bare_type_token("Client").as_deref(), Some("Client"));
        assert_eq!(bare_type_token("db::Client").as_deref(), Some("Client"));
    }

    #[test]
    fn references_and_mut_are_stripped() {
        assert_eq!(bare_type_token("&Client").as_deref(), Some("Client"));
        assert_eq!(bare_type_token("&mut Client").as_deref(), Some("Client"));
        // The token stream renders types with spaces around punctuation.
        assert_eq!(
            bare_type_token("& mut db :: Client").as_deref(),
            Some("Client")
        );
    }

    #[test]
    fn deref_transparent_wrappers_are_peeled() {
        // Previously these produced a concatenated nonsense token like
        // `ArcClient`, which matched no impl at all.
        assert_eq!(bare_type_token("Arc<Client>").as_deref(), Some("Client"));
        assert_eq!(
            bare_type_token("Box<db::Client>").as_deref(),
            Some("Client")
        );
        // `Arc` is peeled, `Mutex` is not: `arc_mutex.lock()` is
        // `Mutex::lock`, not a method of the guarded type.
        assert_eq!(
            bare_type_token("&mut Arc<Mutex<Client>>").as_deref(),
            Some("Mutex")
        );
        assert_eq!(
            bare_type_token("Pin<Box<Client>>").as_deref(),
            Some("Client")
        );
        // `Cow<'a, T>`: the pointee is the last non-lifetime argument.
        assert_eq!(
            bare_type_token("Cow<'a, Client>").as_deref(),
            Some("Client")
        );
    }

    #[test]
    fn containers_with_their_own_methods_are_not_peeled() {
        // `vec.push(..)` is `Vec::push`, not a method of the element type.
        assert_eq!(bare_type_token("Vec<Client>").as_deref(), Some("Vec"));
        assert_eq!(bare_type_token("Option<Client>").as_deref(), Some("Option"));
        assert_eq!(
            bare_type_token("HashMap<String, Client>").as_deref(),
            Some("HashMap")
        );
    }

    #[test]
    fn generic_types_keep_their_head() {
        assert_eq!(bare_type_token("Sink<String>").as_deref(), Some("Sink"));
        assert_eq!(bare_type_token("Wrapper<'a>").as_deref(), Some("Wrapper"));
    }

    #[test]
    fn primitives_and_non_types_are_rejected() {
        assert_eq!(bare_type_token("u32"), None);
        assert_eq!(bare_type_token("bool"), None);
        assert_eq!(bare_type_token(""), None);
        assert_eq!(bare_type_token("&str"), None);
    }

    #[test]
    fn trait_objects_reduce_to_the_trait() {
        assert_eq!(bare_type_token("&dyn Store").as_deref(), Some("Store"));
        assert_eq!(bare_type_token("impl Store").as_deref(), Some("Store"));
    }
}

#[cfg(test)]
mod taint_bound_tests {
    use rusi_schema::DataFlowNode;

    use super::{ConcreteTaint, MAX_TAINT_PATH_STEPS, MAX_TAINT_PATHS, TaintPath, TaintStep};

    fn step(node_id: &str) -> TaintStep {
        TaintStep {
            node: DataFlowNode {
                id: node_id.to_string(),
                ..DataFlowNode::default()
            },
            edge: None,
        }
    }

    fn path(origin: &str, node_ids: &[&str]) -> TaintPath {
        TaintPath {
            origin_key: origin.to_string(),
            category: "test".to_string(),
            steps: node_ids.iter().map(|id| step(id)).collect(),
        }
    }

    #[test]
    fn single_short_path_is_untouched() {
        let taint = ConcreteTaint {
            paths: vec![path("env:a", &["n1", "n2"])],
        }
        .bounded();
        assert_eq!(taint.paths.len(), 1);
    }

    #[test]
    fn deduplicates_witnesses_with_same_origin_and_nodes() {
        let taint = ConcreteTaint {
            paths: vec![
                path("env:a", &["n1", "n2"]),
                path("env:a", &["n1", "n2"]),
                path("env:a", &["n1", "n3"]),
            ],
        }
        .bounded();
        // The two identical witnesses collapse; the distinct one survives.
        assert_eq!(taint.paths.len(), 2);
    }

    #[test]
    fn keeps_distinct_sources_separate() {
        let taint = ConcreteTaint {
            paths: vec![path("env:a", &["n1"]), path("cli:b", &["n1"])],
        }
        .bounded();
        // Same node sequence but different origins must not be merged.
        assert_eq!(taint.paths.len(), 2);
    }

    #[test]
    fn caps_total_number_of_witnesses() {
        let paths = (0..(MAX_TAINT_PATHS * 4))
            .map(|i| path(&format!("env:{i}"), &["n1"]))
            .collect::<Vec<_>>();
        let taint = ConcreteTaint { paths }.bounded();
        assert_eq!(taint.paths.len(), MAX_TAINT_PATHS);
    }

    #[test]
    fn drops_pathologically_long_witnesses() {
        let long_nodes: Vec<String> = (0..(MAX_TAINT_PATH_STEPS + 5))
            .map(|i| format!("n{i}"))
            .collect();
        let long_refs: Vec<&str> = long_nodes.iter().map(String::as_str).collect();
        let taint = ConcreteTaint {
            paths: vec![path("env:a", &["short"]), path("env:b", &long_refs)],
        }
        .bounded();
        // The over-length witness is dropped; the short one is retained.
        assert_eq!(taint.paths.len(), 1);
        assert_eq!(taint.paths[0].origin_key, "env:a");
    }
}

/// Tests for the taint passthrough catalogs.
///
/// A missing passthrough is invisible in normal use — the analysis simply
/// reports fewer findings — so the catalogs are asserted directly rather than
/// only through end-to-end fixtures.
#[cfg(test)]
mod passthrough_catalog_tests {
    use std::collections::HashSet;

    use pretty_assertions::assert_eq;

    use super::{
        KNOWN_PASSTHROUGH_NAMES, built_in_dataflow_patterns, is_sanitizer_call, last_segment,
    };

    fn built_in_passthrough_names() -> HashSet<String> {
        built_in_dataflow_patterns()
            .passthroughs
            .into_iter()
            .map(|pattern| pattern.pattern)
            .collect()
    }

    #[test]
    fn the_auto_discovery_allowlist_has_no_duplicates() {
        let unique: HashSet<&&str> = KNOWN_PASSTHROUGH_NAMES.iter().collect();
        assert_eq!(
            unique.len(),
            KNOWN_PASSTHROUGH_NAMES.len(),
            "duplicate entries in KNOWN_PASSTHROUGH_NAMES"
        );
    }

    #[test]
    fn the_auto_discovery_allowlist_holds_bare_method_names() {
        // Matching is on the final path segment, so a qualified path here
        // would never match anything.
        for name in KNOWN_PASSTHROUGH_NAMES {
            assert!(!name.is_empty(), "empty entry");
            assert!(
                !name.contains("::"),
                "{name} is a path, but matching uses the final segment only"
            );
            assert_eq!(last_segment(name), *name);
        }
    }

    #[test]
    fn the_auto_discovery_allowlist_excludes_index_returning_methods() {
        // `substr_range` and `subslice_range` return offsets into the
        // receiver, not the receiver's data. An offset derived from tainted
        // text is not itself the tainted text, so treating these as
        // passthroughs would widen taint to plain integers.
        for name in ["substr_range", "subslice_range", "len", "capacity"] {
            assert!(
                !KNOWN_PASSTHROUGH_NAMES.contains(&name),
                "{name} returns an index or count, not receiver data"
            );
        }
    }

    #[test]
    fn no_name_is_both_a_sanitizer_and_a_passthrough() {
        // A method that both clears and propagates taint is self
        // contradictory, and historically laundered taint past the sanitize
        // step. `discover_auto_passthroughs` filters these out at use time;
        // this asserts the catalogs do not disagree in the first place.
        for name in KNOWN_PASSTHROUGH_NAMES {
            assert!(
                !is_sanitizer_call(name),
                "{name} is listed as both a sanitizer and a passthrough"
            );
        }
    }

    #[test]
    fn the_built_in_pack_models_directional_and_ascii_trimming() {
        // `trim` was modelled but its variants were not, so `input.trim_end()`
        // used to drop taint entirely.
        let names = built_in_passthrough_names();
        for name in [
            "trim",
            "trim_start",
            "trim_end",
            "trim_matches",
            "trim_start_matches",
            "trim_end_matches",
            "trim_ascii",
            "trim_ascii_start",
            "trim_ascii_end",
        ] {
            assert!(names.contains(name), "missing passthrough: {name}");
        }
    }

    #[test]
    fn the_built_in_pack_models_splitting_and_prefix_removal() {
        let names = built_in_passthrough_names();
        for name in [
            "split",
            "split_once",
            "rsplit_once",
            "splitn",
            "split_whitespace",
            "lines",
            "strip_prefix",
            "strip_suffix",
            // Stabilized in Rust 1.98; replaces a strip_prefix/strip_suffix pair.
            "strip_circumfix",
        ] {
            assert!(names.contains(name), "missing passthrough: {name}");
        }
    }

    #[test]
    fn the_built_in_pack_models_owned_and_borrowed_conversions() {
        let names = built_in_passthrough_names();
        for name in [
            "to_str",
            "into_string",
            "into_bytes",
            "to_vec",
            "as_slice",
            "as_deref",
            "as_encoded_bytes",
            "leak",
        ] {
            assert!(names.contains(name), "missing passthrough: {name}");
        }
    }

    #[test]
    fn the_built_in_pack_excludes_index_returning_methods() {
        let names = built_in_passthrough_names();
        for name in ["substr_range", "subslice_range", "len"] {
            assert!(
                !names.contains(name),
                "{name} returns an index or count, not receiver data"
            );
        }
    }

    #[test]
    fn built_in_passthroughs_are_well_formed() {
        for pattern in built_in_dataflow_patterns().passthroughs {
            assert_eq!(pattern.target, "passthrough", "{}", pattern.pattern);
            assert!(!pattern.pattern.is_empty());
            assert!(
                !pattern.category.is_empty(),
                "{} has no category",
                pattern.pattern
            );
            assert!(
                !pattern.relevant_arguments.is_empty(),
                "{} names no argument to propagate",
                pattern.pattern
            );
        }
    }

    #[test]
    fn built_in_passthroughs_are_not_duplicated() {
        let patterns = built_in_dataflow_patterns().passthroughs;
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for pattern in &patterns {
            assert!(
                seen.insert((pattern.pattern.clone(), pattern.category.clone())),
                "duplicate passthrough pattern: {} ({})",
                pattern.pattern,
                pattern.category
            );
        }
    }

    #[test]
    fn no_built_in_passthrough_is_also_a_built_in_sanitizer() {
        for pattern in built_in_dataflow_patterns().passthroughs {
            assert!(
                !is_sanitizer_call(&pattern.pattern),
                "{} is both a sanitizer and a passthrough",
                pattern.pattern
            );
        }
    }
}
