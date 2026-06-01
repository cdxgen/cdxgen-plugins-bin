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
use sha2::{Digest, Sha256};
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

mod modeling;

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
}

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
        }
    }
}

#[derive(Debug, Clone)]
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

impl Default for CompilerBackendPayload {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            files: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            crypto: None,
            call_graph: None,
            data_flow: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RuntimeVersions {
    rustc_version: String,
    cargo_version: String,
    host: String,
}

#[derive(Debug, Clone)]
struct PackageContext {
    package_name: String,
    crate_name: String,
    manifest_path: PathBuf,
    root_dir: PathBuf,
    src_dir: PathBuf,
    module_ref: ModuleRef,
}

#[derive(Debug, Clone)]
struct FileContext {
    package_name: String,
    package_path: String,
    relative_file_path: String,
    module_path: Vec<String>,
}

#[derive(Debug, Clone)]
struct SimplifiedCall {
    callee_text: String,
    position: Position,
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
}

#[derive(Debug, Clone)]
enum Operation {
    Assign { target: String, value: SimpleExpr },
    Expr(SimpleExpr),
    Return(SimpleExpr),
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
    },
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FunctionSummary {
    returns_source_categories: BTreeSet<String>,
    param_to_return: BTreeSet<usize>,
    param_to_sink: BTreeMap<String, BTreeSet<usize>>,
}

#[derive(Debug, Clone)]
struct SourceOrigin {
    key: String,
    node_id: String,
    name: String,
    function: String,
    package_path: String,
    category: String,
}

#[derive(Debug, Clone)]
struct ConcreteTaint {
    origins: Vec<SourceOrigin>,
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
    let package_contexts = workspace_package_contexts(&metadata)?;
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
        },
        modules: package_contexts
            .iter()
            .map(|ctx| ctx.module_ref.clone())
            .collect(),
        ..Report::default()
    };

    let mut analysis_tasks = Vec::new();
    for package_ctx in &package_contexts {
        debug_log(
            options.debug,
            format_args!("pass=file-discovery package={}", package_ctx.crate_name),
        );
        let files = discover_rust_files(package_ctx, options.include_tests)?;
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

        for file_path in files {
            analysis_tasks.push((package_ctx.clone(), file_path));
        }
    }

    let mut analyzed_files = Vec::new();
    debug_log(
        options.debug,
        format_args!("pass=stable-file-analysis files={}", analysis_tasks.len()),
    );
    let mut parse_diagnostics = parallel_map_collect(
        &analysis_tasks,
        |(package_ctx, file_path)| match analyze_file(package_ctx, &analysis_root, file_path) {
            Ok(file) => {
                debug_log(
                    options.debug,
                    format_args!(
                        "pass=stable-file-analysis file={}",
                        relative_display_path(&analysis_root, file_path)
                    ),
                );
                Ok(file)
            }
            Err(error) => Err(Diagnostic {
                kind: "parse".to_string(),
                message: error.to_string(),
                package_path: Some(package_ctx.crate_name.clone()),
                file_path: Some(relative_display_path(&analysis_root, file_path)),
                position: None,
            }),
        },
    );
    for result in parse_diagnostics.drain(..) {
        match result {
            Ok(file) => analyzed_files.push(file),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }
    analyzed_files.sort_by(|left, right| left.file.path.cmp(&right.file.path));

    let mut all_functions = Vec::new();
    for analyzed in &analyzed_files {
        report.files.push(analyzed.file.clone());
        report.imports.extend(analyzed.imports.clone());
        report.declarations.extend(analyzed.declarations.clone());
        report.usages.extend(analyzed.usages.clone());
        report
            .security_signals
            .extend(analyzed.security_signals.clone());
        merge_crypto_evidence(&mut report.crypto, analyzed.file.crypto.clone());
        all_functions.extend(analyzed.functions.clone());
    }

    let fallback_call_graph = if options.call_graph_mode != "none" {
        debug_log(
            options.debug,
            format_args!("pass=stable-callgraph functions={}", all_functions.len()),
        );
        Some(build_call_graph(&all_functions))
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
    let fallback_data_flow = if options.data_flow_mode != "none" {
        debug_log(
            options.debug,
            format_args!("pass=stable-dataflow functions={}", all_functions.len()),
        );
        Some(build_data_flow(
            &options.data_flow_mode,
            &all_functions,
            dataflow_patterns,
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
    debug_log(options.debug, format_args!("pass=normalize-report"));
    normalize_report(&mut report);
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
            merge_pattern_sets(&mut primary.patterns, std::mem::take(&mut fallback.patterns));
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

fn workspace_package_contexts(metadata: &Metadata) -> Result<Vec<PackageContext>> {
    let mut packages = Vec::new();
    for package in metadata.workspace_packages() {
        packages.push(package_context(package)?);
    }
    packages.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    Ok(packages)
}

fn package_context(package: &Package) -> Result<PackageContext> {
    let manifest_path = PathBuf::from(package.manifest_path.as_std_path());
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
            workspace_member: true,
        },
    })
}

fn discover_rust_files(package_ctx: &PackageContext, include_tests: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if package_ctx.src_dir.exists() {
        walk_rust_files(&package_ctx.src_dir, &mut files)?;
    }
    if include_tests {
        let tests_dir = package_ctx.root_dir.join("tests");
        if tests_dir.exists() {
            walk_rust_files(&tests_dir, &mut files)?;
        }
    }
    files.sort();
    Ok(files)
}

fn walk_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn analyze_file(
    package_ctx: &PackageContext,
    root: &Path,
    file_path: &Path,
) -> Result<AnalyzedFile> {
    let source = fs::read_to_string(file_path)
        .with_context(|| format!("failed to read {}", file_path.display()))?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("failed to parse {}", file_path.display()))?;
    let relative_file_path = relative_display_path(root, file_path);
    let module_path = module_path_for_file(package_ctx, file_path);
    let file_ctx = FileContext {
        package_name: package_ctx.package_name.clone(),
        package_path: package_ctx.crate_name.clone(),
        relative_file_path: relative_file_path.clone(),
        module_path,
    };

    let mut collector = SourceCollector::new(file_ctx.clone());
    collector.visit_file(&syntax);

    let file = FileEvidence {
        path: relative_file_path,
        package_name: file_ctx.package_name.clone(),
        package_path: file_ctx.package_path.clone(),
        purl: String::new(),
        imports: collector.imports.clone(),
        declarations: collector.declarations.clone(),
        usages: collector.usages.clone(),
        security_signals: collector.security_signals.clone(),
        crypto: optional_crypto_evidence(&collector.crypto),
    };

    Ok(AnalyzedFile {
        file,
        declarations: collector.declarations,
        usages: collector.usages,
        imports: collector.imports,
        security_signals: collector.security_signals,
        functions: collector.functions,
    })
}

fn module_path_for_file(package_ctx: &PackageContext, file_path: &Path) -> Vec<String> {
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
}

#[derive(Debug, Clone)]
struct FunctionFrame {
    declaration_id: String,
    operations: Vec<Operation>,
    direct_calls: Vec<SimplifiedCall>,
}

impl SourceCollector {
    fn new(file_ctx: FileContext) -> Self {
        Self {
            file_ctx,
            imports: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            crypto: CryptoEvidence::default(),
            functions: Vec::new(),
            current_function: None,
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
            id: stable_id("decl", &[&self.file_ctx.package_path, &qualified_name]),
            name: name.to_string(),
            qualified_name,
            kind: kind.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            file_path: self.file_ctx.relative_file_path.clone(),
            signature,
            receiver,
            position: position_from_span(&self.file_ctx.relative_file_path, span),
        };
        self.declarations.push(declaration.clone());
        declaration
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
            parent.direct_calls.push(SimplifiedCall {
                callee_text: declaration.qualified_name.clone(),
                position,
            });
        }

        let previous = self.current_function.replace(FunctionFrame {
            declaration_id: declaration.id.clone(),
            operations: Vec::new(),
            direct_calls: Vec::new(),
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
        });
        self.current_function = previous;
    }
}

impl<'ast> Visit<'ast> for SourceCollector {
    fn visit_item_use(&mut self, item_use: &'ast syn::ItemUse) {
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
            if node.sig.unsafety.is_some() {
                "unsafe-function"
            } else {
                "function"
            },
            signature_text(&node.sig),
            None,
            node.sig.ident.span(),
        );
        if node.sig.unsafety.is_some() {
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
            });
        }

        let previous = self.current_function.replace(FunctionFrame {
            declaration_id: declaration.id.clone(),
            operations: Vec::new(),
            direct_calls: Vec::new(),
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
        });
        self.current_function = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let receiver = node.self_ty.to_token_stream().to_string().replace(' ', "");
        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                let declaration = self.push_declaration(
                    &method.sig.ident.to_string(),
                    if method.sig.unsafety.is_some() {
                        "unsafe-method"
                    } else {
                        "method"
                    },
                    signature_text(&method.sig),
                    Some(receiver.clone()),
                    method.sig.ident.span(),
                );
                let previous = self.current_function.replace(FunctionFrame {
                    declaration_id: declaration.id.clone(),
                    operations: Vec::new(),
                    direct_calls: Vec::new(),
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
                });
                self.current_function = previous;
            }
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        self.push_declaration(
            &node.ident.to_string(),
            "module",
            format!("mod {}", node.ident),
            None,
            node.ident.span(),
        );
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        match node {
            Item::Struct(item) => {
                self.push_declaration(
                    &item.ident.to_string(),
                    "struct",
                    item.to_token_stream().to_string(),
                    None,
                    item.ident.span(),
                );
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
            }
            _ => {}
        }
        syn::visit::visit_item(self, node);
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
            frame.operations.push(Operation::Expr(call.clone()));
            frame.direct_calls.push(SimplifiedCall {
                callee_text: callee_name.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
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
        properties.insert("receiver".to_string(), receiver_text);
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
            frame.operations.push(Operation::Expr(call.clone()));
            frame.direct_calls.push(SimplifiedCall {
                callee_text: callee_name.clone(),
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
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
                    if let Pat::Ident(PatIdent { ident, .. }) = &local.pat
                        && let Some(init) = &local.init
                    {
                        frame.operations.push(Operation::Assign {
                            target: ident.to_string(),
                            value: simple_expr(&init.expr),
                        });
                    }
                }
                Stmt::Expr(expr, _) => {
                    if let Expr::Return(ExprReturn {
                        expr: Some(value), ..
                    }) = expr
                    {
                        frame.operations.push(Operation::Return(simple_expr(value)));
                    } else {
                        frame.operations.push(Operation::Expr(simple_expr(expr)));
                    }
                }
                _ => {}
            }
        }
        syn::visit::visit_stmt(self, node);
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
            FnArg::Receiver(receiver) => {
                let mut text = String::from("Self");
                if receiver.reference.is_some() {
                    text = if receiver.mutability.is_some() {
                        "&mut Self".to_string()
                    } else {
                        "&Self".to_string()
                    };
                }
                text
            }
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
        http_route_attr_names()
            .iter()
            .any(|candidate| name == *candidate)
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
    if index == 0 && matches!(normalized.as_str(), "Iron::new" | "iron::Iron::new") {
        Some("http-request")
    } else if index == 0
        && matches!(
            last_segment(&normalized),
            "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "route" | "handler"
        )
    {
        Some("http-request")
    } else {
        None
    }
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
    built_in_sanitizer_patterns().iter().any(|pattern| {
        normalized == normalize_pattern_text(pattern)
            || normalized.ends_with(&normalize_pattern_text(pattern))
    })
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

fn signature_text(sig: &Signature) -> String {
    let mut text = sig.to_token_stream().to_string();
    if let ReturnType::Default = sig.output {
        text = text.replace(" ->", "");
    }
    text
}

fn qualify_name(file_ctx: &FileContext, receiver: Option<&str>, name: &str) -> String {
    let mut segments = vec![file_ctx.package_path.clone()];
    segments.extend(file_ctx.module_path.clone());
    if let Some(receiver) = receiver {
        segments.push(receiver.to_string());
    }
    segments.push(name.to_string());
    segments.join("::")
}

fn position_from_span(file_path: &str, span: Span) -> Position {
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
        Expr::Call(ExprCall { func, args, .. }) => SimpleExpr::Call {
            callee: callee_text_from_expr(func),
            args: args.iter().map(simple_expr).collect(),
            position: Position::default(),
        },
        Expr::MethodCall(ExprMethodCall {
            receiver,
            method,
            args,
            ..
        }) => {
            let mut all_args = vec![simple_expr(receiver)];
            all_args.extend(args.iter().map(simple_expr));
            SimpleExpr::Call {
                callee: method_call_callee(receiver, &method.to_string()),
                args: all_args,
                position: Position::default(),
            }
        }
        Expr::Reference(ExprReference { expr, .. }) => simple_expr(expr),
        Expr::Paren(ExprParen { expr, .. }) => simple_expr(expr),
        Expr::Field(ExprField {
            base, member: _, ..
        }) => SimpleExpr::Field {
            base: Box::new(simple_expr(base)),
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

fn build_call_graph(functions: &[FunctionRecord]) -> CallGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut diagnostics = Vec::new();
    let local_index = build_local_function_index(functions);
    let mut seen_nodes = HashSet::new();

    for function in functions {
        if seen_nodes.insert(function.declaration.id.clone()) {
            nodes.push(CallGraphNode {
                id: function.declaration.id.clone(),
                name: function.declaration.name.clone(),
                qualified_name: function.declaration.qualified_name.clone(),
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

        for call in &function.direct_calls {
            let resolved =
                resolve_call_target(&call.callee_text, &function.package_path, &local_index);
            let target_node = match resolved {
                Some(resolved) => resolved,
                None => {
                    let synthetic_id = stable_id("cg-node", &["external", &call.callee_text]);
                    if seen_nodes.insert(synthetic_id.clone()) {
                        nodes.push(CallGraphNode {
                            id: synthetic_id.clone(),
                            name: last_segment(&call.callee_text).to_string(),
                            qualified_name: call.callee_text.clone(),
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
                    synthetic_id
                }
            };
            let mut properties = IndexMap::new();
            properties.insert("calleeText".to_string(), call.callee_text.clone());
            edges.push(CallGraphEdge {
                id: stable_id(
                    "cg-edge",
                    &[
                        &function.declaration.id,
                        &target_node,
                        &call.position.line.to_string(),
                        &call.position.column.to_string(),
                    ],
                ),
                source_id: function.declaration.id.clone(),
                target_id: target_node.clone(),
                source_name: function.declaration.qualified_name.clone(),
                target_name: target_node.clone(),
                source_purl: String::new(),
                target_purl: String::new(),
                purls: Vec::new(),
                call_type: if target_node.starts_with("decl-") {
                    "static".to_string()
                } else {
                    "external".to_string()
                },
                position: call.position.clone(),
                properties,
            });
        }
    }

    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
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
    None
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
) -> DataFlowEvidence {
    let local_index = build_local_function_index(functions);
    let function_map: HashMap<String, &FunctionRecord> = functions
        .iter()
        .map(|function| (function.declaration.id.clone(), function))
        .collect();
    let summaries = infer_summaries(functions, &local_index, &patterns);
    let partials = parallel_map_collect(functions, |function| {
        let mut builder = DataFlowBuilder::new(
            mode,
            patterns.clone(),
            summaries.clone(),
            &local_index,
            &function_map,
        );
        builder.materialize_function(function);
        builder
    });
    let mut builder = DataFlowBuilder::new(
        mode,
        patterns.clone(),
        summaries.clone(),
        &local_index,
        &function_map,
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
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::var_os".to_string(),
                category: "env".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::var".to_string(),
                category: "env".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::args".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::args".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::env::args_os".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "env::args_os".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::fs::read_to_string".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "fs::read_to_string".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::fs::read".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "fs::read".to_string(),
                category: "file".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "std::io::stdin".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
            DataFlowPattern {
                target: "source".to_string(),
                pattern: "stdin".to_string(),
                category: "cli".to_string(),
                relevant_arguments: vec![],
            },
        ],
        sinks: vec![
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::process::Command::new".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Command::new".to_string(),
                category: "process-exec".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::fs::write".to_string(),
                category: "filesystem-write".to_string(),
                relevant_arguments: vec![0, 1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fs::write".to_string(),
                category: "filesystem-write".to_string(),
                relevant_arguments: vec![0, 1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::fs::remove_file".to_string(),
                category: "filesystem-delete".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fs::remove_file".to_string(),
                category: "filesystem-delete".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "std::net::TcpStream::connect".to_string(),
                category: "network-connect".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "TcpStream::connect".to_string(),
                category: "network-connect".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_one".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_all".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch_optional".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "fetch".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "load".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "load_iter".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get_result".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get_results".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "first".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_one".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_opt".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_map".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_row".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_and_then".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_drop".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_first".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "query_iter".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "simple_query".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "batch_execute".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute_batch".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "execute_unprepared".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "prepare".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "prepare_cached".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "exec".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "exec_drop".to_string(),
                category: "sql-query".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "reqwest::blocking::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "reqwest::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "put".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "patch".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "delete".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "request".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![2],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "send".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "surf::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "surf::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "ureq::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "ureq::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "isahc::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "isahc::post".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "hyper::Client::get".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "hyper::Client::request".to_string(),
                category: "network-request".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "format!#html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Response::with".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "warp::reply::html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "HttpResponse::body".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Response::body".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![1],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "Html".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "sink".to_string(),
                pattern: "RawHtml".to_string(),
                category: "html-response".to_string(),
                relevant_arguments: vec![0],
            },
        ],
        passthroughs: vec![
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or_else".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "unwrap_or_default".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "expect".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "nth".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "next".to_string(),
                category: "iterator-adapter".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "map".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "and_then".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_string".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "to_owned".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_owned".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "clone".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "trim".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_inner".to_string(),
                category: "extractor-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_str".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_ref".to_string(),
                category: "value-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "query".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "path".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "uri".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "param".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "query_string".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "match_info".to_string(),
                category: "http-request-accessor".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "format!".to_string(),
                category: "string-format".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "format!#html".to_string(),
                category: "string-format".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "CString::new".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query_as".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sqlx::query_scalar".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "diesel::dsl::sql_query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sql_query".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sea_orm::Statement::from_sql_and_values".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "sea_query::Query::from_string".to_string(),
                category: "sql-builder".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "std::ffi::CString::new".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "as_ptr".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "deref".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
            DataFlowPattern {
                target: "passthrough".to_string(),
                pattern: "into_raw".to_string(),
                category: "ffi-wrapper".to_string(),
                relevant_arguments: vec![0],
            },
        ],
    }
}

fn infer_summaries(
    functions: &[FunctionRecord],
    local_index: &HashMap<String, Vec<String>>,
    patterns: &DataFlowPatternSet,
) -> BTreeMap<String, FunctionSummary> {
    let mut summaries = BTreeMap::<String, FunctionSummary>::new();
    for function in functions {
        summaries.insert(function.declaration.id.clone(), FunctionSummary::default());
    }

    for _ in 0..6 {
        let next_entries = parallel_map_collect(functions, |function| {
            (
                function.declaration.id.clone(),
                summarize_function(function, &summaries, local_index, patterns),
            )
        });
        let mut changed = false;
        for (function_id, next) in next_entries {
            let entry = summaries.entry(function_id).or_default();
            if entry != &next {
                *entry = next;
                changed = true;
            }
        }
        if !changed {
            break;
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
) -> FunctionSummary {
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
                if let SimpleExpr::Call { callee, args, .. } = expr {
                    if let Some(sink_match) = find_sink_pattern(callee, args, &patterns.sinks) {
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

                    if let Some(resolved) =
                        resolve_call_target(callee, &function.package_path, local_index)
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
        SimpleExpr::Var(name) => env.get(name).cloned().unwrap_or_default(),
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
            if let Some(resolved) = resolve_call_target(callee, package_path, local_index)
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
        SimpleExpr::Field { base, .. } => {
            eval_abstract_expr(base, env, summaries, package_path, local_index, patterns)
        }
        SimpleExpr::Literal | SimpleExpr::Unknown => BTreeSet::new(),
    }
}

struct DataFlowBuilder<'a> {
    mode: &'a str,
    patterns: DataFlowPatternSet,
    summaries: BTreeMap<String, FunctionSummary>,
    local_index: &'a HashMap<String, Vec<String>>,
    function_map: &'a HashMap<String, &'a FunctionRecord>,
    nodes: IndexMap<String, DataFlowNode>,
    edges: IndexMap<String, DataFlowEdge>,
    slices: IndexMap<String, DataFlowSlice>,
}

impl<'a> DataFlowBuilder<'a> {
    fn new(
        mode: &'a str,
        patterns: DataFlowPatternSet,
        summaries: BTreeMap<String, FunctionSummary>,
        local_index: &'a HashMap<String, Vec<String>>,
        function_map: &'a HashMap<String, &'a FunctionRecord>,
    ) -> Self {
        Self {
            mode,
            patterns,
            summaries,
            local_index,
            function_map,
            nodes: IndexMap::new(),
            edges: IndexMap::new(),
            slices: IndexMap::new(),
        }
    }

    fn materialize_function(&mut self, function: &FunctionRecord) {
        let mut env: HashMap<String, ConcreteTaint> = HashMap::new();
        for (idx, param) in function.params.iter().enumerate() {
            if let Some(category) = function.param_source_categories.get(&idx) {
                let origin = self.source_origin(
                    function,
                    param,
                    category,
                    function.declaration.position.clone(),
                );
                env.insert(
                    param.clone(),
                    ConcreteTaint {
                        origins: vec![origin],
                    },
                );
            }
        }
        for operation in &function.operations {
            match operation {
                Operation::Assign { target, value } => {
                    let taint = self.eval_concrete_expr(function, value, &env);
                    if !taint.origins.is_empty() {
                        env.insert(target.clone(), taint);
                    }
                }
                Operation::Expr(expr) | Operation::Return(expr) => {
                    if let SimpleExpr::Call {
                        callee,
                        args,
                        position,
                    } = expr
                    {
                        if let Some(sink_match) =
                            find_sink_pattern(callee, args, &self.patterns.sinks)
                        {
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

                        if let Some(resolved) =
                            resolve_call_target(callee, &function.package_path, self.local_index)
                            && let Some(summary) = self.summaries.get(&resolved).cloned()
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

    fn eval_concrete_expr(
        &mut self,
        function: &FunctionRecord,
        expr: &SimpleExpr,
        env: &HashMap<String, ConcreteTaint>,
    ) -> ConcreteTaint {
        match expr {
            SimpleExpr::Var(name) => env
                .get(name)
                .cloned()
                .unwrap_or(ConcreteTaint { origins: vec![] }),
            SimpleExpr::Call {
                callee,
                args,
                position,
            } => {
                if let Some(source_match) = find_source_pattern(callee, &self.patterns.sources) {
                    let origin = self.source_origin(
                        function,
                        callee,
                        &source_match.category,
                        position.clone(),
                    );
                    return ConcreteTaint {
                        origins: vec![origin],
                    };
                }
                if is_sanitizer_call(callee) {
                    return ConcreteTaint { origins: vec![] };
                }
                if has_passthrough_pattern(callee, &self.patterns.passthroughs) {
                    let mut origins = Vec::new();
                    for arg in args {
                        origins.extend(self.eval_concrete_expr(function, arg, env).origins);
                    }
                    return ConcreteTaint { origins };
                }
                if let Some(resolved) =
                    resolve_call_target(callee, &function.package_path, self.local_index)
                    && let Some(summary) = self.summaries.get(&resolved).cloned()
                {
                    let mut origins = Vec::new();
                    for category in &summary.returns_source_categories {
                        let callee_name = self
                            .function_map
                            .get(&resolved)
                            .map(|f| f.declaration.qualified_name.clone())
                            .unwrap_or_else(|| callee.to_string());
                        origins.push(self.source_origin(
                            function,
                            &callee_name,
                            category,
                            position.clone(),
                        ));
                    }
                    for param_index in &summary.param_to_return {
                        if let Some(arg) = args.get(*param_index) {
                            origins.extend(self.eval_concrete_expr(function, arg, env).origins);
                        }
                    }
                    return ConcreteTaint { origins };
                }
                ConcreteTaint { origins: vec![] }
            }
            SimpleExpr::Compose(items) => {
                let mut origins = Vec::new();
                for item in items {
                    origins.extend(self.eval_concrete_expr(function, item, env).origins);
                }
                ConcreteTaint { origins }
            }
            SimpleExpr::Field { base, .. } => self.eval_concrete_expr(function, base, env),
            SimpleExpr::Literal | SimpleExpr::Unknown => ConcreteTaint { origins: vec![] },
        }
    }

    fn source_origin(
        &mut self,
        function: &FunctionRecord,
        name: &str,
        category: &str,
        position: Position,
    ) -> SourceOrigin {
        let node_id = stable_id(
            "df-node",
            &[
                &function.declaration.id,
                name,
                category,
                &position.line.to_string(),
                &position.column.to_string(),
            ],
        );
        self.nodes
            .entry(node_id.clone())
            .or_insert_with(|| DataFlowNode {
                id: node_id.clone(),
                kind: "source".to_string(),
                name: name.to_string(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                function: function.declaration.qualified_name.clone(),
                position: position.clone(),
                source: true,
                sink: false,
                category: category.to_string(),
                parameter_index: None,
                type_name: None,
                properties: IndexMap::new(),
            });
        SourceOrigin {
            key: format!("{}:{}:{}", function.declaration.id, name, category),
            node_id,
            name: name.to_string(),
            function: function.declaration.qualified_name.clone(),
            package_path: function.package_path.clone(),
            category: category.to_string(),
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
        if taint.origins.is_empty() {
            return;
        }
        let sink_node_id = stable_id(
            "df-node",
            &[
                &function.declaration.id,
                sink_name,
                sink_category,
                &position.line.to_string(),
                &position.column.to_string(),
            ],
        );
        self.nodes
            .entry(sink_node_id.clone())
            .or_insert_with(|| DataFlowNode {
                id: sink_node_id.clone(),
                kind: "sink".to_string(),
                name: sink_name.to_string(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                function: function.declaration.qualified_name.clone(),
                position: position.clone(),
                source: false,
                sink: true,
                category: sink_category.to_string(),
                parameter_index: None,
                type_name: None,
                properties: IndexMap::new(),
            });

        for origin in &taint.origins {
            let edge_id = stable_id("df-edge", &[&origin.node_id, &sink_node_id, sink_category]);
            self.edges
                .entry(edge_id.clone())
                .or_insert_with(|| DataFlowEdge {
                    id: edge_id.clone(),
                    source_id: origin.node_id.clone(),
                    target_id: sink_node_id.clone(),
                    kind: "taint".to_string(),
                    properties: IndexMap::new(),
                });

            let slice_id = stable_id("df-slice", &[&origin.key, &sink_node_id, sink_category]);
            self.slices
                .entry(slice_id.clone())
                .or_insert_with(|| DataFlowSlice {
                    id: slice_id,
                    source_id: origin.node_id.clone(),
                    sink_id: sink_node_id.clone(),
                    source_name: origin.name.clone(),
                    sink_name: sink_name.to_string(),
                    source_function: origin.function.clone(),
                    sink_function: function.declaration.qualified_name.clone(),
                    source_package_path: origin.package_path.clone(),
                    sink_package_path: function.package_path.clone(),
                    source_purl: String::new(),
                    target_purl: String::new(),
                    purls: Vec::new(),
                    source_category: origin.category.clone(),
                    sink_category: sink_category.to_string(),
                    node_ids: vec![origin.node_id.clone(), sink_node_id.clone()],
                    edge_ids: vec![edge_id],
                    path_length: 1,
                    source_parameter_index: None,
                    sink_parameter_index: None,
                    source_type_name: None,
                    sink_type_name: None,
                    rule_name: format!("{}-to-{}", origin.category, sink_category),
                    description: format!(
                        "{} data can flow from {} to {}",
                        origin.category, origin.name, sink_name
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
                .get(&function_id)
                .map(|record| record.declaration.qualified_name.clone())
                .unwrap_or_default();
            let package_path = self
                .function_map
                .get(&function_id)
                .map(|record| record.package_path.clone())
                .unwrap_or_default();
            summaries.push(DataFlowMethodSummary {
                function_id: function_id.clone(),
                function,
                package_path,
                purl: String::new(),
                parameter_names: self
                    .function_map
                    .get(&function_id)
                    .map(|record| record.params.clone())
                    .unwrap_or_default(),
                parameter_types: self
                    .function_map
                    .get(&function_id)
                    .map(|record| record.param_types.clone())
                    .unwrap_or_default(),
                return_type: self
                    .function_map
                    .get(&function_id)
                    .map(|record| record.return_type.clone())
                    .unwrap_or_else(|| "()".to_string()),
                param_to_return: summary.param_to_return.into_iter().collect(),
                param_to_sink: summary
                    .param_to_sink
                    .into_iter()
                    .map(|(key, value)| (key, value.into_iter().collect()))
                    .collect(),
                source_returns: summary.returns_source_categories.into_iter().collect(),
                properties: IndexMap::new(),
            });
        }
        summaries.sort_by(|left, right| left.function_id.cmp(&right.function_id));

        let nodes = self.nodes.into_values().collect::<Vec<_>>();
        let edges = self.edges.into_values().collect::<Vec<_>>();
        let slices = self.slices.into_values().collect::<Vec<_>>();
        DataFlowEvidence {
            mode: self.mode.to_string(),
            patterns: self.patterns,
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
        }
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
    }
}

fn find_source_pattern(callee: &str, patterns: &[DataFlowPattern]) -> Option<SourcePatternMatch> {
    let normalized = normalize_pattern_text(callee);
    patterns
        .iter()
        .find(|pattern| {
            normalized == normalize_pattern_text(&pattern.pattern)
                || normalized.ends_with(&normalize_pattern_text(&pattern.pattern))
        })
        .map(|pattern| SourcePatternMatch {
            category: pattern.category.clone(),
        })
}

fn find_sink_pattern(
    callee: &str,
    args: &[SimpleExpr],
    patterns: &[DataFlowPattern],
) -> Option<SinkPatternMatch> {
    let normalized = normalize_pattern_text(callee);
    patterns
        .iter()
        .find(|pattern| {
            let candidate = normalize_pattern_text(&pattern.pattern);
            (normalized == candidate || normalized.ends_with(&candidate))
                && sink_pattern_context_confident(&normalized, args, pattern)
        })
        .map(|pattern| SinkPatternMatch {
            category: pattern.category.clone(),
            relevant_arguments: pattern.relevant_arguments.clone(),
        })
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
        SimpleExpr::Field { base } => simple_expr_looks_sqlish(base),
        SimpleExpr::Literal | SimpleExpr::Unknown => false,
    }
}

fn has_passthrough_pattern(callee: &str, patterns: &[DataFlowPattern]) -> bool {
    let normalized = callee.replace(' ', "");
    patterns.iter().any(|pattern| {
        let candidate = normalize_pattern_text(&pattern.pattern);
        normalized == candidate || normalized.ends_with(&candidate)
    })
}

fn normalize_pattern_text(value: &str) -> String {
    value.replace(' ', "")
}

fn relative_display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn stable_id(prefix: &str, components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for component in components {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{prefix}-{hex}")
}

fn enrich_graph_component_purls(report: &mut Report) {
    let package_purls = package_purl_index(&report.packages);

    for package in &mut report.packages {
        package.purl = resolve_package_purl(&package.package_path, &package_purls);
    }
    for file in &mut report.files {
        file.purl = resolve_package_purl(&file.package_path, &package_purls);
        for import in &mut file.imports {
            import.purl = resolve_package_purl(&import.package_path, &package_purls);
        }
        for declaration in &mut file.declarations {
            declaration.purl = resolve_package_purl(&declaration.package_path, &package_purls);
        }
        for usage in &mut file.usages {
            usage.purl = resolve_package_purl(&usage.package_path, &package_purls);
        }
        for signal in &mut file.security_signals {
            signal.purl = resolve_package_purl(&signal.package_path, &package_purls);
        }
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
        let mut node_purls = HashMap::new();
        for node in &mut call_graph.nodes {
            node.purl = resolve_package_purl(&node.package_path, &package_purls);
            node_purls.insert(node.id.clone(), node.purl.clone());
        }
        for edge in &mut call_graph.edges {
            edge.source_purl = node_purls
                .get(&edge.source_id)
                .cloned()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    resolve_package_purl(&inferred_package_path(&edge.source_name), &package_purls)
                });
            edge.target_purl = node_purls
                .get(&edge.target_id)
                .cloned()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    resolve_package_purl(&inferred_package_path(&edge.target_name), &package_purls)
                });
            edge.purls = combined_purls(&edge.source_purl, &edge.target_purl);
        }
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
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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
                .any(|edge| edge.source_name.ends_with("main")
                    && edge.properties.get("calleeText")
                        == Some(&"helper::read_secret".to_string()))
        );
        assert!(
            call_graph
                .edges
                .iter()
                .any(|edge| edge.properties.get("calleeText")
                    == Some(&"helper::run_command".to_string()))
        );

        let data_flow = report.data_flow.expect("dataflow emitted");
        assert!(
            data_flow.slices.iter().any(
                |slice| slice.source_category == "env" && slice.sink_category == "process-exec"
            )
        );
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
                .any(|edge| edge.properties.get("calleeText")
                    == Some(&"crate::util::compute".to_string()))
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.properties.get("calleeText") == Some(&"render".to_string()))
        );
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
                .any(|edge| edge.properties.get("calleeText") == Some(&"sqlx::query".to_string()))
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.properties.get("calleeText") == Some(&"post".to_string()))
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
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.source_name.ends_with("main"))
            .expect("callgraph edge exists");
        assert!(edge.source_purl.starts_with("pkg:cargo/"));
        assert!(!edge.purls.is_empty());
        assert!(
            edge.purls
                .iter()
                .any(|purl| purl == &edge.source_purl || purl == &edge.target_purl)
        );

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
                id: "decl-compiler-test".to_string(),
                name: "read_secret".to_string(),
                qualified_name: "basic_app::helper::read_secret".to_string(),
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
                }],
                sinks: vec![DataFlowPattern {
                    target: String::new(),
                    pattern: "helper::run_command".to_string(),
                    category: "custom-command".to_string(),
                    relevant_arguments: vec![0],
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
}
