use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use indexmap::IndexMap;
use proc_macro2::Span;
use quote::ToTokens;
use rusi_core::{AnalyzeOptionsInput, CompilerBackendPayload};
use rusi_schema::{
    CallGraph, CompilerEvidence, CryptoComponent, CryptoEvidence, CryptoFinding, CryptoLibrary,
    CryptoMaterial, DataFlowEvidence, DataFlowStats, Declaration, Diagnostic, FileEvidence,
    GraphStats, ImportUsage, LibraryUsage, Position, SecuritySignal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Attribute, File, ForeignItem, ItemFn, ItemForeignMod, ItemMod, LitStr, ReturnType, Signature,
};

pub const BACKEND_KIND_STUB: &str = "compiler-stub";
pub const BACKEND_KIND_EMBEDDED: &str = "compiler-embedded";
pub const DRIVER_PROTOCOL_VERSION: &str = "rusi.driver/v0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverOptions {
    pub analysis_root: PathBuf,
    pub call_graph_mode: String,
    pub data_flow_mode: String,
    pub include_tests: bool,
    pub rustc_toolchain: String,
    pub debug: bool,
}

impl DriverOptions {
    pub fn from_analyze_options(options: &AnalyzeOptionsInput) -> Self {
        Self {
            analysis_root: options.dir.clone(),
            call_graph_mode: options.call_graph_mode.clone(),
            data_flow_mode: options.data_flow_mode.clone(),
            include_tests: options.include_tests,
            rustc_toolchain: "auto".to_string(),
            debug: options.debug,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DriverCapabilities {
    pub rustup_available: bool,
    pub available_toolchains: Vec<String>,
    pub requested_toolchain: String,
    pub resolved_toolchain: String,
    pub toolchain_available: bool,
    pub nightly_toolchain: bool,
    pub embedded_backend_supported: bool,
    pub source_evidence_collected: bool,
    pub native_interop_collected: bool,
    pub mir_evidence_collected: bool,
    pub rustc_version: String,
    pub cargo_version: String,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriverProtocolEnvelope {
    pub protocol_version: String,
    pub backend_kind: String,
    pub analysis_root: String,
    pub capabilities: DriverCapabilities,
    pub payload: DriverProtocolPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriverProtocolPayload {
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

impl Default for DriverProtocolPayload {
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

impl DriverProtocolEnvelope {
    pub fn from_payload(
        options: &DriverOptions,
        backend_kind: &str,
        capabilities: DriverCapabilities,
        payload: DriverProtocolPayload,
    ) -> Self {
        Self {
            protocol_version: DRIVER_PROTOCOL_VERSION.to_string(),
            backend_kind: backend_kind.to_string(),
            analysis_root: options.analysis_root.display().to_string(),
            capabilities,
            payload,
        }
    }

    pub fn into_compiler_payload(self) -> CompilerBackendPayload {
        CompilerBackendPayload {
            diagnostics: self.payload.diagnostics,
            files: self.payload.files,
            imports: self.payload.imports,
            declarations: self.payload.declarations,
            usages: self.payload.usages,
            security_signals: self.payload.security_signals,
            crypto: self.payload.crypto,
            call_graph: self.payload.call_graph,
            data_flow: self.payload.data_flow,
        }
    }

    pub fn write_to_path(&self, output_path: &Path) -> Result<()> {
        let file = fs::File::create(output_path)
            .with_context(|| format!("failed to create {}", output_path.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        // Intermediate driver-protocol artifact: minified to keep the temp file
        // small and fast to (de)serialize.
        serde_json::to_writer(&mut writer, self)
            .with_context(|| format!("failed to write {}", output_path.display()))?;
        writer
            .flush()
            .with_context(|| format!("failed to flush {}", output_path.display()))
    }

    pub fn read_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let envelope = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse driver protocol from {}", path.display()))?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Default)]
struct NativeInteropEvidence {
    files: Vec<FileEvidence>,
    declarations: Vec<Declaration>,
    usages: Vec<LibraryUsage>,
    security_signals: Vec<SecuritySignal>,
    foreign_symbols: HashMap<String, ForeignFunctionInfo>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ForeignFunctionInfo {
    declaration: Declaration,
    parameter_types: Vec<String>,
    abi: String,
    link_name: Option<String>,
}

#[derive(Debug, Clone)]
struct PackageContext {
    package_name: String,
    crate_name: String,
    root_dir: PathBuf,
    src_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct NativeFileContext {
    package_name: String,
    package_path: String,
    relative_file_path: String,
    module_path: Vec<String>,
}

pub fn run_driver(options: &DriverOptions) -> Result<DriverProtocolEnvelope> {
    let analysis_root = fs::canonicalize(&options.analysis_root).with_context(|| {
        format!(
            "failed to resolve compiler backend root {}",
            options.analysis_root.display()
        )
    })?;
    debug_log(
        options.debug,
        format_args!("pass=compiler-driver root={}", analysis_root.display()),
    );
    let metadata = load_metadata(&analysis_root)?;
    debug_log(
        options.debug,
        format_args!("pass=compiler-capability-detection"),
    );
    let mut capabilities = detect_capabilities(options, &analysis_root);
    let mut payload = DriverProtocolPayload::default();
    payload
        .diagnostics
        .push(capability_summary_diagnostic(&analysis_root, &capabilities));

    let mut backend_kind = BACKEND_KIND_STUB;

    if capabilities.embedded_backend_supported {
        debug_log(
            options.debug,
            format_args!("pass=embedded-compiler-backend"),
        );
        match collect_embedded_compiler_evidence(&analysis_root, options, &capabilities) {
            Ok(evidence) => {
                capabilities.source_evidence_collected = !evidence.declarations.is_empty();
                capabilities.mir_evidence_collected =
                    evidence.call_graph.is_some() || evidence.data_flow.is_some();
                merge_file_evidence(&mut payload.files, evidence.files);
                extend_unique_imports(&mut payload.imports, evidence.imports);
                extend_unique_declarations(&mut payload.declarations, evidence.declarations);
                extend_unique_usages(&mut payload.usages, evidence.usages);
                extend_unique_security_signals(
                    &mut payload.security_signals,
                    evidence.security_signals,
                );
                merge_crypto_evidence(&mut payload.crypto, evidence.crypto);
                payload.call_graph = evidence.call_graph;
                payload.data_flow = evidence.data_flow;
                payload.diagnostics.extend(evidence.diagnostics);
                payload.diagnostics.push(Diagnostic {
                    kind: "compiler-source-evidence".to_string(),
                    message: format!(
                        "collected compiler source, callgraph, and MIR slicing evidence via embedded rustc callbacks using toolchain {}",
                        capabilities.resolved_toolchain
                    ),
                    package_path: None,
                    file_path: None,
                    position: Some(Position {
                        filename: analysis_root.display().to_string(),
                        line: 0,
                        column: 0,
                    }),
                });
                backend_kind = BACKEND_KIND_EMBEDDED;
            }
            Err(error) => payload.diagnostics.push(Diagnostic {
                kind: "backend-error".to_string(),
                message: format!("embedded compiler backend could not collect evidence: {error:#}"),
                package_path: None,
                file_path: None,
                position: Some(Position {
                    filename: analysis_root.display().to_string(),
                    line: 0,
                    column: 0,
                }),
            }),
        }
    }

    debug_log(options.debug, format_args!("pass=native-interop-scan"));
    match collect_native_interop_evidence(
        &analysis_root,
        &metadata,
        options.include_tests,
        options.debug,
    ) {
        Ok(evidence) => {
            capabilities.native_interop_collected =
                !evidence.declarations.is_empty() || !evidence.usages.is_empty();
            merge_file_evidence(&mut payload.files, evidence.files);
            extend_unique_declarations(&mut payload.declarations, evidence.declarations);
            extend_unique_usages(&mut payload.usages, evidence.usages);
            extend_unique_security_signals(
                &mut payload.security_signals,
                evidence.security_signals,
            );
            if capabilities.native_interop_collected {
                payload.diagnostics.push(Diagnostic {
                    kind: "native-interop".to_string(),
                    message: format!(
                        "collected native interop evidence for {} foreign symbol(s)",
                        evidence.foreign_symbols.len()
                    ),
                    package_path: None,
                    file_path: None,
                    position: Some(Position {
                        filename: analysis_root.display().to_string(),
                        line: 0,
                        column: 0,
                    }),
                });
            }
        }
        Err(error) => payload.diagnostics.push(Diagnostic {
            kind: "backend-error".to_string(),
            message: format!(
                "compiler backend could not collect native interop evidence: {error:#}"
            ),
            package_path: None,
            file_path: None,
            position: Some(Position {
                filename: analysis_root.display().to_string(),
                line: 0,
                column: 0,
            }),
        }),
    }

    if backend_kind == BACKEND_KIND_STUB {
        payload.diagnostics.push(Diagnostic {
            kind: "backend".to_string(),
            message: format!(
                "compiler backend selected for {}; embedded rustc support is unavailable for resolved toolchain {}",
                analysis_root.display(),
                capabilities.resolved_toolchain
            ),
            package_path: None,
            file_path: None,
            position: Some(Position {
                filename: analysis_root.display().to_string(),
                line: 0,
                column: 0,
            }),
        });
    }

    enrich_payload_purls(&metadata, &mut payload);
    debug_log(options.debug, format_args!("pass=compiler-driver-done"));

    Ok(DriverProtocolEnvelope::from_payload(
        options,
        backend_kind,
        capabilities,
        payload,
    ))
}

fn debug_log(enabled: bool, args: std::fmt::Arguments<'_>) {
    if enabled {
        eprintln!("rusi debug: {args}");
    }
}

fn load_metadata(dir: &Path) -> Result<Metadata> {
    let mut command = MetadataCommand::new();
    command.current_dir(dir);
    command
        .exec()
        .context("cargo metadata failed for compiler backend")
}

fn detect_capabilities(options: &DriverOptions, analysis_root: &Path) -> DriverCapabilities {
    let rustup_output = capture_command_output("rustup", &["toolchain", "list"]);
    let rustup_available = !rustup_output.is_empty() && rustup_output != "unknown";
    let available_toolchains = if rustup_available {
        rustup_output
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let requested_toolchain = options.rustc_toolchain.clone();
    let resolved_toolchain = resolve_toolchain(&requested_toolchain, &available_toolchains);
    let toolchain_available = if rustup_available {
        if requested_toolchain == "auto" {
            !resolved_toolchain.is_empty()
        } else {
            available_toolchains.iter().any(|toolchain| {
                toolchain == &resolved_toolchain || toolchain.starts_with(&resolved_toolchain)
            })
        }
    } else {
        requested_toolchain == "auto" || requested_toolchain == "stable"
    };
    let nightly_toolchain = resolved_toolchain.contains("nightly");
    let installed_components = if rustup_available && !resolved_toolchain.is_empty() {
        capture_command_output(
            "rustup",
            &[
                "component",
                "list",
                "--installed",
                "--toolchain",
                &resolved_toolchain,
            ],
        )
    } else {
        String::new()
    };
    let rustc_private_components =
        installed_components.contains("rustc-dev") && installed_components.contains("rust-src");
    let embedded_backend_supported =
        toolchain_available && nightly_toolchain && rustc_private_components;
    let rustc_version = capture_toolchain_rustc_version(&resolved_toolchain, rustup_available);
    let cargo_version = capture_toolchain_cargo_version(&resolved_toolchain, rustup_available);
    let host = detect_host(analysis_root, &resolved_toolchain, rustup_available);

    DriverCapabilities {
        rustup_available,
        available_toolchains,
        requested_toolchain,
        resolved_toolchain,
        toolchain_available,
        nightly_toolchain,
        embedded_backend_supported,
        source_evidence_collected: false,
        native_interop_collected: false,
        mir_evidence_collected: false,
        rustc_version,
        cargo_version,
        host,
    }
}

fn capability_summary_diagnostic(root: &Path, capabilities: &DriverCapabilities) -> Diagnostic {
    Diagnostic {
        kind: "backend-capability".to_string(),
        message: format!(
            "compiler backend capability detection: requested={}, resolved={}, rustupAvailable={}, toolchainAvailable={}, nightly={}, embeddedBackend={}, host={}",
            capabilities.requested_toolchain,
            capabilities.resolved_toolchain,
            capabilities.rustup_available,
            capabilities.toolchain_available,
            capabilities.nightly_toolchain,
            capabilities.embedded_backend_supported,
            capabilities.host
        ),
        package_path: None,
        file_path: None,
        position: Some(Position {
            filename: root.display().to_string(),
            line: 0,
            column: 0,
        }),
    }
}

fn resolve_toolchain(requested: &str, available_toolchains: &[String]) -> String {
    if requested != "auto" {
        return requested.to_string();
    }
    if available_toolchains
        .iter()
        .any(|toolchain| toolchain.starts_with("nightly"))
    {
        return "nightly".to_string();
    }
    if available_toolchains
        .iter()
        .any(|toolchain| toolchain.starts_with("stable"))
    {
        return "stable".to_string();
    }
    "stable".to_string()
}

fn capture_toolchain_rustc_version(toolchain: &str, rustup_available: bool) -> String {
    if rustup_available && !toolchain.is_empty() {
        let value = capture_command_output("rustup", &["run", toolchain, "rustc", "-Vv"]);
        if value != "unknown" && !value.is_empty() {
            return value;
        }
    }
    capture_command_output("rustc", &["-Vv"])
}

fn capture_toolchain_cargo_version(toolchain: &str, rustup_available: bool) -> String {
    if rustup_available && !toolchain.is_empty() {
        let toolchain_arg = format!("+{toolchain}");
        let value = capture_command_output("cargo", &[&toolchain_arg, "-V"]);
        if value != "unknown" && !value.is_empty() {
            return value;
        }
    }
    capture_command_output("cargo", &["-V"])
}

fn detect_host(_analysis_root: &Path, toolchain: &str, rustup_available: bool) -> String {
    let version = capture_toolchain_rustc_version(toolchain, rustup_available);
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS))
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

fn cargo_check_target_args(include_tests: bool) -> &'static [&'static str] {
    if include_tests { &["--all-targets"] } else { &[] }
}

fn rusi_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn ensure_embedded_wrapper_built(capabilities: &DriverCapabilities, debug: bool) -> Result<PathBuf> {
    let workspace_root = rusi_workspace_root();
    let manifest_path = workspace_root.join("Cargo.toml");
    let mut command = Command::new("cargo");
    command.current_dir(&workspace_root);
    if capabilities.rustup_available && !capabilities.resolved_toolchain.is_empty() {
        command.arg(format!("+{}", capabilities.resolved_toolchain));
    }
    command.args(["build", "--manifest-path"]);
    command.arg(&manifest_path);
    command.args(["-p", "rusi-rustc-wrapper"]);
    debug_log(
        debug,
        format_args!(
            "pass=embedded-wrapper-build root={} toolchain={}",
            workspace_root.display(),
            capabilities.resolved_toolchain
        ),
    );
    if debug {
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| {
                format!(
                    "failed to build embedded compiler wrapper from {}",
                    workspace_root.display()
                )
            })?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "failed to build embedded compiler wrapper; see debug output above"
            ));
        }
    } else {
        let output = command.output().with_context(|| {
            format!(
                "failed to build embedded compiler wrapper from {}",
                workspace_root.display()
            )
        })?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to build embedded compiler wrapper: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    let wrapper = workspace_root.join("target/debug/rusi-rustc-wrapper");
    if wrapper.exists() {
        Ok(wrapper)
    } else {
        Err(anyhow::anyhow!(
            "embedded compiler wrapper binary not found at {}",
            wrapper.display()
        ))
    }
}

fn collect_embedded_compiler_evidence(
    analysis_root: &Path,
    options: &DriverOptions,
    capabilities: &DriverCapabilities,
) -> Result<CompilerEvidence> {
    let wrapper = ensure_embedded_wrapper_built(capabilities, options.debug)?;
    let emit_dir = scoped_child_dir(analysis_root, &["target", "rusi-embedded"])?;
    let build_target_dir = scoped_child_dir(analysis_root, &["target", "rusi-embedded-build"])?;
    if emit_dir.exists() {
        fs::remove_dir_all(&emit_dir)
            .with_context(|| format!("failed to clear {}", emit_dir.display()))?;
    }
    if build_target_dir.exists() {
        fs::remove_dir_all(&build_target_dir)
            .with_context(|| format!("failed to clear {}", build_target_dir.display()))?;
    }
    fs::create_dir_all(&emit_dir)
        .with_context(|| format!("failed to create {}", emit_dir.display()))?;
    fs::create_dir_all(&build_target_dir)
        .with_context(|| format!("failed to create {}", build_target_dir.display()))?;
    ensure_directory_within_root(analysis_root, &emit_dir)?;
    ensure_directory_within_root(analysis_root, &build_target_dir)?;

    let mut command = Command::new("cargo");
    command.current_dir(analysis_root);
    if capabilities.rustup_available && !capabilities.resolved_toolchain.is_empty() {
        command.arg(format!("+{}", capabilities.resolved_toolchain));
    }
    command.arg("check");
    command.args(cargo_check_target_args(options.include_tests));
    command.env("RUSTC_WRAPPER", &wrapper);
    command.env("RUSI_EMIT_DIR", &emit_dir);
    command.env("RUSI_ANALYSIS_ROOT", analysis_root);
    command.env("RUSI_DATA_FLOW_MODE", &options.data_flow_mode);
    if options.debug {
        command.env("RUSI_DEBUG", "1");
    }
    command.env("CARGO_TARGET_DIR", &build_target_dir);
    command.env("CARGO_INCREMENTAL", "0");
    debug_log(
        options.debug,
        format_args!(
            "pass=embedded-cargo-check root={} target_dir={} toolchain={} dataflow={} targets={} wrapper={}",
            analysis_root.display(),
            build_target_dir.display(),
            capabilities.resolved_toolchain,
            options.data_flow_mode,
            if options.include_tests { "all-targets" } else { "default" },
            wrapper.display()
        ),
    );
    if options.debug {
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| {
                format!(
                    "failed to run embedded compiler backend for {}",
                    analysis_root.display()
                )
            })?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "embedded compiler backend failed for {}; see debug output above",
                analysis_root.display()
            ));
        }
    } else {
        let output = command.output().with_context(|| {
            format!(
                "failed to run embedded compiler backend for {}",
                analysis_root.display()
            )
        })?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "embedded compiler backend failed for {}: {}",
                analysis_root.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    let mut merger = CompilerEvidenceMerger::default();
    let mut found = false;
    for entry in
        fs::read_dir(&emit_dir).with_context(|| format!("failed to read {}", emit_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let artifact: CompilerEvidence = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse compiler artifact {}", path.display()))?;
            found = true;
            merger.merge(artifact);
        }
    }
    if !found {
        return Err(anyhow::anyhow!(
            "embedded compiler backend produced no artifacts in {}",
            emit_dir.display()
        ));
    }
    Ok(merger.finish())
}

/// Accumulates per-crate [`CompilerEvidence`] artifacts into a single merged
/// result in O(total items) time.
///
/// The previous implementation deduplicated every incoming item with a linear
/// `Vec::iter().any(|e| e.id == ...)` scan against the growing accumulator,
/// making whole-program merging O(n²) over the hundreds of per-crate artifacts
/// a large workspace emits. This struct keeps a hash index per collection so
/// each membership test is amortized O(1), and computes stats once at the end
/// instead of after every artifact.
#[derive(Default)]
struct CompilerEvidenceMerger {
    evidence: CompilerEvidence,
    import_keys: HashSet<String>,
    declaration_ids: HashSet<String>,
    usage_ids: HashSet<String>,
    signal_ids: HashSet<String>,
    crypto: CryptoDedup,
    file_index: HashMap<String, usize>,
    file_dedup: Vec<FileDedup>,
    call_graph_node_ids: HashSet<String>,
    call_graph_edge_ids: HashSet<String>,
    call_graph_diagnostic_keys: HashSet<String>,
    data_flow_node_ids: HashSet<String>,
    data_flow_edge_ids: HashSet<String>,
    data_flow_slice_ids: HashSet<String>,
    data_flow_summary_ids: HashSet<String>,
    data_flow_diagnostic_keys: HashSet<String>,
}

/// Per-file dedup indices, kept parallel to `CompilerEvidenceMerger::evidence.files`.
#[derive(Default)]
struct FileDedup {
    import_keys: HashSet<String>,
    declaration_ids: HashSet<String>,
    usage_ids: HashSet<String>,
    signal_ids: HashSet<String>,
    crypto: CryptoDedup,
}

#[derive(Default)]
struct CryptoDedup {
    library_ids: HashSet<String>,
    component_ids: HashSet<String>,
    material_ids: HashSet<String>,
    finding_ids: HashSet<String>,
}

impl CompilerEvidenceMerger {
    fn merge(&mut self, artifact: CompilerEvidence) {
        let CompilerEvidence {
            diagnostics,
            files,
            imports,
            declarations,
            usages,
            security_signals,
            crypto,
            call_graph,
            data_flow,
        } = artifact;

        // Top-level diagnostics were never deduplicated by the original merge;
        // preserve that so repeated backend diagnostics are still reported.
        self.evidence.diagnostics.extend(diagnostics);
        for file in files {
            self.merge_file(file);
        }
        insert_unique_by(
            &mut self.evidence.imports,
            &mut self.import_keys,
            imports,
            import_key,
        );
        insert_unique_by(
            &mut self.evidence.declarations,
            &mut self.declaration_ids,
            declarations,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut self.evidence.usages,
            &mut self.usage_ids,
            usages,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut self.evidence.security_signals,
            &mut self.signal_ids,
            security_signals,
            |item| item.id.clone(),
        );
        merge_crypto_indexed(&mut self.evidence.crypto, crypto, &mut self.crypto);
        self.merge_call_graph(call_graph);
        self.merge_data_flow(data_flow);
    }

    fn merge_file(&mut self, file: FileEvidence) {
        if let Some(&index) = self.file_index.get(&file.path) {
            let existing = &mut self.evidence.files[index];
            let dedup = &mut self.file_dedup[index];
            insert_unique_by(
                &mut existing.imports,
                &mut dedup.import_keys,
                file.imports,
                import_key,
            );
            insert_unique_by(
                &mut existing.declarations,
                &mut dedup.declaration_ids,
                file.declarations,
                |item| item.id.clone(),
            );
            insert_unique_by(
                &mut existing.usages,
                &mut dedup.usage_ids,
                file.usages,
                |item| item.id.clone(),
            );
            insert_unique_by(
                &mut existing.security_signals,
                &mut dedup.signal_ids,
                file.security_signals,
                |item| item.id.clone(),
            );
            merge_crypto_indexed(&mut existing.crypto, file.crypto, &mut dedup.crypto);
        } else {
            // Seed the dedup indices from the freshly inserted file so later
            // artifacts touching the same path merge against its contents.
            let mut dedup = FileDedup::default();
            dedup
                .import_keys
                .extend(file.imports.iter().map(import_key));
            dedup
                .declaration_ids
                .extend(file.declarations.iter().map(|item| item.id.clone()));
            dedup
                .usage_ids
                .extend(file.usages.iter().map(|item| item.id.clone()));
            dedup
                .signal_ids
                .extend(file.security_signals.iter().map(|item| item.id.clone()));
            if let Some(crypto) = &file.crypto {
                seed_crypto_dedup(&mut dedup.crypto, crypto);
            }
            self.file_index.insert(file.path.clone(), self.evidence.files.len());
            self.evidence.files.push(file);
            self.file_dedup.push(dedup);
        }
    }

    fn merge_call_graph(&mut self, incoming: Option<CallGraph>) {
        let Some(incoming) = incoming else {
            return;
        };
        let existing = self.evidence.call_graph.get_or_insert_with(|| CallGraph {
            mode: incoming.mode.clone(),
            ..CallGraph::default()
        });
        merge_mode(&mut existing.mode, &incoming.mode);
        insert_unique_by(
            &mut existing.nodes,
            &mut self.call_graph_node_ids,
            incoming.nodes,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut existing.edges,
            &mut self.call_graph_edge_ids,
            incoming.edges,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut existing.diagnostics,
            &mut self.call_graph_diagnostic_keys,
            incoming.diagnostics,
            diagnostic_key,
        );
    }

    fn merge_data_flow(&mut self, incoming: Option<DataFlowEvidence>) {
        let Some(incoming) = incoming else {
            return;
        };
        let existing = self.evidence.data_flow.get_or_insert_with(|| DataFlowEvidence {
            mode: incoming.mode.clone(),
            patterns: incoming.patterns.clone(),
            ..DataFlowEvidence::default()
        });
        merge_mode(&mut existing.mode, &incoming.mode);
        if existing.patterns.sources.is_empty()
            && existing.patterns.sinks.is_empty()
            && existing.patterns.passthroughs.is_empty()
        {
            existing.patterns = incoming.patterns.clone();
        }
        insert_unique_by(
            &mut existing.nodes,
            &mut self.data_flow_node_ids,
            incoming.nodes,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut existing.edges,
            &mut self.data_flow_edge_ids,
            incoming.edges,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut existing.slices,
            &mut self.data_flow_slice_ids,
            incoming.slices,
            |item| item.id.clone(),
        );
        insert_unique_by(
            &mut existing.summaries,
            &mut self.data_flow_summary_ids,
            incoming.summaries,
            |item| item.function_id.clone(),
        );
        insert_unique_by(
            &mut existing.diagnostics,
            &mut self.data_flow_diagnostic_keys,
            incoming.diagnostics,
            diagnostic_key,
        );
    }

    /// Finalize the merged evidence, computing graph/data-flow stats once over
    /// the fully merged collections rather than recomputing after each artifact.
    fn finish(mut self) -> CompilerEvidence {
        if let Some(call_graph) = &mut self.evidence.call_graph {
            call_graph.stats = GraphStats {
                node_count: call_graph.nodes.len(),
                edge_count: call_graph.edges.len(),
            };
        }
        if let Some(data_flow) = &mut self.evidence.data_flow {
            data_flow.stats = DataFlowStats {
                source_count: data_flow.nodes.iter().filter(|node| node.source).count(),
                sink_count: data_flow.nodes.iter().filter(|node| node.sink).count(),
                slice_count: data_flow.slices.len(),
                node_count: data_flow.nodes.len(),
                edge_count: data_flow.edges.len(),
                summary_count: data_flow.summaries.len(),
            };
        }
        self.evidence
    }
}

/// Append every item from `incoming` to `target` whose key has not been seen
/// before, recording the key in `seen`. Amortized O(1) per item.
fn insert_unique_by<T, K, F>(target: &mut Vec<T>, seen: &mut HashSet<K>, incoming: Vec<T>, key: F)
where
    K: Eq + std::hash::Hash,
    F: Fn(&T) -> K,
{
    target.reserve(incoming.len());
    for item in incoming {
        if seen.insert(key(&item)) {
            target.push(item);
        }
    }
}

fn merge_crypto_indexed(
    target: &mut Option<CryptoEvidence>,
    incoming: Option<CryptoEvidence>,
    dedup: &mut CryptoDedup,
) {
    let Some(incoming) = incoming else {
        return;
    };
    let existing = target.get_or_insert_with(CryptoEvidence::default);
    insert_unique_by(
        &mut existing.libraries,
        &mut dedup.library_ids,
        incoming.libraries,
        |item| item.id.clone(),
    );
    insert_unique_by(
        &mut existing.components,
        &mut dedup.component_ids,
        incoming.components,
        |item| item.id.clone(),
    );
    insert_unique_by(
        &mut existing.materials,
        &mut dedup.material_ids,
        incoming.materials,
        |item| item.id.clone(),
    );
    insert_unique_by(
        &mut existing.findings,
        &mut dedup.finding_ids,
        incoming.findings,
        |item| item.id.clone(),
    );
    for (key, value) in incoming.properties {
        existing.properties.entry(key).or_insert(value);
    }
}

fn seed_crypto_dedup(dedup: &mut CryptoDedup, crypto: &CryptoEvidence) {
    dedup
        .library_ids
        .extend(crypto.libraries.iter().map(|item| item.id.clone()));
    dedup
        .component_ids
        .extend(crypto.components.iter().map(|item| item.id.clone()));
    dedup
        .material_ids
        .extend(crypto.materials.iter().map(|item| item.id.clone()));
    dedup
        .finding_ids
        .extend(crypto.findings.iter().map(|item| item.id.clone()));
}

fn merge_mode(existing: &mut String, incoming: &str) {
    if existing.is_empty() {
        *existing = incoming.to_string();
    } else if existing != incoming && !existing.contains(incoming) {
        *existing = format!("{existing},{incoming}");
    }
}

/// Stable dedup key for an [`ImportUsage`], matching the original tuple equality
/// over `(path, alias, package_path, position)`.
fn import_key(import_usage: &ImportUsage) -> String {
    format!(
        "{}\u{1}{:?}\u{1}{}\u{1}{}:{}:{}",
        import_usage.path,
        import_usage.alias,
        import_usage.package_path,
        import_usage.position.filename,
        import_usage.position.line,
        import_usage.position.column,
    )
}

/// Stable dedup key for a [`Diagnostic`], matching the original full-struct
/// equality used by `extend_unique_diagnostics`.
fn diagnostic_key(diagnostic: &Diagnostic) -> String {
    let position = diagnostic
        .position
        .as_ref()
        .map(|position| format!("{}:{}:{}", position.filename, position.line, position.column))
        .unwrap_or_default();
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        diagnostic.kind,
        diagnostic.message,
        diagnostic.package_path.as_deref().unwrap_or(""),
        diagnostic.file_path.as_deref().unwrap_or(""),
        position,
    )
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

fn enrich_payload_purls(metadata: &Metadata, payload: &mut DriverProtocolPayload) {
    let package_purls = metadata_package_purls(metadata);
    for file in &mut payload.files {
        file.purl = resolve_package_purl(&file.package_path, &package_purls);
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
    for declaration in &mut payload.declarations {
        declaration.purl = resolve_package_purl(&declaration.package_path, &package_purls);
    }
    for usage in &mut payload.usages {
        usage.purl = resolve_package_purl(&usage.package_path, &package_purls);
    }
    for signal in &mut payload.security_signals {
        signal.purl = resolve_package_purl(&signal.package_path, &package_purls);
    }
    if let Some(call_graph) = &mut payload.call_graph {
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
    if let Some(data_flow) = &mut payload.data_flow {
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

fn metadata_package_purls(metadata: &Metadata) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for package in metadata.workspace_packages() {
        let version = package.version.to_string();
        let purl = build_cargo_purl(&package.name, Some(&version));
        for key in [package.name.to_string(), package.name.replace('-', "_")] {
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
    let mut purls = std::collections::BTreeSet::new();
    if !source_purl.is_empty() {
        purls.insert(source_purl.to_string());
    }
    if !target_purl.is_empty() {
        purls.insert(target_purl.to_string());
    }
    purls.into_iter().collect()
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

fn inferred_package_path(value: &str) -> String {
    if value.contains("::") {
        value.split("::").next().unwrap_or(value).to_string()
    } else {
        String::new()
    }
}

fn collect_native_interop_evidence(
    analysis_root: &Path,
    metadata: &Metadata,
    include_tests: bool,
    debug: bool,
) -> Result<NativeInteropEvidence> {
    let mut files = BTreeMap::<String, FileEvidence>::new();
    let mut declarations = Vec::new();
    let mut usages = Vec::new();
    let mut security_signals = Vec::new();
    let mut foreign_symbols = HashMap::new();

    for package in metadata.workspace_packages() {
        let package_ctx = package_context(package)?;
        debug_log(
            debug,
            format_args!(
                "pass=native-file-discovery package={}",
                package_ctx.crate_name
            ),
        );
        let rust_files = discover_rust_files(&package_ctx, include_tests)?;
        for file_path in rust_files {
            debug_log(
                debug,
                format_args!(
                    "pass=native-interop-file file={}",
                    relative_display_path(analysis_root, &file_path)
                ),
            );
            let source = fs::read_to_string(&file_path)
                .with_context(|| format!("failed to read {}", file_path.display()))?;
            let syntax: File = syn::parse_file(&source)
                .with_context(|| format!("failed to parse {}", file_path.display()))?;
            let relative_file_path = relative_display_path(analysis_root, &file_path);
            let module_path = module_path_for_file(&package_ctx, &file_path);
            let mut collector = NativeInteropCollector::new(NativeFileContext {
                package_name: package_ctx.package_name.clone(),
                package_path: package_ctx.crate_name.clone(),
                relative_file_path,
                module_path,
            });
            collector.visit_file(&syntax);
            if let Some(file) = collector.file_evidence() {
                files.insert(file.path.clone(), file);
            }
            declarations.extend(collector.declarations);
            usages.extend(collector.usages);
            security_signals.extend(collector.security_signals);
            foreign_symbols.extend(collector.foreign_symbols);
        }
    }

    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    usages.sort_by(|left, right| left.id.cmp(&right.id));
    security_signals.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(NativeInteropEvidence {
        files: files.into_values().collect(),
        declarations,
        usages,
        security_signals,
        foreign_symbols,
    })
}

fn package_context(package: &Package) -> Result<PackageContext> {
    let manifest_path = fs::canonicalize(package.manifest_path.as_std_path()).with_context(|| {
        format!(
            "failed to resolve package manifest {}",
            package.manifest_path.as_std_path().display()
        )
    })?;
    let root_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .context("package manifest has no parent directory")?;
    Ok(PackageContext {
        package_name: package.name.to_string(),
        crate_name: package.name.replace('-', "_"),
        src_dir: root_dir.join("src"),
        root_dir,
    })
}

fn discover_rust_files(package_ctx: &PackageContext, include_tests: bool) -> Result<Vec<PathBuf>> {
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
    let canonical_dir = fs::canonicalize(dir)
        .with_context(|| format!("failed to resolve {}", dir.display()))?;
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

fn scoped_child_dir(root: &Path, components: &[&str]) -> Result<PathBuf> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("failed to resolve compiler backend root {}", root.display()))?;
    let mut path = root.clone();
    for component in components {
        path.push(component);
        ensure_safe_directory_component(&path)?;
    }
    Ok(path)
}

fn ensure_safe_directory_component(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to use symlinked compiler artifact path {}",
                    path.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "compiler artifact path component {} exists and is not a directory",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect compiler artifact path {}", path.display()))
        }
    }
    Ok(())
}

fn ensure_directory_within_root(root: &Path, path: &Path) -> Result<()> {
    let canonical_root = fs::canonicalize(root)
        .with_context(|| format!("failed to resolve compiler backend root {}", root.display()))?;
    let canonical_path = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve compiler artifact directory {}", path.display()))?;
    if !canonical_path.starts_with(&canonical_root) {
        anyhow::bail!(
            "compiler artifact directory {} escapes analysis root {}",
            canonical_path.display(),
            canonical_root.display()
        );
    }
    Ok(())
}

fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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

struct NativeInteropCollector {
    file_ctx: NativeFileContext,
    module_stack: Vec<String>,
    declarations: Vec<Declaration>,
    usages: Vec<LibraryUsage>,
    security_signals: Vec<SecuritySignal>,
    foreign_symbols: HashMap<String, ForeignFunctionInfo>,
}

impl NativeInteropCollector {
    fn new(file_ctx: NativeFileContext) -> Self {
        Self {
            file_ctx,
            module_stack: Vec::new(),
            declarations: Vec::new(),
            usages: Vec::new(),
            security_signals: Vec::new(),
            foreign_symbols: HashMap::new(),
        }
    }

    fn file_evidence(&self) -> Option<FileEvidence> {
        if self.declarations.is_empty()
            && self.usages.is_empty()
            && self.security_signals.is_empty()
        {
            return None;
        }
        Some(FileEvidence {
            path: self.file_ctx.relative_file_path.clone(),
            package_name: self.file_ctx.package_name.clone(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            imports: Vec::new(),
            declarations: self.declarations.clone(),
            usages: self.usages.clone(),
            security_signals: self.security_signals.clone(),
            crypto: None,
        })
    }

    fn current_module_path(&self) -> Vec<String> {
        let mut path = self.file_ctx.module_path.clone();
        path.extend(self.module_stack.clone());
        path
    }

    fn qualify_name(&self, name: &str) -> String {
        let mut segments = vec![self.file_ctx.package_path.clone()];
        segments.extend(self.current_module_path());
        segments.push(name.to_string());
        segments.join("::")
    }

    fn push_declaration(
        &mut self,
        name: &str,
        kind: &str,
        signature: String,
        span: Span,
    ) -> Declaration {
        let qualified_name = self.qualify_name(name);
        let declaration = Declaration {
            id: stable_id("decl", &[&self.file_ctx.package_path, &qualified_name]),
            name: name.to_string(),
            canonical_name: rusi_schema::canonical_name(&qualified_name),
            qualified_name,
            kind: kind.to_string(),
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            file_path: self.file_ctx.relative_file_path.clone(),
            signature,
            receiver: None,
            position: position_from_span(&self.file_ctx.relative_file_path, span),
        };
        self.declarations.push(declaration.clone());
        declaration
    }

    fn push_signal(&mut self, kind: &str, description: String, span: Span) {
        self.security_signals.push(SecuritySignal {
            id: stable_id(
                "signal",
                &[&self.file_ctx.relative_file_path, kind, &span_key(span)],
            ),
            category: "native-interop".to_string(),
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            description,
            package_path: self.file_ctx.package_path.clone(),
            purl: String::new(),
            file_path: self.file_ctx.relative_file_path.clone(),
            position: position_from_span(&self.file_ctx.relative_file_path, span),
        });
    }
}

impl<'ast> Visit<'ast> for NativeInteropCollector {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_some() {
            self.module_stack.push(node.ident.to_string());
            syn::visit::visit_item_mod(self, node);
            self.module_stack.pop();
        } else {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        let abi = node
            .abi
            .name
            .as_ref()
            .map(LitStr::value)
            .unwrap_or_else(|| "C".to_string());
        self.push_signal(
            "extern-block",
            format!("extern {abi} block detected"),
            node.span(),
        );
        if let Some(link_name) = parse_link_attribute_name(&node.attrs) {
            let mut properties = IndexMap::new();
            properties.insert("abi".to_string(), abi.clone());
            self.usages.push(LibraryUsage {
                id: stable_id(
                    "usage",
                    &[
                        &self.file_ctx.relative_file_path,
                        "native-link",
                        &link_name,
                        &span_key(node.span()),
                    ],
                ),
                kind: "native-link".to_string(),
                name: link_name,
                package_path: self.file_ctx.package_path.clone(),
                purl: String::new(),
                enclosing_declaration: None,
                position: position_from_span(&self.file_ctx.relative_file_path, node.span()),
                properties,
            });
        }
        for item in &node.items {
            match item {
                ForeignItem::Fn(function) => {
                    let declaration = self.push_declaration(
                        &function.sig.ident.to_string(),
                        "foreign-function",
                        signature_text(&function.sig),
                        function.sig.ident.span(),
                    );
                    self.push_signal(
                        "foreign-function",
                        format!(
                            "foreign function {} declared with ABI {abi}",
                            declaration.qualified_name
                        ),
                        function.sig.ident.span(),
                    );
                    self.foreign_symbols.insert(
                        function.sig.ident.to_string(),
                        ForeignFunctionInfo {
                            declaration,
                            parameter_types: function_parameter_types(&function.sig),
                            abi: abi.clone(),
                            link_name: parse_link_attribute_name(&node.attrs),
                        },
                    );
                }
                ForeignItem::Static(item_static) => {
                    self.push_declaration(
                        &item_static.ident.to_string(),
                        "foreign-static",
                        item_static.to_token_stream().to_string(),
                        item_static.ident.span(),
                    );
                    self.push_signal(
                        "foreign-static",
                        format!(
                            "foreign static {} declared with ABI {abi}",
                            item_static.ident
                        ),
                        item_static.ident.span(),
                    );
                }
                ForeignItem::Type(item_type) => {
                    self.push_declaration(
                        &item_type.ident.to_string(),
                        "foreign-type",
                        item_type.to_token_stream().to_string(),
                        item_type.ident.span(),
                    );
                }
                _ => {}
            }
        }
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if node.sig.abi.is_some() || has_export_attribute(&node.attrs) {
            self.push_signal(
                "native-export",
                format!(
                    "extern/exported Rust function {} detected",
                    self.qualify_name(&node.sig.ident.to_string())
                ),
                node.sig.ident.span(),
            );
        }
        syn::visit::visit_item_fn(self, node);
    }
}

fn parse_link_attribute_name(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("link") {
            let mut value = None;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    value = Some(meta.value()?.parse::<LitStr>()?.value());
                }
                Ok(())
            });
            if value.is_some() {
                return value;
            }
        }
    }
    None
}

fn has_export_attribute(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("no_mangle") || attr.path().is_ident("export_name") {
            return true;
        }
        if attr.path().is_ident("unsafe") {
            let mut found = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("no_mangle") || meta.path.is_ident("export_name") {
                    found = true;
                }
                Ok(())
            });
            if found {
                return true;
            }
        }
    }
    false
}

fn function_parameter_types(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .map(|input| match input {
            syn::FnArg::Typed(pat_type) => pat_type.ty.to_token_stream().to_string(),
            syn::FnArg::Receiver(receiver) => {
                if receiver.reference.is_some() {
                    if receiver.mutability.is_some() {
                        "&mut Self".to_string()
                    } else {
                        "&Self".to_string()
                    }
                } else {
                    "Self".to_string()
                }
            }
        })
        .collect()
}

fn signature_text(sig: &Signature) -> String {
    let mut text = sig.to_token_stream().to_string();
    if let ReturnType::Default = sig.output {
        text = text.replace(" ->", "");
    }
    text
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use pretty_assertions::assert_eq;

    use super::{
        BACKEND_KIND_EMBEDDED, BACKEND_KIND_STUB, DRIVER_PROTOCOL_VERSION, DriverOptions,
        DriverProtocolEnvelope, PackageContext, cargo_check_target_args, detect_capabilities,
        discover_rust_files, run_driver, scoped_child_dir,
    };
    use rusi_core::{AnalysisScope, AnalyzeOptionsInput};

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
        let path = std::env::temp_dir().join(format!("rusi-driver-{prefix}-{timestamp}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    fn create_dir_symlink(src: &std::path::Path, dst: &std::path::Path) {
        std::os::unix::fs::symlink(src, dst).expect("create directory symlink");
    }

    fn test_guard() -> MutexGuard<'static, ()> {
        static DRIVER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        DRIVER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn cargo_check_skips_test_targets_by_default() {
        assert!(cargo_check_target_args(false).is_empty());
        assert_eq!(cargo_check_target_args(true), &["--all-targets"]);
    }

    #[cfg(unix)]
    #[test]
    fn driver_skips_symlinked_source_directories_during_file_discovery() {
        let _guard = test_guard();
        let root = temp_dir("symlink-root");
        let outside = temp_dir("symlink-outside");
        let outside_src = outside.join("src");
        fs::create_dir_all(&outside_src).expect("create outside src");
        fs::write(outside_src.join("main.rs"), "fn main() {}\n").expect("write external main.rs");
        create_dir_symlink(&outside_src, &root.join("src"));

        let package_ctx = PackageContext {
            package_name: "symlink-skip".to_string(),
            crate_name: "symlink_skip".to_string(),
            root_dir: fs::canonicalize(&root).expect("canonical root"),
            src_dir: root.join("src"),
        };
        let files = discover_rust_files(&package_ctx, false).expect("file discovery succeeds");
        assert!(files.is_empty());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn compiler_artifact_dirs_reject_symlinked_target_ancestors() {
        let _guard = test_guard();
        let root = temp_dir("artifact-root");
        let outside = temp_dir("artifact-outside");
        create_dir_symlink(&outside, &root.join("target"));

        let error = scoped_child_dir(&root, &["target", "rusi-embedded"]) 
            .expect_err("symlinked artifact path must be rejected");
        assert!(error.to_string().contains("symlinked compiler artifact path"));

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn driver_options_can_be_derived_from_analyze_options() {
        let _guard = test_guard();
        let options = AnalyzeOptionsInput {
            dir: fixture_path("basic-app"),
            backend: "compiler".to_string(),
            analysis_scope: AnalysisScope::Default,
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            custom_data_flow_patterns: None,
            include_tests: true,
            debug: false,
        };
        let driver_options = DriverOptions::from_analyze_options(&options);
        assert_eq!(driver_options.analysis_root, options.dir);
        assert_eq!(driver_options.call_graph_mode, "static");
        assert_eq!(driver_options.data_flow_mode, "security");
        assert!(driver_options.include_tests);
        assert_eq!(driver_options.rustc_toolchain, "auto");
    }

    #[test]
    fn driver_protocol_round_trips_via_json() {
        let _guard = test_guard();
        let options = DriverOptions {
            analysis_root: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "nightly".to_string(),
            debug: false,
        };
        let envelope = run_driver(&options).expect("driver run succeeds");
        assert_eq!(envelope.protocol_version, DRIVER_PROTOCOL_VERSION);
        assert!(matches!(
            envelope.backend_kind.as_str(),
            BACKEND_KIND_STUB | BACKEND_KIND_EMBEDDED
        ));
        let json = serde_json::to_string_pretty(&envelope).expect("serialize envelope");
        let decoded: DriverProtocolEnvelope =
            serde_json::from_str(&json).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn capability_detection_produces_consistent_invariants() {
        let _guard = test_guard();
        let options = DriverOptions {
            analysis_root: fixture_path("expanded-packs-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        };
        let capabilities = detect_capabilities(&options, &options.analysis_root);
        assert!(!capabilities.resolved_toolchain.is_empty());
        if capabilities.embedded_backend_supported {
            assert!(capabilities.toolchain_available);
            assert!(capabilities.nightly_toolchain);
            assert!(capabilities.rustup_available);
        }
        if !capabilities.toolchain_available || !capabilities.nightly_toolchain {
            assert!(!capabilities.embedded_backend_supported);
        }
        assert!(!capabilities.rustc_version.is_empty());
        assert!(!capabilities.cargo_version.is_empty());
    }

    #[test]
    fn stable_toolchain_disables_embedded_backend_capability() {
        let _guard = test_guard();
        let options = DriverOptions {
            analysis_root: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "stable".to_string(),
            debug: false,
        };
        let envelope = run_driver(&options).expect("driver run succeeds");
        assert_eq!(envelope.capabilities.requested_toolchain, "stable");
        assert_eq!(envelope.capabilities.resolved_toolchain, "stable");
        assert!(!envelope.capabilities.embedded_backend_supported);
        assert!(envelope.payload.call_graph.is_none());
        assert!(envelope.payload.data_flow.is_none());
    }

    #[test]
    #[ignore = "compiler backend: needs nightly rustc-dev and runs nested cargo. Run: cargo +nightly test -- --ignored --test-threads=1"]
    fn driver_collects_real_compiler_evidence_when_embedded_backend_is_available() {
        let _guard = test_guard();
        let options = DriverOptions {
            analysis_root: fixture_path("basic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        };
        let envelope = run_driver(&options).expect("driver run succeeds");

        if envelope.capabilities.embedded_backend_supported {
            assert_eq!(envelope.backend_kind, BACKEND_KIND_EMBEDDED);
            let graph = envelope.payload.call_graph.expect("MIR callgraph emitted");
            let flow = envelope.payload.data_flow.expect("MIR dataflow emitted");
            assert!(
                graph
                    .edges
                    .iter()
                    .any(|edge| edge.source_name.ends_with("main")
                        && edge.target_name.ends_with("run_command"))
            );
            let has_direct_slice = flow.slices.iter().any(|slice| {
                slice.source_category == "env"
                    && slice.sink_category == "process-exec"
                    && slice.sink_parameter_index == Some(0)
            });
            let has_summary_chain = flow.summaries.iter().any(|summary| {
                summary.function.ends_with("read_secret")
                    && summary.source_returns.iter().any(|source| source == "env")
            }) && flow.summaries.iter().any(|summary| {
                summary.function.ends_with("run_command")
                    && summary
                        .param_to_sink
                        .get("process-exec")
                        .is_some_and(|indexes| indexes.contains(&0))
            });
            assert!(has_direct_slice || has_summary_chain);
            assert!(flow.summaries.iter().any(|summary| {
                summary.function.ends_with("run_command")
                    && summary
                        .parameter_types
                        .iter()
                        .any(|ty| ty.contains("String"))
            }));
        } else {
            assert_eq!(envelope.backend_kind, BACKEND_KIND_STUB);
        }
    }

    #[test]
    fn driver_collects_native_interop_evidence() {
        let _guard = test_guard();
        let options = DriverOptions {
            analysis_root: fixture_path("ffi-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        };
        let envelope = run_driver(&options).expect("driver run succeeds");
        assert!(
            envelope
                .payload
                .declarations
                .iter()
                .any(|declaration| declaration.name == "puts"
                    && declaration.qualified_name.ends_with("puts"))
        );
        assert!(
            envelope
                .payload
                .security_signals
                .iter()
                .any(|signal| signal.category == "native-interop")
        );
        let _ = envelope.payload.data_flow;
    }

    #[test]
    fn driver_resolves_dyn_dispatch_candidate_sets() {
        let _guard = test_guard();
        let envelope = run_driver(&DriverOptions {
            analysis_root: fixture_path("dyn-dispatch-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        })
        .expect("driver run succeeds");

        if envelope.backend_kind == BACKEND_KIND_EMBEDDED {
            let dyn_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| {
                    usage.kind == "method-call"
                        && usage.name.contains("persist")
                        && usage
                            .properties
                            .get("candidateTargets")
                            .is_some_and(|value| {
                                value.contains("FileStore") && value.contains("NetStore")
                            })
                })
                .expect("dynamic dispatch candidate set exists");
            let candidates = dyn_usage
                .properties
                .get("candidateTargets")
                .cloned()
                .unwrap_or_default();
            assert!(candidates.contains("<FileStore as Store>::persist"));
            assert!(candidates.contains("<NetStore as Store>::persist"));
        }
    }

    #[test]
    fn driver_collects_async_closure_and_crypto_evidence() {
        let _guard = test_guard();
        let envelope = run_driver(&DriverOptions {
            analysis_root: fixture_path("async-crypto-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        })
        .expect("driver run succeeds");

        if envelope.backend_kind == BACKEND_KIND_EMBEDDED {
            assert!(
                envelope
                    .payload
                    .security_signals
                    .iter()
                    .any(|signal| signal.category == "async-model")
            );
            assert!(
                envelope
                    .payload
                    .security_signals
                    .iter()
                    .any(|signal| signal.category == "closure-model")
            );
            let crypto = envelope.payload.crypto.expect("crypto evidence emitted");
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
                    .any(|component| component.algorithm == "SHA-256")
            );
            assert!(
                crypto
                    .materials
                    .iter()
                    .any(|material| material.kind == "key")
            );
            let flow = envelope.payload.data_flow.expect("dataflow emitted");
            let has_crypto_key_slice = flow
                .slices
                .iter()
                .any(|slice| slice.sink_category == "crypto-key");
            let has_crypto_key_usage = envelope.payload.usages.iter().any(|usage| {
                usage.name.contains("new_from_slice")
                    && usage
                        .properties
                        .get("resolvedSymbol")
                        .is_some_and(|symbol| {
                            symbol.contains("aes_gcm::aead::KeyInit::new_from_slice")
                        })
            });
            assert!(
                has_crypto_key_slice || has_crypto_key_usage,
                "expected either a crypto-key slice or direct crypto-key sink usage evidence"
            );
        }
    }

    #[test]
    fn driver_tracks_generic_specialization_and_edge_precision_metadata() {
        let _guard = test_guard();
        let envelope = run_driver(&DriverOptions {
            analysis_root: fixture_path("generic-specialization-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        })
        .expect("driver run succeeds");

        if envelope.backend_kind == BACKEND_KIND_EMBEDDED {
            let graph = envelope
                .payload
                .call_graph
                .as_ref()
                .expect("callgraph emitted");
            let run_node = graph
                .nodes
                .iter()
                .find(|node| node.qualified_name.ends_with("run_specific"))
                .expect("generic dispatch source node exists");
            assert!(run_node.purl.starts_with("pkg:cargo/"));

            let submit_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| {
                    usage.kind == "method-call"
                        && usage.name.contains("Sink::submit")
                        && usage
                            .properties
                            .get("receiverType")
                            .is_some_and(|value| value.contains('S'))
                })
                .expect("generic receiver specialization usage exists");
            assert_eq!(
                submit_usage
                    .properties
                    .get("dispatchConfidence")
                    .map(String::as_str),
                Some("high")
            );
            assert!(
                submit_usage
                    .properties
                    .get("candidateReceiverTypes")
                    .is_some_and(|value| value.contains('S'))
            );
            assert!(
                submit_usage
                    .properties
                    .get("specializationKey")
                    .is_some_and(|value| value.contains("trait-dispatch"))
            );

            // P2.2: monomorphization-driven devirtualization. `run_specific` is
            // generic over `S: Sink<String>`, so per-body resolution cannot pin
            // `sink.submit(..)`. Walking the concrete instantiations resolves it
            // to BOTH impl methods, and the edges now point at the concrete
            // impls (`<FileSink as Sink<String>>::submit` and the `NetSink` one)
            // rather than the abstract trait item.
            let devirt_edges = graph
                .edges
                .iter()
                .filter(|edge| {
                    edge.source_name.ends_with("run_specific")
                        && edge.target_name.contains("Sink<")
                        && edge.target_name.contains(">::submit")
                })
                .collect::<Vec<_>>();
            assert!(
                devirt_edges
                    .iter()
                    .any(|edge| edge.target_name.contains("FileSink")),
                "expected devirtualized edge to FileSink::submit, got {:?}",
                devirt_edges
                    .iter()
                    .map(|e| &e.target_name)
                    .collect::<Vec<_>>()
            );
            assert!(
                devirt_edges
                    .iter()
                    .any(|edge| edge.target_name.contains("NetSink")),
                "expected devirtualized edge to NetSink::submit"
            );
            for edge in &devirt_edges {
                assert_eq!(edge.call_type, "trait-static-bounded");
                assert_eq!(
                    edge.properties.get("edgePrecision").map(String::as_str),
                    Some("bounded")
                );
                assert!(
                    edge.source_purl.starts_with("pkg:cargo/")
                        || edge.target_purl.starts_with("pkg:cargo/"),
                    "expected at least one callgraph endpoint PURL"
                );
            }

            // No edge should target the abstract trait item or a raw generic
            // parameter now that devirtualization succeeded.
            assert!(
                graph.edges.iter().all(|edge| !(edge
                    .source_name
                    .ends_with("run_specific")
                    && (edge.target_name.contains("<S as Sink")
                        || edge.target_name == "Sink::submit")))
            );
        } else {
            assert_eq!(envelope.backend_kind, BACKEND_KIND_STUB);
        }
    }

    #[test]
    fn driver_materializes_projection_and_field_write_summaries() {
        let _guard = test_guard();
        let envelope = run_driver(&DriverOptions {
            analysis_root: fixture_path("projection-flow-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        })
        .expect("driver run succeeds");

        if envelope.backend_kind == BACKEND_KIND_EMBEDDED {
            let flow = envelope
                .payload
                .data_flow
                .as_ref()
                .expect("dataflow emitted");
            let direct_return = flow
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("direct_field_to_return"))
                .expect("direct field return summary exists");
            assert!(
                direct_return
                    .properties
                    .get("fieldToReturn")
                    .is_some_and(|value| value.contains(".*.0"))
            );
            assert!(
                direct_return
                    .properties
                    .get("receiverType")
                    .is_some_and(|value| value.contains("DirectHolder"))
            );

            let direct_write = flow
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("direct_param_to_field_write"))
                .expect("direct field write summary exists");
            assert!(
                direct_write
                    .properties
                    .get("paramToFieldWrite")
                    .is_some_and(|value| value.contains("holder.*.0:1"))
            );
            assert!(
                direct_write
                    .properties
                    .get("receiverType")
                    .is_some_and(|value| value.contains("&mut DirectHolder"))
            );

            let wrapper_return = flow
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("wrapper_field_to_return"))
                .expect("wrapper field return summary exists");
            assert!(wrapper_return.purl.starts_with("pkg:cargo/"));
            assert!(
                wrapper_return
                    .properties
                    .get("fieldToReturn")
                    .is_some_and(|value| value.contains("holder.*"))
            );
            assert!(
                wrapper_return
                    .properties
                    .get("fieldToReturn")
                    .is_some_and(|value| !value.contains("_"))
            );
            assert!(
                wrapper_return
                    .properties
                    .get("effectShapes")
                    .is_some_and(
                        |value| value.contains("field-return") && value.contains("param-return")
                    )
            );

            let wrapper_write = flow
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("wrapper_param_to_field_write"))
                .expect("wrapper field write summary exists");
            assert!(wrapper_write.purl.starts_with("pkg:cargo/"));
            assert!(
                wrapper_write
                    .properties
                    .get("paramToFieldWrite")
                    .is_some_and(|value| value.contains(":1"))
            );
            assert!(
                wrapper_write
                    .properties
                    .get("paramToFieldWrite")
                    .is_some_and(|value| value.starts_with("holder") && !value.contains("_"))
            );
            assert!(
                wrapper_write
                    .properties
                    .get("effectShapes")
                    .is_some_and(|value| value.contains("param-field-write"))
            );

            let run_summary = flow
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("run"))
                .expect("run summary exists");
            assert!(
                run_summary
                    .properties
                    .get("effectShapes")
                    .is_some_and(|value| value.contains("sink-call")
                        && value.contains("param-return")
                        && value.contains("field-return"))
            );

            let process_slice = flow
                .slices
                .iter()
                .find(|slice| {
                    slice.source_category == "env" && slice.sink_category == "process-exec"
                })
                .expect("projection env-to-process slice exists");
            assert!(process_slice.source_purl.starts_with("pkg:cargo/"));
            assert!(process_slice.target_purl.starts_with("pkg:cargo/"));

            let borrow_mut_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("borrow_mut"))
                .expect("borrow_mut usage exists");
            assert!(borrow_mut_usage.purl.starts_with("pkg:cargo/"));
            assert!(
                borrow_mut_usage
                    .properties
                    .get("semanticTags")
                    .is_some_and(|value| value.contains("passthrough"))
            );
            assert!(
                envelope
                    .payload
                    .files
                    .iter()
                    .all(|file| file.purl.starts_with("pkg:cargo/"))
            );
        } else {
            assert_eq!(envelope.backend_kind, BACKEND_KIND_STUB);
        }
    }

    #[test]
    fn driver_reconstructs_async_logical_edges_and_semantic_models() {
        let _guard = test_guard();
        let envelope = run_driver(&DriverOptions {
            analysis_root: fixture_path("async-semantic-app"),
            call_graph_mode: "static".to_string(),
            data_flow_mode: "security".to_string(),
            include_tests: false,
            rustc_toolchain: "auto".to_string(),
            debug: false,
        })
        .expect("driver run succeeds");

        if envelope.backend_kind == BACKEND_KIND_EMBEDDED {
            assert!(
                envelope
                    .payload
                    .security_signals
                    .iter()
                    .any(|signal| signal.category == "async-model")
            );
            assert!(
                envelope
                    .payload
                    .security_signals
                    .iter()
                    .any(|signal| signal.category == "closure-model")
            );

            let spawn_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name == "std::thread::spawn")
                .expect("spawn usage exists");
            assert_eq!(
                spawn_usage
                    .properties
                    .get("taskBoundary")
                    .map(String::as_str),
                Some("true")
            );
            assert!(
                spawn_usage
                    .properties
                    .get("specializationKey")
                    .is_some_and(|value| value.contains("task-boundary"))
            );

            let poll_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name == "std::future::Future::poll")
                .expect("poll usage exists");
            assert_eq!(
                poll_usage
                    .properties
                    .get("asyncBoundary")
                    .map(String::as_str),
                Some("true")
            );
            assert!(
                poll_usage
                    .properties
                    .get("semanticTags")
                    .is_some_and(|value| value.contains("async-boundary")
                        && value.contains("trait-dispatch"))
            );

            let combinator_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("Result::<T, E>::map"))
                .expect("result combinator usage exists");
            assert!(
                combinator_usage
                    .properties
                    .get("semanticTags")
                    .is_some_and(
                        |value| value.contains("combinator") && value.contains("passthrough")
                    )
            );

            let lock_semantics = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("Option::<T>::take"))
                .expect("interior mutability usage exists");
            assert!(
                lock_semantics
                    .properties
                    .get("semanticTags")
                    .is_some_and(|value| value.contains("interior-mutability"))
            );

            let callable_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("Executor::<F>::execute"))
                .expect("callable wrapper usage exists");
            assert!(callable_usage.purl.starts_with("pkg:cargo/"));
            assert!(
                callable_usage
                    .properties
                    .get("receiverType")
                    .is_some_and(|value| value.contains("Executor"))
            );

            let recv_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("Receiver::<T>::recv"))
                .expect("channel recv usage exists");
            assert!(recv_usage
                .properties
                .get("semanticTags")
                .is_some_and(|value| value.contains("channel") && value.contains("passthrough")));

            let send_usage = envelope
                .payload
                .usages
                .iter()
                .find(|usage| usage.name.contains("Sender::<T>::send"))
                .expect("channel send usage exists");
            assert!(
                send_usage
                    .properties
                    .get("semanticTags")
                    .is_some_and(|value| value.contains("channel"))
            );

            let execute_summary = envelope
                .payload
                .data_flow
                .as_ref()
                .expect("dataflow emitted")
                .summaries
                .iter()
                .find(|summary| summary.function.ends_with("Executor::<F>::execute"))
                .expect("callable wrapper summary exists");
            assert!(execute_summary.purl.starts_with("pkg:cargo/"));
            assert!(
                execute_summary
                    .param_to_sink
                    .get("process-exec")
                    .is_some_and(|indexes| indexes.contains(&1))
            );
            assert!(
                execute_summary
                    .properties
                    .get("fieldToReturn")
                    .is_some_and(|value| value.contains("self.0"))
            );

            let dispatch_async_body_summary = envelope
                .payload
                .data_flow
                .as_ref()
                .expect("dataflow emitted")
                .summaries
                .iter()
                .find(|summary| summary.function == "dispatch::{closure#0}")
                .expect("dispatch async body summary exists");
            assert!(
                dispatch_async_body_summary
                    .properties
                    .get("effectShapes")
                    .is_some_and(
                        |value| value.contains("field-return") && value.contains("sink-call")
                    )
            );
            assert!(
                dispatch_async_body_summary
                    .properties
                    .get("semanticTags")
                    .is_some_and(|value| value.contains("callable") && value.contains("closure"))
            );

            assert!(
                envelope
                    .payload
                    .declarations
                    .iter()
                    .all(|declaration| declaration.purl.starts_with("pkg:cargo/"))
            );
            assert!(
                envelope
                    .payload
                    .security_signals
                    .iter()
                    .all(|signal| signal.purl.starts_with("pkg:cargo/"))
            );

            let graph = envelope
                .payload
                .call_graph
                .as_ref()
                .expect("callgraph emitted");
            assert!(graph.edges.iter().any(|edge| {
                edge.target_name == "std::thread::spawn"
                    && edge.call_type == "async-logical"
                    && edge
                        .properties
                        .get("taskBoundary")
                        .is_some_and(|value| value == "true")
                    && edge
                        .properties
                        .get("sourceLevel")
                        .is_some_and(|value| value == "true")
            }));
            assert!(graph.edges.iter().any(|edge| {
                edge.target_name == "block_on"
                    && edge.call_type == "async-logical"
                    && edge
                        .properties
                        .get("asyncBoundary")
                        .is_some_and(|value| value == "true")
            }));
            assert!(graph.edges.iter().any(|edge| {
                edge.target_name == "std::future::Future::poll"
                    && edge.call_type == "async-logical"
                    && edge
                        .properties
                        .get("edgePrecision")
                        .is_some_and(|value| value == "exact")
            }));
        } else {
            assert_eq!(envelope.backend_kind, BACKEND_KIND_STUB);
        }
    }
}

#[cfg(test)]
mod merger_tests {
    use super::{CompilerEvidenceMerger, diagnostic_key, import_key, merge_mode};
    use rusi_schema::{
        CallGraph, CallGraphEdge, CallGraphNode, CompilerEvidence, CryptoEvidence, CryptoLibrary,
        DataFlowEdge, DataFlowEvidence, DataFlowNode, DataFlowSlice, Declaration, Diagnostic,
        FileEvidence, ImportUsage, Position,
    };

    fn node(id: &str, source: bool, sink: bool) -> DataFlowNode {
        DataFlowNode {
            id: id.to_string(),
            source,
            sink,
            ..DataFlowNode::default()
        }
    }

    fn cg_node(id: &str) -> CallGraphNode {
        CallGraphNode {
            id: id.to_string(),
            ..CallGraphNode::default()
        }
    }

    fn cg_edge(id: &str) -> CallGraphEdge {
        CallGraphEdge {
            id: id.to_string(),
            ..CallGraphEdge::default()
        }
    }

    fn diagnostic(kind: &str, message: &str) -> Diagnostic {
        Diagnostic {
            kind: kind.to_string(),
            message: message.to_string(),
            ..Diagnostic::default()
        }
    }

    fn merge_all(artifacts: Vec<CompilerEvidence>) -> CompilerEvidence {
        let mut merger = CompilerEvidenceMerger::default();
        for artifact in artifacts {
            merger.merge(artifact);
        }
        merger.finish()
    }

    #[test]
    fn deduplicates_call_graph_nodes_and_edges_across_artifacts() {
        let artifact_a = CompilerEvidence {
            call_graph: Some(CallGraph {
                mode: "static".to_string(),
                nodes: vec![cg_node("a"), cg_node("b")],
                edges: vec![cg_edge("a->b")],
                ..CallGraph::default()
            }),
            ..CompilerEvidence::default()
        };
        let artifact_b = CompilerEvidence {
            call_graph: Some(CallGraph {
                mode: "static".to_string(),
                // "b" overlaps with artifact_a and must not be duplicated.
                nodes: vec![cg_node("b"), cg_node("c")],
                edges: vec![cg_edge("a->b"), cg_edge("b->c")],
                ..CallGraph::default()
            }),
            ..CompilerEvidence::default()
        };

        let merged = merge_all(vec![artifact_a, artifact_b]);
        let call_graph = merged.call_graph.expect("call graph present");

        let node_ids: Vec<_> = call_graph.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(node_ids, vec!["a", "b", "c"]);
        let edge_ids: Vec<_> = call_graph.edges.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(edge_ids, vec!["a->b", "b->c"]);
        // Stats are computed once over the merged result.
        assert_eq!(call_graph.stats.node_count, 3);
        assert_eq!(call_graph.stats.edge_count, 2);
    }

    #[test]
    fn deduplicates_data_flow_and_recomputes_stats() {
        let artifact_a = CompilerEvidence {
            data_flow: Some(DataFlowEvidence {
                mode: "security".to_string(),
                nodes: vec![node("src", true, false), node("sink", false, true)],
                edges: vec![DataFlowEdge {
                    id: "src->sink".to_string(),
                    ..DataFlowEdge::default()
                }],
                slices: vec![DataFlowSlice {
                    id: "slice-1".to_string(),
                    ..DataFlowSlice::default()
                }],
                ..DataFlowEvidence::default()
            }),
            ..CompilerEvidence::default()
        };
        let artifact_b = CompilerEvidence {
            data_flow: Some(DataFlowEvidence {
                mode: "security".to_string(),
                // "sink" overlaps; "mid" is a new pure-passthrough node.
                nodes: vec![node("sink", false, true), node("mid", false, false)],
                edges: vec![DataFlowEdge {
                    id: "src->sink".to_string(),
                    ..DataFlowEdge::default()
                }],
                slices: vec![DataFlowSlice {
                    id: "slice-1".to_string(),
                    ..DataFlowSlice::default()
                }],
                ..DataFlowEvidence::default()
            }),
            ..CompilerEvidence::default()
        };

        let merged = merge_all(vec![artifact_a, artifact_b]);
        let data_flow = merged.data_flow.expect("data flow present");

        assert_eq!(data_flow.stats.node_count, 3);
        assert_eq!(data_flow.stats.edge_count, 1);
        assert_eq!(data_flow.stats.slice_count, 1);
        assert_eq!(data_flow.stats.source_count, 1);
        assert_eq!(data_flow.stats.sink_count, 1);
    }

    #[test]
    fn merges_files_by_path_and_dedups_their_contents() {
        let import = ImportUsage {
            path: "std::fs".to_string(),
            ..ImportUsage::default()
        };
        let decl = Declaration {
            id: "decl-1".to_string(),
            ..Declaration::default()
        };
        let file_first = FileEvidence {
            path: "src/main.rs".to_string(),
            imports: vec![import.clone()],
            declarations: vec![decl.clone()],
            ..FileEvidence::default()
        };
        let file_second = FileEvidence {
            path: "src/main.rs".to_string(),
            // Same import + declaration must not duplicate; the new declaration must land.
            imports: vec![import.clone()],
            declarations: vec![
                decl.clone(),
                Declaration {
                    id: "decl-2".to_string(),
                    ..Declaration::default()
                },
            ],
            ..FileEvidence::default()
        };

        let merged = merge_all(vec![
            CompilerEvidence {
                files: vec![file_first],
                ..CompilerEvidence::default()
            },
            CompilerEvidence {
                files: vec![file_second],
                ..CompilerEvidence::default()
            },
        ]);

        assert_eq!(merged.files.len(), 1);
        let file = &merged.files[0];
        assert_eq!(file.imports.len(), 1);
        let decl_ids: Vec<_> = file.declarations.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(decl_ids, vec!["decl-1", "decl-2"]);
    }

    #[test]
    fn merges_top_level_collections_and_crypto() {
        let library = CryptoLibrary {
            id: "lib-1".to_string(),
            ..CryptoLibrary::default()
        };
        let artifact_a = CompilerEvidence {
            declarations: vec![Declaration {
                id: "d1".to_string(),
                ..Declaration::default()
            }],
            crypto: Some(CryptoEvidence {
                libraries: vec![library.clone()],
                ..CryptoEvidence::default()
            }),
            ..CompilerEvidence::default()
        };
        let artifact_b = CompilerEvidence {
            declarations: vec![
                Declaration {
                    id: "d1".to_string(),
                    ..Declaration::default()
                },
                Declaration {
                    id: "d2".to_string(),
                    ..Declaration::default()
                },
            ],
            crypto: Some(CryptoEvidence {
                libraries: vec![library.clone()],
                ..CryptoEvidence::default()
            }),
            ..CompilerEvidence::default()
        };

        let merged = merge_all(vec![artifact_a, artifact_b]);
        let decl_ids: Vec<_> = merged.declarations.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(decl_ids, vec!["d1", "d2"]);
        let crypto = merged.crypto.expect("crypto present");
        assert_eq!(crypto.libraries.len(), 1);
    }

    #[test]
    fn merges_modes_without_duplicating() {
        let mut mode = String::new();
        merge_mode(&mut mode, "static");
        assert_eq!(mode, "static");
        // Identical mode is a no-op.
        merge_mode(&mut mode, "static");
        assert_eq!(mode, "static");
        // Substring already present is a no-op.
        merge_mode(&mut mode, "static");
        assert_eq!(mode, "static");
        // Distinct mode is appended.
        merge_mode(&mut mode, "dynamic");
        assert_eq!(mode, "static,dynamic");
    }

    #[test]
    fn import_and_diagnostic_keys_distinguish_relevant_fields() {
        let base = ImportUsage {
            path: "std::fs".to_string(),
            alias: None,
            package_path: "app".to_string(),
            position: Position {
                filename: "a.rs".to_string(),
                line: 1,
                column: 0,
            },
            ..ImportUsage::default()
        };
        let aliased = ImportUsage {
            alias: Some(String::new()),
            ..base.clone()
        };
        // None vs Some("") must not collide.
        assert_ne!(import_key(&base), import_key(&aliased));

        let d1 = diagnostic("backend", "ok");
        let d2 = diagnostic("backend", "different");
        assert_ne!(diagnostic_key(&d1), diagnostic_key(&d2));
        assert_eq!(diagnostic_key(&d1), diagnostic_key(&diagnostic("backend", "ok")));
    }

    #[test]
    fn deduplicates_call_graph_diagnostics_but_keeps_top_level() {
        let artifact = |kind: &str| CompilerEvidence {
            diagnostics: vec![diagnostic(kind, "top")],
            call_graph: Some(CallGraph {
                mode: "static".to_string(),
                diagnostics: vec![diagnostic("backend-capability", "cap")],
                ..CallGraph::default()
            }),
            ..CompilerEvidence::default()
        };

        let merged = merge_all(vec![artifact("a"), artifact("a")]);
        // Top-level diagnostics are intentionally not deduplicated.
        assert_eq!(merged.diagnostics.len(), 2);
        // Call-graph diagnostics are deduplicated.
        let call_graph = merged.call_graph.expect("call graph present");
        assert_eq!(call_graph.diagnostics.len(), 1);
    }
}
