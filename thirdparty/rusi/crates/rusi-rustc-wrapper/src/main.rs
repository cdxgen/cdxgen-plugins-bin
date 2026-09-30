#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_driver_impl;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use indexmap::IndexMap;
use rusi_schema::fixpoint::{
    Dependents, MinRankWorklist, TrackedReads, callee_first_order, join_map, join_set,
    weak_topological_order,
};
use rusi_schema::{
    CallGraph, CallGraphEdge, CallGraphNode, CompilerEvidence, CryptoComponent, CryptoEvidence,
    CryptoFinding, CryptoLibrary, CryptoMaterial, DataFlowEdge, DataFlowEvidence,
    DataFlowMethodSummary, DataFlowNode, DataFlowPattern, DataFlowPatternSet, DataFlowSlice,
    DataFlowStats, Declaration, Diagnostic, FileEvidence, GraphStats, ImportUsage, LibraryUsage,
    Position, SecuritySignal, relative_display_path, stable_id,
};
use rustc_driver_impl::{Callbacks, Compilation, run_compiler};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_hir::intravisit::{self, Visitor};
use rustc_hir::{
    BodyId, ClosureKind, CoroutineDesugaring, CoroutineKind, Expr, ExprKind, ForeignItemKind,
    ImplItemKind, ItemKind, PatKind, TraitItemKind, UnsafeSource, UseKind,
};
use rustc_interface::interface;
use rustc_middle::hir::nested_filter::OnlyBodies;
use rustc_middle::mir::{
    self, BasicBlock, Body as MirBody, Local, Operand, Place, ProjectionElem, Rvalue,
    StatementKind, TerminatorKind, UnwindAction,
};
use rustc_middle::mono::MonoItem;
use rustc_middle::ty::{self, AssocContainer, Ty, TyCtxt};
use rustc_span::{FileName, Span};

// rustc_private shims. The wrapper builds against both the pinned stable
// toolchain and current nightly, so these paper over API changes between them
// without per-version cfgs.

/// `const { .. }` blocks. rustc 1.98 gives them `DefKind::InlineConst`; newer
/// compilers fold them into `DefKind::AnonConst`, which also covers array
/// lengths and enum discriminants. `is_typeck_child` picks out exactly the
/// inline consts on both, once closures and coroutine bodies are excluded.
fn is_inline_const(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    !matches!(
        tcx.def_kind(def_id),
        DefKind::Closure | DefKind::SyntheticCoroutineBody
    ) && tcx.is_typeck_child(def_id)
}

/// MIR for a body owner. `optimized_mir` panics for const contexts ("do not
/// use `optimized_mir` for constants"), which includes inline consts; those
/// only have the CTFE body.
fn owner_mir(tcx: TyCtxt<'_>, def_id: DefId) -> &rustc_middle::mir::Body<'_> {
    if is_inline_const(tcx, def_id) {
        tcx.mir_for_ctfe(def_id)
    } else {
        tcx.optimized_mir(def_id)
    }
}

/// Self type of an impl, as a type name. `instantiate_identity` returns an
/// `Unnormalized` wrapper, whose `Debug` output is `Unnormalized { value: T,
/// .. }` rather than the type; unwrap it before formatting.
fn impl_self_ty_name(tcx: TyCtxt<'_>, impl_def_id: DefId) -> String {
    format!(
        "{:?}",
        tcx.type_of(impl_def_id)
            .instantiate_identity()
            .skip_normalization()
    )
}

/// Generic args of a `TyKind::FnDef`. rustc 1.98 stores them bare; newer
/// compilers wrap them in a `Binder`. Args with escaping bound vars cannot be
/// resolved to an instance, so those yield `None`.
trait FnDefArgs<'tcx> {
    fn fn_def_args(self) -> Option<ty::GenericArgsRef<'tcx>>;
}

impl<'tcx> FnDefArgs<'tcx> for ty::GenericArgsRef<'tcx> {
    fn fn_def_args(self) -> Option<ty::GenericArgsRef<'tcx>> {
        Some(self)
    }
}

impl<'tcx> FnDefArgs<'tcx> for ty::Binder<'tcx, ty::GenericArgsRef<'tcx>> {
    fn fn_def_args(self) -> Option<ty::GenericArgsRef<'tcx>> {
        self.no_bound_vars()
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let mut callbacks = WrapperCallbacks::from_env();
    run_compiler(args.get(1..).unwrap_or(&[]), &mut callbacks);
}

#[derive(Debug, Clone)]
struct WrapperCallbacks {
    emit_dir: Option<PathBuf>,
    analysis_root: Option<PathBuf>,
    data_flow_mode: String,
    debug: bool,
}

impl WrapperCallbacks {
    fn from_env() -> Self {
        Self {
            emit_dir: std::env::var_os("RUSI_EMIT_DIR").map(PathBuf::from),
            analysis_root: std::env::var_os("RUSI_ANALYSIS_ROOT").map(PathBuf::from),
            data_flow_mode: std::env::var("RUSI_DATA_FLOW_MODE")
                .unwrap_or_else(|_| "security".to_string()),
            debug: std::env::var_os("RUSI_DEBUG").is_some(),
        }
    }

    fn should_collect(&self) -> bool {
        self.emit_dir.is_some() && self.analysis_root.is_some()
    }
}

impl Callbacks for WrapperCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        config.opts.unstable_opts.mir_opt_level = Some(0);
        // Under `cargo check`, dependencies are built metadata-only: no
        // exported symbols and no MIR for non-generic items. The mono
        // collector behind `collect_mono_devirtualization` then treats every
        // upstream callee as needing local instantiation and aborts with
        // "missing optimized MIR". The wrapper runs for dependencies too, so
        // encoding their MIR keeps the collector supplied.
        config.opts.unstable_opts.always_encode_mir = true;
    }

    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &interface::Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> Compilation {
        if !self.should_collect() {
            return Compilation::Continue;
        }
        let emit_dir = self.emit_dir.clone().expect("emit dir present");
        let analysis_root = self.analysis_root.clone().expect("analysis root present");
        let crate_path = local_crate_source_path(tcx);
        if !data_flow_mode_collects_external_bodies(&self.data_flow_mode)
            && !crate_path
                .as_ref()
                .is_some_and(|path| path_is_under_root(&analysis_root, path))
        {
            debug_log(
                self.debug,
                format_args!(
                    "pass=rustc-wrapper-skip-dependency crate={} file={} dataflow={}",
                    tcx.crate_name(LOCAL_CRATE),
                    crate_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    self.data_flow_mode
                ),
            );
            return Compilation::Continue;
        }
        if let Err(error) = collect_and_write_artifact(tcx, &analysis_root, &emit_dir, self.debug) {
            eprintln!("rusi wrapper failed: {error:#}");
        }
        Compilation::Continue
    }
}

fn collect_and_write_artifact(
    tcx: TyCtxt<'_>,
    analysis_root: &Path,
    emit_dir: &Path,
    debug: bool,
) -> Result<()> {
    let (analysis_root, emit_dir) = prepare_emit_dir(analysis_root, emit_dir)?;
    debug_log(
        debug,
        format_args!("pass=rustc-wrapper crate={}", tcx.crate_name(LOCAL_CRATE)),
    );
    let artifact = EmbeddedCollector::collect(tcx, &analysis_root, debug)?;
    if artifact.declarations.is_empty() && artifact.files.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(&emit_dir)
        .with_context(|| format!("failed to create {}", emit_dir.display()))?;
    ensure_directory_within_root(&analysis_root, &emit_dir)?;
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let crate_root = tcx
        .sess
        .local_crate_source_file()
        .and_then(|path| path.into_local_path())
        .map(|path| relative_display_path(&analysis_root, &path))
        .unwrap_or_default();
    let output_path = emit_dir.join(format!(
        "{}.json",
        stable_id("artifact", &[&crate_name, &crate_root])
    ));
    debug_log(
        debug,
        format_args!(
            "pass=rustc-wrapper-write artifact={}",
            output_path.display()
        ),
    );
    fs::write(&output_path, serde_json::to_string_pretty(&artifact)?)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    Ok(())
}

#[derive(Debug, Default)]
struct EmbeddedCollector {
    crate_name: String,
    analysis_root: PathBuf,
    debug: bool,
    files: BTreeMap<String, FileEvidence>,
    imports: Vec<ImportUsage>,
    declarations: Vec<Declaration>,
    usages: Vec<LibraryUsage>,
    security_signals: Vec<SecuritySignal>,
    crypto: CryptoEvidence,
    diagnostics: Vec<Diagnostic>,
    function_decls: HashMap<LocalDefId, Declaration>,
    function_ids: HashMap<LocalDefId, String>,
    callsites: HashMap<(LocalDefId, String), ResolvedCall>,
    hir_calls: Vec<HirCallRecord>,
    functions: Vec<MirFunction>,
}

impl EmbeddedCollector {
    fn collect(tcx: TyCtxt<'_>, analysis_root: &Path, debug: bool) -> Result<CompilerEvidence> {
        let mut collector = Self {
            crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
            analysis_root: analysis_root.to_path_buf(),
            debug,
            ..Self::default()
        };
        debug_log(
            debug,
            format_args!("pass=compiler-items crate={}", collector.crate_name),
        );
        collector.collect_items(tcx)?;
        debug_log(
            debug,
            format_args!("pass=compiler-hir-bodies crate={}", collector.crate_name),
        );
        collector.collect_bodies(tcx)?;
        debug_log(
            debug,
            format_args!("pass=compiler-mir crate={}", collector.crate_name),
        );
        collector.collect_mir(tcx)?;
        debug_log(
            debug,
            format_args!("pass=compiler-finish crate={}", collector.crate_name),
        );
        Ok(collector.finish())
    }

    fn finish(mut self) -> CompilerEvidence {
        for file in self.files.values_mut() {
            if let Some(crypto) = &mut file.crypto {
                sort_crypto(crypto);
                if crypto.libraries.is_empty()
                    && crypto.components.is_empty()
                    && crypto.materials.is_empty()
                    && crypto.findings.is_empty()
                {
                    file.crypto = None;
                }
            }
            file.imports.sort_by(|l, r| l.path.cmp(&r.path));
            file.declarations.sort_by(|l, r| l.id.cmp(&r.id));
            file.usages.sort_by(|l, r| l.id.cmp(&r.id));
            file.security_signals.sort_by(|l, r| l.id.cmp(&r.id));
        }
        self.imports.sort_by(|l, r| l.path.cmp(&r.path));
        self.declarations.sort_by(|l, r| l.id.cmp(&r.id));
        self.usages.sort_by(|l, r| l.id.cmp(&r.id));
        self.security_signals.sort_by(|l, r| l.id.cmp(&r.id));
        self.diagnostics.sort_by(|l, r| l.message.cmp(&r.message));
        sort_crypto(&mut self.crypto);

        debug_log(
            self.debug,
            format_args!(
                "pass=compiler-finish-sort crate={} files={} functions={} hir_calls={}",
                self.crate_name,
                self.files.len(),
                self.functions.len(),
                self.hir_calls.len()
            ),
        );
        let mut call_graph_diagnostics = Vec::new();
        debug_log(
            self.debug,
            format_args!("pass=compiler-callgraph-build crate={}", self.crate_name),
        );
        let call_graph = build_call_graph(
            &self.functions,
            &self.hir_calls,
            &self.declarations,
            &mut call_graph_diagnostics,
        );
        let mut flow_diagnostics = Vec::new();
        debug_log(
            self.debug,
            format_args!("pass=compiler-dataflow-build crate={}", self.crate_name),
        );
        let data_flow = build_data_flow(&self.functions, &mut flow_diagnostics, self.debug);
        debug_log(
            self.debug,
            format_args!("pass=compiler-evidence-pack crate={}", self.crate_name),
        );
        self.diagnostics.extend(call_graph_diagnostics);
        self.diagnostics.extend(flow_diagnostics);
        self.diagnostics.sort_by(|l, r| l.message.cmp(&r.message));

        CompilerEvidence {
            diagnostics: self.diagnostics,
            files: self.files.into_values().collect(),
            imports: self.imports,
            declarations: self.declarations,
            usages: self.usages,
            security_signals: self.security_signals,
            crypto: if self.crypto.libraries.is_empty()
                && self.crypto.components.is_empty()
                && self.crypto.materials.is_empty()
                && self.crypto.findings.is_empty()
            {
                None
            } else {
                Some(self.crypto)
            },
            call_graph: Some(call_graph),
            data_flow: Some(data_flow),
        }
    }

    fn collect_items(&mut self, tcx: TyCtxt<'_>) -> Result<()> {
        let items = tcx.hir_crate_items(());
        for item_id in items.free_items() {
            let item = tcx.hir_item(item_id);
            match item.kind {
                ItemKind::Use(path, kind) => {
                    self.push_import(tcx, item.span, path.segments, kind);
                }
                ItemKind::Struct(..) => {
                    self.push_decl(tcx, item.owner_id.def_id, "struct", None)?;
                }
                ItemKind::Enum(..) => {
                    self.push_decl(tcx, item.owner_id.def_id, "enum", None)?;
                }
                ItemKind::Union(..) => {
                    self.push_decl(tcx, item.owner_id.def_id, "union", None)?;
                }
                ItemKind::Trait { .. } => {
                    self.push_decl(tcx, item.owner_id.def_id, "trait", None)?;
                }
                ItemKind::Mod(..) => {
                    self.push_decl(tcx, item.owner_id.def_id, "module", None)?;
                }
                ItemKind::Fn { .. } => {
                    let kind = if tcx
                        .fn_sig(item.owner_id.to_def_id())
                        .skip_binder()
                        .safety()
                        .is_unsafe()
                    {
                        "unsafe-function"
                    } else {
                        "function"
                    };
                    let declaration = self.push_decl(tcx, item.owner_id.def_id, kind, None)?;
                    self.function_decls
                        .insert(item.owner_id.def_id, declaration.clone());
                    self.function_ids
                        .insert(item.owner_id.def_id, declaration.id.clone());
                }
                ItemKind::ForeignMod { .. } => {}
                _ => {}
            }
        }
        for foreign_item_id in items.foreign_items() {
            let item = tcx.hir_foreign_item(foreign_item_id);
            let kind = match item.kind {
                ForeignItemKind::Fn(..) => "foreign-function",
                ForeignItemKind::Static(..) => "foreign-static",
                ForeignItemKind::Type => "foreign-type",
            };
            let declaration = self.push_decl(tcx, item.owner_id.def_id, kind, None)?;
            self.push_security_signal(SecuritySignal {
                cfg_gate: None,
                id: stable_id("signal", &[&declaration.id, "native-interop"]),
                category: "native-interop".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                description: format!("foreign item {} declared", declaration.qualified_name),
                package_path: declaration.package_path.clone(),
                purl: String::new(),
                file_path: declaration.file_path.clone(),
                position: declaration.position.clone(),
            });
        }
        for impl_item_id in items.impl_items() {
            let item = tcx.hir_impl_item(impl_item_id);
            if let ImplItemKind::Fn { .. } = item.kind {
                let assoc = tcx.associated_item(item.owner_id.to_def_id());
                let kind = if tcx
                    .fn_sig(item.owner_id.to_def_id())
                    .skip_binder()
                    .safety()
                    .is_unsafe()
                {
                    "unsafe-method"
                } else if assoc.is_method() {
                    "method"
                } else {
                    "associated-function"
                };
                let receiver = assoc
                    .impl_container(tcx)
                    .map(|impl_def_id| impl_self_ty_name(tcx, impl_def_id));
                let declaration = self.push_decl(tcx, item.owner_id.def_id, kind, receiver)?;
                self.function_decls
                    .insert(item.owner_id.def_id, declaration.clone());
                self.function_ids
                    .insert(item.owner_id.def_id, declaration.id.clone());
            }
        }
        for trait_item_id in items.trait_items() {
            let item = tcx.hir_trait_item(trait_item_id);
            if let TraitItemKind::Fn(..) = item.kind {
                let declaration =
                    self.push_decl(tcx, item.owner_id.def_id, "trait-method", None)?;
                self.function_decls
                    .insert(item.owner_id.def_id, declaration.clone());
                self.function_ids
                    .insert(item.owner_id.def_id, declaration.id.clone());
            }
        }
        Ok(())
    }

    fn collect_bodies(&mut self, tcx: TyCtxt<'_>) -> Result<()> {
        for owner in tcx.hir_body_owners() {
            let body = tcx.hir_body_owned_by(owner);
            let declaration = self.ensure_function_decl(tcx, owner)?;
            debug_log(
                self.debug,
                format_args!(
                    "pass=compiler-hir-body file={} function={}",
                    declaration.file_path, declaration.qualified_name
                ),
            );
            let typeck = tcx.typeck(owner);
            let mut visitor = BodyVisitor {
                tcx,
                analysis_root: &self.analysis_root,
                crate_name: &self.crate_name,
                caller: owner,
                caller_decl: &declaration,
                typeck,
                callsites: &mut self.callsites,
                hir_calls: &mut self.hir_calls,
                usages: &mut self.usages,
                security_signals: &mut self.security_signals,
                files: &mut self.files,
                crypto: &mut self.crypto,
                function_ids: &self.function_ids,
            };
            visitor.visit_body(body);
        }
        Ok(())
    }

    fn collect_mir(&mut self, tcx: TyCtxt<'_>) -> Result<()> {
        // P2.2: monomorphization-collector-driven devirtualization. Runs first
        // so a generic function's callsites carry the union of concrete targets
        // discovered across every instantiation (context-insensitive, sound).
        self.collect_mono_devirtualization(tcx);
        let local_resolutions = self.local_resolution_index();
        let closure_candidates = self.closure_candidate_index(tcx)?;
        for owner in tcx.mir_keys(()) {
            let owner = *owner;
            if !matches!(
                tcx.def_kind(owner),
                DefKind::Fn | DefKind::AssocFn | DefKind::Closure | DefKind::SyntheticCoroutineBody
            ) && !is_inline_const(tcx, owner.to_def_id())
            {
                continue;
            }
            let declaration = self.ensure_function_decl(tcx, owner)?;
            debug_log(
                self.debug,
                format_args!(
                    "pass=compiler-mir-body file={} function={}",
                    declaration.file_path, declaration.qualified_name
                ),
            );
            let body = owner_mir(tcx, owner.to_def_id());
            let callsites = self
                .callsites
                .iter()
                .filter(|((call_owner, _), _)| *call_owner == owner)
                .map(|((_, key), value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>();
            self.functions.push(MirFunction::from_mir(
                &self.crate_name,
                declaration,
                body,
                callsites,
                &local_resolutions,
                &closure_candidates,
            ));
        }
        Ok(())
    }

    /// P2.2: walk every monomorphized function instance the crate actually
    /// generates and resolve each of its call terminators with the instance's
    /// concrete substitutions applied. This devirtualizes calls that depend on
    /// the *caller's* generic parameters (e.g. `fn run<S: Sink>(s: &S)` calling
    /// `s.submit()`), which per-body resolution cannot see. Results are keyed by
    /// `(owner, canonical trait-method symbol)` and unioned across every
    /// instantiation into one multi-candidate resolution (context-insensitive
    /// over-approximation), then used to sharpen the matching HIR/MIR callsite
    /// records so the concrete impls survive precision arbitration.
    fn collect_mono_devirtualization<'tcx>(&mut self, tcx: TyCtxt<'tcx>) {
        use rustc_middle::ty::EarlyBinder;
        // (owner def, canonical original-callee symbol) -> concrete callee
        // DefIds. Neither LocalDefId nor DefId is Ord, so use hashed containers
        // and sort by path string at emit time for deterministic output.
        let mut resolved: HashMap<(LocalDefId, String), Vec<DefId>> = HashMap::new();

        for cgu in tcx.collect_and_partition_mono_items(()).codegen_units {
            for mono_item in cgu.items().keys() {
                let MonoItem::Fn(instance) = mono_item else {
                    continue;
                };
                let instance = *instance;
                let ty::InstanceKind::Item(def) = instance.def else {
                    continue;
                };
                let Some(owner) = def.as_local() else {
                    continue;
                };
                if !tcx.is_mir_available(def) {
                    continue;
                }
                let body = tcx.instance_mir(instance.def);
                let typing_env = ty::TypingEnv::fully_monomorphized();
                for block in body.basic_blocks.iter() {
                    let Some(terminator) = &block.terminator else {
                        continue;
                    };
                    let TerminatorKind::Call { func, .. } = &terminator.kind else {
                        continue;
                    };
                    let generic_ty = func.ty(&body.local_decls, tcx);
                    // Apply the instance's substitutions so callee generics are
                    // concrete, then resolve.
                    let concrete_ty = instance.instantiate_mir_and_normalize_erasing_regions(
                        tcx,
                        typing_env,
                        EarlyBinder::bind(tcx, generic_ty),
                    );
                    let ty::TyKind::FnDef(callee_def, callee_args) = concrete_ty.kind() else {
                        continue;
                    };
                    let Some(callee_args) = callee_args.fn_def_args() else {
                        continue;
                    };
                    // Only trait-method calls are devirtualization candidates;
                    // the per-body pass already handles concrete-receiver calls.
                    if tcx
                        .opt_associated_item(*callee_def)
                        .and_then(|item| item.trait_container(tcx))
                        .is_none()
                    {
                        continue;
                    }
                    let Ok(Some(callee_instance)) =
                        ty::Instance::try_resolve(tcx, typing_env, *callee_def, callee_args)
                    else {
                        continue;
                    };
                    let callee_def_id = callee_instance.def_id();
                    if callee_def_id == *callee_def {
                        continue;
                    }
                    let symbol = canonical_call_symbol(&tcx.def_path_str(*callee_def));
                    let bucket = resolved.entry((owner, symbol)).or_default();
                    if !bucket.contains(&callee_def_id) {
                        bucket.push(callee_def_id);
                    }
                }
            }
        }

        for ((owner, symbol), mut def_ids) in resolved {
            def_ids.sort_by_key(|def_id| tcx.def_path_str(*def_id));
            let mut target_ids = Vec::new();
            let mut target_names = Vec::new();
            for def_id in &def_ids {
                let (ids, names) = target_for_def_id(tcx, *def_id, &self.function_ids);
                target_ids.extend(ids);
                target_names.extend(names);
            }
            if target_ids.is_empty() {
                continue;
            }
            let Some(source_id) = self.function_ids.get(&owner).cloned() else {
                continue;
            };
            let specialization_key = target_names.join("|");
            // Rewrite the matching HIR record(s): a trait-dispatch call in this
            // owner whose callee canonicalizes to `symbol`. HIR edges are
            // authoritative (sourceLevel), so sharpening them here makes the
            // devirtualized concrete impls the emitted targets; any duplicate or
            // superseded MIR-side edge is then dropped by `reconcile_edges`. The
            // MIR-side `callsites` map is deliberately NOT rewritten: it drives
            // the interprocedural dataflow summaries, and forcing concrete
            // targets onto ubiquitous trait methods (`clone`, `borrow`) there
            // would disturb passthrough/summary matching.
            for record in &mut self.hir_calls {
                if record.source_id != source_id {
                    continue;
                }
                if !hir_symbols(&record.resolved).contains(&symbol) {
                    continue;
                }
                // Preserve intentionally-modeled async/task boundary calls
                // (`Future::poll`, `spawn`, `block_on`) as logical edges; do not
                // devirtualize them to a concrete poll impl.
                if record.resolved.async_boundary || record.resolved.task_boundary {
                    continue;
                }
                record.resolved.call_type = "trait-static".to_string();
                record.resolved.dispatch_confidence = "high".to_string();
                record.resolved.target_ids = target_ids.clone();
                record.resolved.target_names = target_names.clone();
                record.resolved.specialization_key = specialization_key.clone();
            }
        }
    }

    fn local_resolution_index(&self) -> HashMap<String, ResolvedCall> {
        let mut index = HashMap::new();
        // A bare name such as `persist` can belong to a trait item and to each
        // of its impls. Resolving it to whichever the hash map yields first
        // produced a different "exact" target per run; an ambiguous bare name
        // must not resolve at all. Qualified names stay unique keys.
        let mut ambiguous = HashSet::new();
        let mut bare_owner = HashMap::<&str, &str>::new();
        for declaration in self.function_decls.values() {
            match bare_owner.insert(&declaration.name, &declaration.qualified_name) {
                Some(previous) if previous != declaration.qualified_name => {
                    ambiguous.insert(declaration.name.clone());
                }
                _ => {}
            }
        }
        let mut declarations = self.function_decls.iter().collect::<Vec<_>>();
        declarations.sort_by(|(_, left), (_, right)| {
            (&left.qualified_name, &left.id).cmp(&(&right.qualified_name, &right.id))
        });
        for (owner, declaration) in declarations {
            let Some(function_id) = self.function_ids.get(owner) else {
                continue;
            };
            let resolved = ResolvedCall {
                callee_display: declaration.name.clone(),
                call_type: "static".to_string(),
                dispatch_confidence: "high".to_string(),
                target_ids: vec![function_id.clone()],
                target_names: vec![declaration.qualified_name.clone()],
                candidate_receivers: declaration.receiver.clone().into_iter().collect(),
                receiver_type: declaration.receiver.clone(),
                dispatch_trait: None,
                specialization_key: declaration.qualified_name.clone(),
                semantic_tags: semantic_tags_for_call(
                    &declaration.qualified_name,
                    std::slice::from_ref(&declaration.qualified_name),
                    "static",
                    declaration.receiver.as_deref(),
                ),
                async_boundary: false,
                task_boundary: false,
            };
            if !ambiguous.contains(&declaration.name) {
                index
                    .entry(declaration.name.clone())
                    .or_insert_with(|| resolved.clone());
            }
            index
                .entry(declaration.qualified_name.clone())
                .or_insert_with(|| resolved.clone());
        }
        index
    }

    fn closure_candidate_index(
        &mut self,
        tcx: TyCtxt<'_>,
    ) -> Result<HashMap<usize, Vec<ResolvedCall>>> {
        let mut index = HashMap::<usize, Vec<ResolvedCall>>::new();
        for owner in tcx.mir_keys(()) {
            let owner = *owner;
            if !matches!(
                tcx.def_kind(owner),
                DefKind::Closure | DefKind::SyntheticCoroutineBody
            ) && !is_inline_const(tcx, owner.to_def_id())
            {
                continue;
            }
            let declaration = self.ensure_function_decl(tcx, owner)?;
            let Some(function_id) = self.function_ids.get(&owner).cloned() else {
                continue;
            };
            let body = owner_mir(tcx, owner.to_def_id());
            let target_names = vec![declaration.qualified_name.clone()];
            let semantic_tags = vec!["closure".to_string(), "callable".to_string()];
            index.entry(body.arg_count).or_default().push(ResolvedCall {
                callee_display: declaration.qualified_name.clone(),
                call_type: "closure".to_string(),
                dispatch_confidence: dispatch_confidence_for("closure", 1),
                target_ids: vec![function_id],
                target_names: target_names.clone(),
                candidate_receivers: Vec::new(),
                receiver_type: None,
                dispatch_trait: None,
                specialization_key: specialization_key_from_parts(
                    None,
                    &semantic_tags,
                    &target_names,
                ),
                semantic_tags,
                async_boundary: false,
                task_boundary: false,
            });
        }
        Ok(index)
    }

    fn ensure_function_decl(&mut self, tcx: TyCtxt<'_>, owner: LocalDefId) -> Result<Declaration> {
        if let Some(decl) = self.function_decls.get(&owner) {
            return Ok(decl.clone());
        }
        let kind = function_kind(tcx, owner);
        let receiver = tcx
            .opt_associated_item(owner.to_def_id())
            .and_then(|assoc| assoc.impl_container(tcx))
            .map(|impl_def_id| impl_self_ty_name(tcx, impl_def_id));
        let decl = self.push_decl(tcx, owner, &kind, receiver)?;
        self.function_decls.insert(owner, decl.clone());
        self.function_ids.insert(owner, decl.id.clone());
        Ok(decl)
    }

    fn push_import(
        &mut self,
        tcx: TyCtxt<'_>,
        span: Span,
        segments: &[rustc_hir::PathSegment<'_>],
        kind: UseKind,
    ) {
        let path = segments
            .iter()
            .map(|seg| seg.ident.as_str().to_string())
            .collect::<Vec<_>>()
            .join("::");
        let alias = match kind {
            UseKind::Single(ident) => {
                let alias = ident.as_str().to_string();
                if alias != last_segment(&path) {
                    Some(alias)
                } else {
                    None
                }
            }
            UseKind::Glob | UseKind::ListStem => None,
        };
        let import = ImportUsage {
            path: path.clone(),
            alias,
            package_path: self.crate_name.clone(),
            purl: String::new(),
            position: position_from_span(tcx, &self.analysis_root, span),
        };
        if !self.imports.iter().any(|existing| {
            existing.path == import.path
                && existing.alias == import.alias
                && existing.package_path == import.package_path
                && existing.position == import.position
        }) {
            self.imports.push(import.clone());
        }
        let file_path = file_path_from_span(tcx, &self.analysis_root, span);
        let file = self.file_entry(&file_path);
        if !file.imports.iter().any(|existing| {
            existing.path == import.path
                && existing.alias == import.alias
                && existing.package_path == import.package_path
                && existing.position == import.position
        }) {
            file.imports.push(import);
        }
    }

    fn push_decl(
        &mut self,
        tcx: TyCtxt<'_>,
        owner: LocalDefId,
        kind: &str,
        receiver: Option<String>,
    ) -> Result<Declaration> {
        let def_id = owner.to_def_id();
        let qualified_name = tcx.def_path_str(def_id);
        let file_path = file_path_from_span(tcx, &self.analysis_root, tcx.def_span(def_id));
        let name = tcx
            .opt_item_name(def_id)
            .map(|symbol| symbol.to_string())
            .unwrap_or_else(|| last_segment(&qualified_name).to_string());
        let declaration = Declaration {
            // The compiler backend only sees code that survived cfg expansion.
            cfg_gate: None,
            id: stable_id("decl", &[&self.crate_name, &qualified_name]),
            name,
            canonical_name: rusi_schema::canonical_name(&qualified_name),
            qualified_name,
            kind: kind.to_string(),
            package_path: self.crate_name.clone(),
            purl: String::new(),
            file_path: file_path.clone(),
            signature: declaration_signature(tcx, def_id),
            receiver,
            position: position_from_span(tcx, &self.analysis_root, tcx.def_span(def_id)),
        };
        if !self
            .declarations
            .iter()
            .any(|existing| existing.id == declaration.id)
        {
            self.declarations.push(declaration.clone());
        }
        let file = self.file_entry(&file_path);
        if !file
            .declarations
            .iter()
            .any(|existing| existing.id == declaration.id)
        {
            file.declarations.push(declaration.clone());
        }
        if kind == "unsafe-function" || kind == "unsafe-method" {
            self.push_security_signal(SecuritySignal {
                cfg_gate: None,
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
        Ok(declaration)
    }

    fn push_security_signal(&mut self, signal: SecuritySignal) {
        if self
            .security_signals
            .iter()
            .any(|existing| existing.id == signal.id)
        {
            return;
        }
        let file = self.file_entry(&signal.file_path);
        if !file
            .security_signals
            .iter()
            .any(|existing| existing.id == signal.id)
        {
            file.security_signals.push(signal.clone());
        }
        self.security_signals.push(signal);
    }

    fn file_entry(&mut self, path: &str) -> &mut FileEvidence {
        self.files
            .entry(path.to_string())
            .or_insert_with(|| FileEvidence {
                path: path.to_string(),
                package_name: self.crate_name.clone(),
                package_path: self.crate_name.clone(),
                purl: String::new(),
                imports: Vec::new(),
                declarations: Vec::new(),
                usages: Vec::new(),
                security_signals: Vec::new(),
                crypto: Some(CryptoEvidence::default()),
            })
    }
}

struct BodyVisitor<'tcx, 'a> {
    tcx: TyCtxt<'tcx>,
    analysis_root: &'a Path,
    crate_name: &'a str,
    caller: LocalDefId,
    caller_decl: &'a Declaration,
    typeck: &'tcx ty::TypeckResults<'tcx>,
    callsites: &'a mut HashMap<(LocalDefId, String), ResolvedCall>,
    hir_calls: &'a mut Vec<HirCallRecord>,
    usages: &'a mut Vec<LibraryUsage>,
    security_signals: &'a mut Vec<SecuritySignal>,
    files: &'a mut BTreeMap<String, FileEvidence>,
    crypto: &'a mut CryptoEvidence,
    function_ids: &'a HashMap<LocalDefId, String>,
}

#[derive(Debug, Clone)]
struct HirCallRecord {
    source_id: String,
    file_path: String,
    position: Position,
    resolved: ResolvedCall,
}

impl<'tcx> Visitor<'tcx> for BodyVisitor<'tcx, '_> {
    type NestedFilter = OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_nested_body(&mut self, id: BodyId) {
        // Closures and inline consts share the caller's typeck results, but an
        // anon const such as the `w() * 2` in `[0u8; w() * 2]` is typechecked
        // on its own; reading it through `self.typeck` ICEs with "no type for
        // node". Such bodies are visited as body owners in their own right.
        let owner = self.tcx.hir_body_owner_def_id(id).to_def_id();
        if self.tcx.typeck_root_def_id(owner)
            != self.tcx.typeck_root_def_id(self.caller.to_def_id())
        {
            return;
        }
        self.visit_body(self.tcx.hir_body(id));
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        match expr.kind {
            ExprKind::MethodCall(segment, receiver, _args, _) => {
                let def_id = self.typeck.type_dependent_def_id(expr.hir_id);
                let receiver_ty = self.typeck.expr_ty(receiver);
                let resolved =
                    resolve_method_call(self.tcx, receiver_ty, def_id, self.function_ids);
                self.record_call(
                    segment.ident.span,
                    "method-call",
                    resolved.unwrap_or_else(|| {
                        ResolvedCall::unresolved(segment.ident.as_str().to_string())
                    }),
                );
            }
            ExprKind::Call(func, _) => {
                let resolved = resolve_expr_call(self.tcx, self.typeck, func, self.function_ids);
                self.record_call(
                    func.span,
                    "call",
                    resolved.unwrap_or_else(|| {
                        ResolvedCall::unresolved(
                            self.tcx
                                .sess
                                .source_map()
                                .span_to_snippet(func.span)
                                .unwrap_or_else(|_| "<unknown-call>".to_string()),
                        )
                    }),
                );
            }
            ExprKind::Closure(closure) => match closure.kind {
                ClosureKind::Closure => {
                    self.push_signal(
                        expr.span,
                        "closure-model",
                        "closure environment modeled via MIR aggregate captures",
                    );
                }
                ClosureKind::Coroutine(kind) => {
                    let message = if matches!(
                        kind,
                        CoroutineKind::Desugared(
                            CoroutineDesugaring::Async | CoroutineDesugaring::AsyncGen,
                            _
                        )
                    ) {
                        "async coroutine modeled via compiler coroutine MIR"
                    } else {
                        "coroutine modeled via compiler coroutine MIR"
                    };
                    self.push_signal(expr.span, "async-model", message);
                }
                ClosureKind::CoroutineClosure(desug) => {
                    let _ = desug;
                    self.push_signal(
                        expr.span,
                        "async-model",
                        "async closure/task environment modeled via coroutine-closure MIR",
                    );
                }
            },
            _ => {}
        }
        intravisit::walk_expr(self, expr);
    }

    fn visit_block(&mut self, block: &'tcx rustc_hir::Block<'tcx>) {
        if let rustc_hir::BlockCheckMode::UnsafeBlock(source) = block.rules {
            let description = match source {
                UnsafeSource::UserProvided => "unsafe block detected",
                UnsafeSource::CompilerGenerated => "compiler-generated unsafe block detected",
            };
            self.push_signal(block.span, "unsafe-code", description);
        }
        intravisit::walk_block(self, block);
    }

    fn visit_pat(&mut self, pat: &'tcx rustc_hir::Pat<'tcx>) {
        if let PatKind::Binding(_, _, ident, _) = pat.kind {
            let material_kind = classify_secret_name_kind(ident.as_str());
            if material_kind != "material" {
                self.push_crypto_material(pat.span, material_kind, ident.as_str(), "medium");
            }
        }
        intravisit::walk_pat(self, pat);
    }
}

impl<'tcx> BodyVisitor<'tcx, '_> {
    fn record_call(&mut self, span: Span, usage_kind: &str, resolved: ResolvedCall) {
        let file_path = file_path_from_span(self.tcx, self.analysis_root, span);
        let position = position_from_span(self.tcx, self.analysis_root, span);
        let mut properties = IndexMap::new();
        properties.insert("callType".to_string(), resolved.call_type.clone());
        properties.insert(
            "resolvedSymbol".to_string(),
            resolved.callee_display.clone(),
        );
        properties.insert(
            "dispatchConfidence".to_string(),
            resolved.dispatch_confidence.clone(),
        );
        properties.insert(
            "specializationKey".to_string(),
            resolved.specialization_key.clone(),
        );
        if let Some(receiver_type) = &resolved.receiver_type {
            properties.insert("receiverType".to_string(), receiver_type.clone());
        }
        if !resolved.target_names.is_empty() {
            properties.insert(
                "candidateTargets".to_string(),
                resolved.target_names.join(","),
            );
        }
        if !resolved.candidate_receivers.is_empty() {
            properties.insert(
                "candidateReceiverTypes".to_string(),
                resolved.candidate_receivers.join(","),
            );
        }
        if !resolved.semantic_tags.is_empty() {
            properties.insert("semanticTags".to_string(), resolved.semantic_tags.join(","));
        }
        if resolved.async_boundary {
            properties.insert("asyncBoundary".to_string(), "true".to_string());
        }
        if resolved.task_boundary {
            properties.insert("taskBoundary".to_string(), "true".to_string());
        }
        let usage = LibraryUsage {
            id: stable_id(
                "usage",
                &[
                    &file_path,
                    usage_kind,
                    &resolved.callee_display,
                    &span_key(self.tcx, span),
                ],
            ),
            kind: usage_kind.to_string(),
            name: resolved.callee_display.clone(),
            package_path: self.crate_name.to_string(),
            purl: String::new(),
            enclosing_declaration: Some(self.caller_decl.id.clone()),
            position: position.clone(),
            properties: properties.clone(),
        };
        if !self.usages.iter().any(|existing| existing.id == usage.id) {
            self.usages.push(usage.clone());
        }
        let file = self.file_entry(&file_path);
        if !file.usages.iter().any(|existing| existing.id == usage.id) {
            file.usages.push(usage);
        }
        self.callsites
            .insert((self.caller, span_key_simple(span)), resolved.clone());
        self.hir_calls.push(HirCallRecord {
            source_id: self.caller_decl.id.clone(),
            file_path: file_path.clone(),
            position: position.clone(),
            resolved: resolved.clone(),
        });
        if let Some(rule) = classify_crypto_symbol(&resolved.callee_display) {
            self.push_crypto_component(span, &rule);
        }
        if resolved.async_boundary
            || resolved.task_boundary
            || looks_like_async_boundary(&resolved.callee_display)
        {
            self.push_signal(
                span,
                "async-model",
                "spawn/task boundary modeled for callgraph and slicing",
            );
        }
    }

    fn push_signal(&mut self, span: Span, category: &str, description: &str) {
        let file_path = file_path_from_span(self.tcx, self.analysis_root, span);
        let signal = SecuritySignal {
            cfg_gate: None,
            id: stable_id("signal", &[&file_path, category, &span_key(self.tcx, span)]),
            category: category.to_string(),
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            description: description.to_string(),
            package_path: self.crate_name.to_string(),
            purl: String::new(),
            file_path: file_path.clone(),
            position: position_from_span(self.tcx, self.analysis_root, span),
        };
        if !self
            .security_signals
            .iter()
            .any(|existing| existing.id == signal.id)
        {
            self.security_signals.push(signal.clone());
        }
        let file = self.file_entry(&file_path);
        if !file
            .security_signals
            .iter()
            .any(|existing| existing.id == signal.id)
        {
            file.security_signals.push(signal);
        }
    }

    fn push_crypto_component(&mut self, span: Span, rule: &CryptoRule) {
        let file_path = file_path_from_span(self.tcx, self.analysis_root, span);
        let position = position_from_span(self.tcx, self.analysis_root, span);
        let library = CryptoLibrary {
            id: stable_id("crypto-library", &[rule.provider, &file_path]),
            path: rule.provider.to_string(),
            family: rule.kind.to_string(),
            package_path: self.crate_name.to_string(),
            file_path: file_path.clone(),
            position: position.clone(),
            properties: IndexMap::new(),
        };
        if !self
            .crypto
            .libraries
            .iter()
            .any(|existing| existing.id == library.id)
        {
            self.crypto.libraries.push(library.clone());
        }
        let component = CryptoComponent {
            id: stable_id(
                "crypto-component",
                &[rule.symbol, &file_path, &span_key(self.tcx, span)],
            ),
            kind: rule.kind.to_string(),
            algorithm: rule.algorithm.to_string(),
            provider: rule.provider.to_string(),
            operation: rule.operation.to_string(),
            symbol: rule.symbol.to_string(),
            package_path: self.crate_name.to_string(),
            file_path: file_path.clone(),
            position: position.clone(),
            properties: IndexMap::new(),
        };
        if !self
            .crypto
            .components
            .iter()
            .any(|existing| existing.id == component.id)
        {
            self.crypto.components.push(component.clone());
        }
        if let Some((category, severity, summary)) = rule.finding {
            let finding = CryptoFinding {
                id: stable_id(
                    "crypto-finding",
                    &[category, rule.symbol, &span_key(self.tcx, span)],
                ),
                category: category.to_string(),
                severity: severity.to_string(),
                confidence: "high".to_string(),
                summary: summary.to_string(),
                package_path: self.crate_name.to_string(),
                file_path: file_path.clone(),
                position,
                properties: IndexMap::new(),
            };
            if !self
                .crypto
                .findings
                .iter()
                .any(|existing| existing.id == finding.id)
            {
                self.crypto.findings.push(finding.clone());
            }
            let file = self.file_entry(&file_path);
            let file_crypto = file.crypto.get_or_insert_with(CryptoEvidence::default);
            if !file_crypto
                .libraries
                .iter()
                .any(|existing| existing.id == library.id)
            {
                file_crypto.libraries.push(library.clone());
            }
            if !file_crypto
                .components
                .iter()
                .any(|existing| existing.id == component.id)
            {
                file_crypto.components.push(component.clone());
            }
            if !file_crypto
                .findings
                .iter()
                .any(|existing| existing.id == finding.id)
            {
                file_crypto.findings.push(finding);
            }
        } else {
            let file = self.file_entry(&file_path);
            let file_crypto = file.crypto.get_or_insert_with(CryptoEvidence::default);
            if !file_crypto
                .libraries
                .iter()
                .any(|existing| existing.id == library.id)
            {
                file_crypto.libraries.push(library);
            }
            if !file_crypto
                .components
                .iter()
                .any(|existing| existing.id == component.id)
            {
                file_crypto.components.push(component);
            }
        }
    }

    fn push_crypto_material(&mut self, span: Span, kind: &str, name: &str, confidence: &str) {
        if !looks_like_secret_name(name) {
            return;
        }
        let file_path = file_path_from_span(self.tcx, self.analysis_root, span);
        let material = CryptoMaterial {
            id: stable_id(
                "crypto-material",
                &[kind, name, &file_path, &span_key(self.tcx, span)],
            ),
            kind: kind.to_string(),
            name: name.to_string(),
            package_path: self.crate_name.to_string(),
            file_path: file_path.clone(),
            function: self.caller_decl.qualified_name.clone(),
            confidence: confidence.to_string(),
            position: position_from_span(self.tcx, self.analysis_root, span),
            properties: IndexMap::new(),
        };
        if !self
            .crypto
            .materials
            .iter()
            .any(|existing| existing.id == material.id)
        {
            self.crypto.materials.push(material.clone());
        }
        let file = self.file_entry(&file_path);
        let file_crypto = file.crypto.get_or_insert_with(CryptoEvidence::default);
        if !file_crypto
            .materials
            .iter()
            .any(|existing| existing.id == material.id)
        {
            file_crypto.materials.push(material);
        }
    }

    fn file_entry(&mut self, path: &str) -> &mut FileEvidence {
        self.files
            .entry(path.to_string())
            .or_insert_with(|| FileEvidence {
                path: path.to_string(),
                package_name: self.crate_name.to_string(),
                package_path: self.crate_name.to_string(),
                purl: String::new(),
                imports: Vec::new(),
                declarations: Vec::new(),
                usages: Vec::new(),
                security_signals: Vec::new(),
                crypto: Some(CryptoEvidence::default()),
            })
    }
}

#[derive(Debug, Clone)]
struct ResolvedCall {
    callee_display: String,
    call_type: String,
    dispatch_confidence: String,
    target_ids: Vec<String>,
    target_names: Vec<String>,
    candidate_receivers: Vec<String>,
    receiver_type: Option<String>,
    /// Trait whose vtable dispatched this call. `Some` only for a
    /// `ty::Dynamic` receiver whose targets were found through that trait's
    /// impls; see [`DynCandidates`].
    dispatch_trait: Option<String>,
    specialization_key: String,
    semantic_tags: Vec<String>,
    async_boundary: bool,
    task_boundary: bool,
}

impl ResolvedCall {
    fn unresolved(name: String) -> Self {
        Self {
            callee_display: name,
            call_type: "unresolved".to_string(),
            dispatch_confidence: "low".to_string(),
            target_ids: Vec::new(),
            target_names: Vec::new(),
            candidate_receivers: Vec::new(),
            receiver_type: None,
            dispatch_trait: None,
            specialization_key: "unresolved".to_string(),
            semantic_tags: Vec::new(),
            async_boundary: false,
            task_boundary: false,
        }
    }
}

#[derive(Debug, Clone)]
struct MirFunction {
    id: String,
    name: String,
    qualified_name: String,
    kind: String,
    package_path: String,
    file_path: String,
    position: Position,
    param_names: Vec<String>,
    param_types: Vec<String>,
    return_type: String,
    blocks: Vec<MirBlock>,
}

impl MirFunction {
    fn from_mir(
        crate_name: &str,
        declaration: Declaration,
        body: &MirBody<'_>,
        callsites: HashMap<String, ResolvedCall>,
        local_resolutions: &HashMap<String, ResolvedCall>,
        closure_candidates: &HashMap<usize, Vec<ResolvedCall>>,
    ) -> Self {
        let debug_names = debug_local_names(body);
        let param_names = (1..=body.arg_count)
            .map(|idx| {
                debug_names
                    .get(&Local::from_usize(idx))
                    .cloned()
                    .unwrap_or_else(|| format!("_{idx}"))
            })
            .collect::<Vec<_>>();
        let param_types = (1..=body.arg_count)
            .map(|idx| body.local_decls[Local::from_usize(idx)].ty.to_string())
            .collect::<Vec<_>>();
        let blocks = body
            .basic_blocks
            .iter_enumerated()
            .map(|(bb, data)| {
                MirBlock::from_block(
                    body,
                    &debug_names,
                    bb,
                    data,
                    &callsites,
                    local_resolutions,
                    closure_candidates,
                )
            })
            .collect::<Vec<_>>();
        Self {
            id: declaration.id.clone(),
            name: declaration.name.clone(),
            qualified_name: declaration.qualified_name,
            kind: declaration.kind,
            package_path: crate_name.to_string(),
            file_path: declaration.file_path,
            position: declaration.position,
            param_names,
            param_types,
            return_type: body.local_decls[mir::RETURN_PLACE].ty.to_string(),
            blocks,
        }
    }
}

#[derive(Debug, Clone)]
struct MirBlock {
    label: String,
    ops: Vec<MirOp>,
    successors: Vec<String>,
    returns: bool,
}

impl MirBlock {
    fn from_block(
        body: &MirBody<'_>,
        debug_names: &HashMap<Local, String>,
        bb: BasicBlock,
        data: &mir::BasicBlockData<'_>,
        callsites: &HashMap<String, ResolvedCall>,
        local_resolutions: &HashMap<String, ResolvedCall>,
        closure_candidates: &HashMap<usize, Vec<ResolvedCall>>,
    ) -> Self {
        let mut ops = Vec::new();
        for statement in &data.statements {
            match &statement.kind {
                StatementKind::Assign(assign) => {
                    let (place, rvalue) = &**assign;
                    if let Some(action) =
                        AssignAction::from_rvalue(body, debug_names, place, rvalue)
                    {
                        ops.push(MirOp::Assign(action));
                    }
                }
                StatementKind::StorageDead(local) => {
                    ops.push(MirOp::Kill(place_from_local(debug_names, *local)));
                }
                StatementKind::SetDiscriminant {
                    place,
                    variant_index,
                } => {
                    ops.push(MirOp::Assign(AssignAction {
                        dest: place_to_path(debug_names, **place),
                        sources: Vec::new(),
                        alias: None,
                        field_sources: vec![(
                            place_to_path(debug_names, **place).push(PlaceProjection::Variant(
                                variant_index.as_usize().to_string(),
                            )),
                            Vec::new(),
                        )],
                    }));
                }
                _ => {}
            }
        }
        let mut successors = Vec::new();
        let mut returns = false;
        if let Some(terminator) = &data.terminator {
            match &terminator.kind {
                TerminatorKind::Return => returns = true,
                TerminatorKind::Goto { target } => successors.push(label_for(*target)),
                TerminatorKind::SwitchInt { targets, .. } => {
                    successors.extend(targets.all_targets().iter().map(|bb| label_for(*bb)));
                }
                TerminatorKind::Drop { target, unwind, .. }
                | TerminatorKind::Assert { target, unwind, .. } => {
                    successors.push(label_for(*target));
                    push_unwind_successor(unwind, &mut successors);
                }
                TerminatorKind::FalseEdge {
                    real_target,
                    imaginary_target,
                } => {
                    successors.push(label_for(*real_target));
                    successors.push(label_for(*imaginary_target));
                }
                TerminatorKind::FalseUnwind {
                    real_target,
                    unwind,
                } => {
                    successors.push(label_for(*real_target));
                    push_unwind_successor(unwind, &mut successors);
                }
                TerminatorKind::Call {
                    func,
                    args,
                    destination,
                    target,
                    unwind,
                    fn_span,
                    ..
                } => {
                    let unresolved_display = operand_display(func, body);
                    let normalized_unresolved = normalize_symbol(&unresolved_display);
                    let normalized_last = normalize_symbol(last_segment(&unresolved_display));
                    let resolved = callsites
                        .get(&span_key_simple(*fn_span))
                        .cloned()
                        .or_else(|| local_resolutions.get(&unresolved_display).cloned())
                        .or_else(|| local_resolutions.get(&normalized_unresolved).cloned())
                        .or_else(|| {
                            local_resolutions
                                .get(last_segment(&unresolved_display))
                                .cloned()
                        })
                        .or_else(|| local_resolutions.get(&normalized_last).cloned())
                        .or_else(|| {
                            callable_candidate_resolution(
                                &unresolved_display,
                                args.len(),
                                closure_candidates,
                            )
                        })
                        .unwrap_or_else(|| ResolvedCall::unresolved(unresolved_display));
                    ops.push(MirOp::Call(MirCall {
                        dest: place_to_path(debug_names, *destination),
                        dest_type: Some(body.local_decls[destination.local].ty.to_string()),
                        callee_display: resolved.callee_display,
                        call_type: resolved.call_type,
                        dispatch_confidence: resolved.dispatch_confidence,
                        target_ids: resolved.target_ids,
                        target_names: resolved.target_names,
                        candidate_receivers: resolved.candidate_receivers,
                        receiver_type: resolved.receiver_type,
                        dispatch_trait: resolved.dispatch_trait,
                        specialization_key: resolved.specialization_key,
                        semantic_tags: resolved.semantic_tags,
                        async_boundary: resolved.async_boundary,
                        task_boundary: resolved.task_boundary,
                        args: args
                            .iter()
                            .map(|arg| CallArg::from_operand(body, debug_names, arg.node.clone()))
                            .collect(),
                    }));
                    if let Some(target) = target {
                        successors.push(label_for(*target));
                    }
                    push_unwind_successor(unwind, &mut successors);
                }
                _ => {}
            }
        }
        successors.sort();
        successors.dedup();
        Self {
            label: label_for(bb),
            ops,
            successors,
            returns,
        }
    }
}

fn callable_candidate_resolution(
    unresolved_display: &str,
    arg_count: usize,
    closure_candidates: &HashMap<usize, Vec<ResolvedCall>>,
) -> Option<ResolvedCall> {
    let normalized = normalize_symbol(unresolved_display);
    if !(normalized.contains("FnOnce")
        || normalized.contains("FnMut")
        || normalized.contains("Fn<")
        || normalized.contains("call_once")
        || normalized.contains("call_mut"))
    {
        return None;
    }
    let candidates = closure_candidates.get(&arg_count)?;
    if candidates.is_empty() {
        return None;
    }
    let mut target_ids = Vec::new();
    let mut target_names = Vec::new();
    for candidate in candidates {
        target_ids.extend(candidate.target_ids.clone());
        target_names.extend(candidate.target_names.clone());
    }
    target_names.sort();
    target_names.dedup();
    target_ids.sort();
    target_ids.dedup();
    let semantic_tags = vec!["callable".to_string(), "closure".to_string()];
    Some(ResolvedCall {
        callee_display: unresolved_display.to_string(),
        call_type: "closure".to_string(),
        dispatch_confidence: dispatch_confidence_for("closure", target_ids.len()),
        target_ids,
        target_names: target_names.clone(),
        candidate_receivers: Vec::new(),
        receiver_type: None,
        dispatch_trait: None,
        specialization_key: specialization_key_from_parts(None, &semantic_tags, &target_names),
        semantic_tags,
        async_boundary: false,
        task_boundary: false,
    })
}

#[derive(Debug, Clone)]
enum MirOp {
    Assign(AssignAction),
    Kill(PlacePath),
    Call(MirCall),
}

#[derive(Debug, Clone)]
struct AssignAction {
    dest: PlacePath,
    sources: Vec<PlacePath>,
    alias: Option<PlacePath>,
    field_sources: Vec<(PlacePath, Vec<PlacePath>)>,
}

impl AssignAction {
    fn from_rvalue(
        body: &MirBody<'_>,
        debug_names: &HashMap<Local, String>,
        dest: &Place<'_>,
        rvalue: &Rvalue<'_>,
    ) -> Option<Self> {
        let dest_path = place_to_path(debug_names, *dest);
        match rvalue {
            Rvalue::Use(operand, _)
            | Rvalue::Cast(_, operand, _)
            | Rvalue::UnaryOp(_, operand)
            | Rvalue::Repeat(operand, _) => Some(Self {
                dest: dest_path,
                sources: operand_places(body, debug_names, operand),
                alias: None,
                field_sources: Vec::new(),
            }),
            Rvalue::Ref(_, _, borrowed)
            | Rvalue::RawPtr(_, borrowed)
            | Rvalue::CopyForDeref(borrowed) => Some(Self {
                dest: dest_path,
                sources: vec![place_to_path(debug_names, *borrowed)],
                alias: Some(place_to_path(debug_names, *borrowed)),
                field_sources: Vec::new(),
            }),
            Rvalue::BinaryOp(_, operands) => {
                let (left, right) = &**operands;
                let mut sources = operand_places(body, debug_names, left);
                sources.extend(operand_places(body, debug_names, right));
                Some(Self {
                    dest: dest_path,
                    sources,
                    alias: None,
                    field_sources: Vec::new(),
                })
            }
            Rvalue::Aggregate(_, operands) => {
                let mut field_sources = Vec::new();
                let mut sources = Vec::new();
                for (index, operand) in operands.iter_enumerated() {
                    let operand_places = operand_places(body, debug_names, operand);
                    sources.extend(operand_places.clone());
                    field_sources.push((
                        dest_path.push(PlaceProjection::Field(index.as_usize().to_string())),
                        operand_places,
                    ));
                }
                Some(Self {
                    dest: dest_path,
                    sources,
                    alias: None,
                    field_sources,
                })
            }
            Rvalue::Discriminant(place) => Some(Self {
                dest: dest_path,
                sources: Vec::new(),
                alias: Some(place_to_path(debug_names, *place)),
                field_sources: Vec::new(),
            }),
            Rvalue::ThreadLocalRef(_) => Some(Self {
                dest: dest_path,
                sources: Vec::new(),
                alias: None,
                field_sources: Vec::new(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct MirCall {
    dest: PlacePath,
    dest_type: Option<String>,
    callee_display: String,
    call_type: String,
    dispatch_confidence: String,
    target_ids: Vec<String>,
    target_names: Vec<String>,
    candidate_receivers: Vec<String>,
    receiver_type: Option<String>,
    dispatch_trait: Option<String>,
    specialization_key: String,
    semantic_tags: Vec<String>,
    async_boundary: bool,
    task_boundary: bool,
    args: Vec<CallArg>,
}

#[derive(Debug, Clone)]
struct CallArg {
    place: Option<PlacePath>,
    type_name: Option<String>,
}

impl CallArg {
    fn from_operand(
        body: &MirBody<'_>,
        debug_names: &HashMap<Local, String>,
        operand: Operand<'_>,
    ) -> Self {
        match operand {
            Operand::Copy(place) | Operand::Move(place) => {
                let path = place_to_path(debug_names, place);
                Self {
                    place: Some(path.clone()),
                    type_name: Some(body.local_decls[place.local].ty.to_string()),
                }
            }
            Operand::Constant(constant) => Self {
                place: None,
                type_name: Some(constant.const_.ty().to_string()),
            },
            Operand::RuntimeChecks(_) => Self {
                place: None,
                type_name: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
struct PlacePath {
    base: String,
    projections: Vec<PlaceProjection>,
}

impl PlacePath {
    fn push(&self, projection: PlaceProjection) -> Self {
        let mut next = self.clone();
        next.projections.push(projection);
        next
    }

    fn parent(&self) -> Option<Self> {
        if self.projections.is_empty() {
            None
        } else {
            let mut next = self.clone();
            next.projections.pop();
            Some(next)
        }
    }

    fn is_indirect(&self) -> bool {
        self.projections.iter().any(|projection| {
            matches!(
                projection,
                PlaceProjection::Deref | PlaceProjection::Index(_) | PlaceProjection::Opaque(_)
            )
        })
    }

    fn synthetic_field(&self, name: &str) -> Self {
        self.push(PlaceProjection::Field(name.to_string()))
    }

    fn render(&self) -> String {
        let mut value = self.base.clone();
        for projection in &self.projections {
            match projection {
                PlaceProjection::Deref => value.push_str(".*"),
                PlaceProjection::Field(name) => {
                    value.push('.');
                    value.push_str(name);
                }
                PlaceProjection::Variant(name) => {
                    value.push_str("::");
                    value.push_str(name);
                }
                PlaceProjection::Index(name) => {
                    value.push('[');
                    value.push_str(name);
                    value.push(']');
                }
                PlaceProjection::Opaque(name) => {
                    value.push_str(".<");
                    value.push_str(name);
                    value.push('>');
                }
            }
        }
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PlaceProjection {
    Deref,
    Field(String),
    Variant(String),
    Index(String),
    Opaque(String),
}

fn place_from_local(debug_names: &HashMap<Local, String>, local: Local) -> PlacePath {
    PlacePath {
        base: debug_names
            .get(&local)
            .cloned()
            .unwrap_or_else(|| format!("_{}", local.index())),
        projections: Vec::new(),
    }
}

fn place_to_path(debug_names: &HashMap<Local, String>, place: Place<'_>) -> PlacePath {
    let mut current = place_from_local(debug_names, place.local);
    for projection in place.projection.iter() {
        match projection {
            ProjectionElem::Deref => current.projections.push(PlaceProjection::Deref),
            ProjectionElem::Field(field, _) => current
                .projections
                .push(PlaceProjection::Field(field.as_usize().to_string())),
            ProjectionElem::Downcast(name, variant) => {
                current.projections.push(PlaceProjection::Variant(
                    name.map(|sym| sym.to_string())
                        .unwrap_or_else(|| variant.as_usize().to_string()),
                ))
            }
            ProjectionElem::Index(local) => current.projections.push(PlaceProjection::Index(
                debug_names
                    .get(&local)
                    .cloned()
                    .unwrap_or_else(|| format!("_{}", local.index())),
            )),
            ProjectionElem::ConstantIndex { offset, .. } => current
                .projections
                .push(PlaceProjection::Index(offset.to_string())),
            ProjectionElem::Subslice { from, to, from_end } => current.projections.push(
                PlaceProjection::Opaque(format!("subslice:{from}:{to}:{from_end}")),
            ),
            ProjectionElem::OpaqueCast(ty) => current
                .projections
                .push(PlaceProjection::Opaque(ty.to_string())),
            ProjectionElem::UnwrapUnsafeBinder(ty) => current
                .projections
                .push(PlaceProjection::Opaque(ty.to_string())),
        }
    }
    current
}

fn debug_local_names(body: &MirBody<'_>) -> HashMap<Local, String> {
    let mut names = HashMap::new();
    for debug in &body.var_debug_info {
        if let mir::VarDebugInfoContents::Place(place) = debug.value
            && let Some(local) = place.as_local()
        {
            names.insert(local, debug.name.to_string());
        }
    }
    names
}

fn operand_places(
    _body: &MirBody<'_>,
    debug_names: &HashMap<Local, String>,
    operand: &Operand<'_>,
) -> Vec<PlacePath> {
    match operand {
        Operand::Copy(place) | Operand::Move(place) => vec![place_to_path(debug_names, *place)],
        Operand::Constant(_) | Operand::RuntimeChecks(_) => Vec::new(),
    }
}

fn operand_display(operand: &Operand<'_>, _body: &MirBody<'_>) -> String {
    match operand {
        Operand::Constant(constant) => format!("{:?}", constant),
        Operand::Copy(place) | Operand::Move(place) => format!("{:?}", place),
        Operand::RuntimeChecks(_) => "runtime-checks".to_string(),
    }
}

fn push_unwind_successor(unwind: &UnwindAction, successors: &mut Vec<String>) {
    if let UnwindAction::Cleanup(bb) = unwind {
        successors.push(label_for(*bb));
    }
}

fn label_for(bb: BasicBlock) -> String {
    format!("bb{}", bb.index())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractOrigin {
    Param(usize),
    Source(String),
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FunctionSummary {
    returns_source_categories: BTreeSet<String>,
    observed_source_categories: BTreeSet<String>,
    param_to_return: BTreeSet<usize>,
    param_to_sink: BTreeMap<String, BTreeSet<usize>>,
    source_to_sink: BTreeMap<String, BTreeSet<String>>,
    param_to_field_write: BTreeMap<PlacePath, BTreeSet<usize>>,
    field_to_return: BTreeSet<PlacePath>,
    effect_shapes: BTreeSet<String>,
    semantic_tags: BTreeSet<String>,
    receiver_type: Option<String>,
    specialization_key: String,
}

impl FunctionSummary {
    fn with_context(function: &MirFunction) -> Self {
        Self {
            receiver_type: receiver_type_for_function(function),
            specialization_key: specialization_key_for_function(function),
            ..Self::default()
        }
    }

    /// Unions `other` into this summary and reports whether anything was
    /// added. The summary fixpoint only ever joins, so a summary grows until
    /// nothing new is learned and the iteration ends by itself.
    fn join(&mut self, other: Self) -> bool {
        let mut changed = false;
        changed |= join_set(
            &mut self.returns_source_categories,
            other.returns_source_categories,
        );
        changed |= join_set(
            &mut self.observed_source_categories,
            other.observed_source_categories,
        );
        changed |= join_set(&mut self.param_to_return, other.param_to_return);
        changed |= join_map(&mut self.param_to_sink, other.param_to_sink);
        changed |= join_map(&mut self.source_to_sink, other.source_to_sink);
        changed |= join_map(&mut self.param_to_field_write, other.param_to_field_write);
        changed |= join_set(&mut self.field_to_return, other.field_to_return);
        changed |= join_set(&mut self.effect_shapes, other.effect_shapes);
        changed |= join_set(&mut self.semantic_tags, other.semantic_tags);
        if self.receiver_type.is_none() && other.receiver_type.is_some() {
            self.receiver_type = other.receiver_type;
            changed = true;
        }
        if self.specialization_key.is_empty() && !other.specialization_key.is_empty() {
            self.specialization_key = other.specialization_key;
            changed = true;
        }
        changed
    }
}

/// What the data-flow passes consult besides the summaries, built once per
/// crate so that no pass rescans every function for every call it meets.
struct FlowContext<'a> {
    patterns: &'a DataFlowPatternSet,
    local_ids: &'a HashSet<String>,
    function_map: &'a HashMap<String, &'a MirFunction>,
    /// Trait impl methods by `(trait's last path segment, method name)`, in
    /// id order.
    trait_impls: HashMap<(String, String), Vec<String>>,
    /// Trait impl methods of any trait by method name, in id order.
    impl_methods: HashMap<String, Vec<String>>,
    /// Closure and async bodies nested anywhere under a function, keyed by
    /// the enclosing function's qualified name, in id order.
    nested_bodies: HashMap<String, Vec<String>>,
    /// Each function's control-flow graph, by function id.
    block_graphs: HashMap<String, BlockGraph>,
    /// What every call in the crate's bodies amounts to, by function id,
    /// then block and operation index (see [`FlowContext::call_facts`]).
    call_facts: HashMap<String, Vec<Vec<Option<CallFacts>>>>,
}

/// What the data-flow passes derive from a call on its own, whatever state
/// it is reached in. None of it changes between visits, so it is worked out
/// once per call when the context is built rather than on every trip through
/// the fixpoints; rustc hoists loop-invariant work out of its hot paths the
/// same way (rust-lang/rust#160605).
struct CallFacts {
    source_category: Option<String>,
    sinks: Vec<(String, Vec<usize>)>,
    source_arguments: Vec<(String, Vec<usize>)>,
    effect_shape: String,
    model_tags: BTreeSet<&'static str>,
    /// A modeled or conventionally named passthrough (`clone`, `unwrap`).
    passthrough: bool,
    /// Passes data through by its semantic tags (a combinator, a callable).
    semantic_passthrough: bool,
    /// The local functions the call may reach ([`candidate_dataflow_targets`]).
    targets: Vec<String>,
}

impl CallFacts {
    fn of(call: &MirCall, ctx: &FlowContext<'_>) -> Self {
        let source_category = source_category(call);
        let sinks = sink_matches(call, ctx.patterns).unwrap_or_default();
        let passthrough = passthrough(call);
        let semantic_passthrough = semantic_passthrough(call);
        let mut shapes = Vec::new();
        if source_category.is_some() {
            shapes.push("source-return");
        }
        if !sinks.is_empty() {
            shapes.push("sink-call");
        }
        if passthrough || semantic_passthrough {
            shapes.push("param-return");
        }
        if call.semantic_tags.iter().any(|tag| tag == "builder") {
            shapes.push("param-field-write");
        }
        if is_channel_send(call) {
            shapes.push("channel-send");
        }
        if is_channel_recv(call) {
            shapes.push("channel-recv");
        }
        if shapes.is_empty() {
            shapes.push("opaque");
        }
        Self {
            source_category,
            sinks,
            source_arguments: source_argument_matches(call),
            effect_shape: shapes.join("+"),
            model_tags: model_tags_for_call(call),
            passthrough,
            semantic_passthrough,
            targets: candidate_dataflow_targets(call, ctx),
        }
    }
}

impl<'a> FlowContext<'a> {
    fn new(
        functions: &[MirFunction],
        patterns: &'a DataFlowPatternSet,
        local_ids: &'a HashSet<String>,
        function_map: &'a HashMap<String, &'a MirFunction>,
    ) -> Self {
        let mut trait_impls: HashMap<(String, String), Vec<String>> = HashMap::new();
        let mut impl_methods: HashMap<String, Vec<String>> = HashMap::new();
        let mut nested_bodies: HashMap<String, Vec<String>> = HashMap::new();
        for function in functions {
            if let Some((trait_name, method)) = impl_trait_method_parts(&function.qualified_name) {
                impl_methods
                    .entry(method.clone())
                    .or_default()
                    .push(function.id.clone());
                trait_impls
                    .entry((trait_name, method))
                    .or_default()
                    .push(function.id.clone());
            }
            // Every prefix that ends right before a `::{closure#` is an
            // enclosing function of this body.
            let name = function.qualified_name.as_str();
            for (at, _) in name.match_indices("::{closure#") {
                nested_bodies
                    .entry(name[..at].to_string())
                    .or_default()
                    .push(function.id.clone());
            }
        }
        for ids in trait_impls
            .values_mut()
            .chain(impl_methods.values_mut())
            .chain(nested_bodies.values_mut())
        {
            ids.sort();
            ids.dedup();
        }
        let block_graphs = functions
            .iter()
            .map(|function| (function.id.clone(), BlockGraph::new(function)))
            .collect();
        let mut ctx = Self {
            patterns,
            local_ids,
            function_map,
            trait_impls,
            impl_methods,
            nested_bodies,
            block_graphs,
            call_facts: HashMap::new(),
        };
        let call_facts = functions
            .iter()
            .map(|function| {
                let blocks = function
                    .blocks
                    .iter()
                    .map(|block| {
                        block
                            .ops
                            .iter()
                            .map(|op| match op {
                                MirOp::Call(call) => Some(CallFacts::of(call, &ctx)),
                                _ => None,
                            })
                            .collect()
                    })
                    .collect();
                (function.id.clone(), blocks)
            })
            .collect();
        ctx.call_facts = call_facts;
        ctx
    }

    /// The facts of the call at operation `op` of block `block` in
    /// `function`, one of the bodies this context was built from. A call is
    /// named by where it sits rather than by its address, so a copy of a
    /// body finds the same facts.
    fn call_facts(&self, function: &MirFunction, block: usize, op: usize) -> &CallFacts {
        self.call_facts
            .get(function.id.as_str())
            .and_then(|blocks| blocks.get(block))
            .and_then(|ops| ops.get(op))
            .and_then(Option::as_ref)
            .expect("a call in a body this context was built from")
    }

    fn block_graph(&self, function: &MirFunction) -> &BlockGraph {
        self.block_graphs
            .get(&function.id)
            .expect("every function has a block graph")
    }

    /// Impl methods `<T as Trait>::method` of a trait whose last path
    /// segment is `trait_name`.
    fn trait_method_impls(&self, trait_name: &str, method: &str) -> &[String] {
        self.trait_impls
            .get(&(last_segment(trait_name).to_string(), method.to_string()))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Trait impl methods named `method`, of any trait.
    fn method_impls(&self, method: &str) -> &[String] {
        self.impl_methods
            .get(method)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// A function's blocks as successor indexes, with the order the fixpoint
/// visits them in.
struct BlockGraph {
    successors: Vec<Vec<usize>>,
    /// Blocks reachable from the entry block in weak topological order: each
    /// loop's blocks together, right after its head (see
    /// `rusi_schema::fixpoint`).
    order: Vec<usize>,
}

impl BlockGraph {
    fn new(function: &MirFunction) -> Self {
        let index: HashMap<&str, usize> = function
            .blocks
            .iter()
            .enumerate()
            .map(|(position, block)| (block.label.as_str(), position))
            .collect();
        let successors: Vec<Vec<usize>> = function
            .blocks
            .iter()
            .map(|block| {
                block
                    .successors
                    .iter()
                    .filter_map(|label| index.get(label.as_str()).copied())
                    .collect()
            })
            .collect();
        let order = weak_topological_order(successors.len(), 0, |block| {
            successors[block].iter().copied()
        });
        Self { successors, order }
    }
}

/// One evaluation of a function's summary: the summaries it may read, which
/// are recorded as it reads them, and the recursion cycle it sits in.
struct SummaryPass<'p, 'a> {
    ctx: &'p FlowContext<'a>,
    summaries: &'p TrackedReads<'p, FunctionSummary>,
    component_of: &'p HashMap<&'p str, usize>,
    component: usize,
}

impl SummaryPass<'_, '_> {
    /// Whether `callee` is in the recursion cycle being summarized. Places
    /// taken from such a callee's summary are widened when rebased: a
    /// recursive call on a projection of its own parameter (`walk(&n.next)`)
    /// would otherwise grow `n.next.val`, `n.next.next.val`, and so on
    /// without end.
    fn in_cycle(&self, callee: &str) -> bool {
        self.component_of.get(callee) == Some(&self.component)
    }
}

#[derive(Debug, Clone, Default)]
struct AbstractState {
    taints: BTreeMap<PlacePath, BTreeSet<AbstractOrigin>>,
    aliases: HashMap<PlacePath, PlacePath>,
}

#[derive(Debug, Clone, Default)]
struct ConcreteState {
    taints: BTreeMap<PlacePath, ConcreteTaint>,
    aliases: HashMap<PlacePath, PlacePath>,
}

fn build_call_graph(
    functions: &[MirFunction],
    hir_calls: &[HirCallRecord],
    declarations: &[Declaration],
    diagnostics: &mut Vec<Diagnostic>,
) -> CallGraph {
    let mut nodes = IndexMap::<String, CallGraphNode>::new();
    let mut edges = IndexMap::<String, CallGraphEdge>::new();
    let local_ids = functions
        .iter()
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>();
    let hir_precision = hir_precision_index(hir_calls);
    for function in functions {
        nodes
            .entry(function.id.clone())
            .or_insert_with(|| CallGraphNode {
                id: function.id.clone(),
                name: function.name.clone(),
                qualified_name: function.qualified_name.clone(),
                canonical_name: rusi_schema::canonical_name(&function.qualified_name),
                kind: function.kind.clone(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                file_path: function.file_path.clone(),
                local: true,
                external: false,
                receiver: None,
                position: function.position.clone(),
            });
        for block in &function.blocks {
            for op in &block.ops {
                let MirOp::Call(call) = op else {
                    continue;
                };
                let targets = if call.target_ids.is_empty() {
                    vec![(
                        stable_id("cg-node", &["external", &call.callee_display]),
                        call.callee_display.clone(),
                        false,
                    )]
                } else {
                    call.target_ids
                        .iter()
                        .enumerate()
                        .map(|(idx, id)| {
                            (
                                id.clone(),
                                call.target_names
                                    .get(idx)
                                    .cloned()
                                    .unwrap_or_else(|| call.callee_display.clone()),
                                local_ids.contains(id),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                for (target_id, target_name, local) in targets {
                    if should_skip_mir_edge(&function.id, &target_name, call, &hir_precision) {
                        continue;
                    }
                    if !local {
                        nodes
                            .entry(target_id.clone())
                            .or_insert_with(|| CallGraphNode {
                                id: target_id.clone(),
                                name: last_segment(&target_name).to_string(),
                                qualified_name: target_name.clone(),
                                canonical_name: rusi_schema::canonical_name(&target_name),
                                kind: if call.call_type == "native" {
                                    "foreign-function".to_string()
                                } else {
                                    "external-function".to_string()
                                },
                                package_path: inferred_package_path(&target_name),
                                purl: String::new(),
                                file_path: String::new(),
                                local: false,
                                external: true,
                                receiver: None,
                                position: function.position.clone(),
                            });
                    }
                    if !local
                        && call.target_ids.is_empty()
                        && should_emit_unresolved_dataflow_diagnostic(&call.callee_display)
                    {
                        diagnostics.push(Diagnostic {
                            kind: "resolution".to_string(),
                            message: format!(
                                "unresolved embedded compiler call target {}",
                                call.callee_display
                            ),
                            package_path: Some(function.package_path.clone()),
                            file_path: Some(function.file_path.clone()),
                            position: Some(function.position.clone()),
                        });
                    }
                    let mut properties = IndexMap::new();
                    properties.insert("calleeText".to_string(), call.callee_display.clone());
                    properties.insert(
                        "dispatchConfidence".to_string(),
                        call.dispatch_confidence.clone(),
                    );
                    properties.insert(
                        "specializationKey".to_string(),
                        call.specialization_key.clone(),
                    );
                    properties.insert("edgePrecision".to_string(), edge_precision_for(call));
                    if !call.target_names.is_empty() {
                        properties
                            .insert("candidateTargets".to_string(), call.target_names.join(","));
                    }
                    if !call.candidate_receivers.is_empty() {
                        properties.insert(
                            "candidateReceiverTypes".to_string(),
                            call.candidate_receivers.join(","),
                        );
                    }
                    if let Some(receiver_type) = &call.receiver_type {
                        properties.insert("receiverType".to_string(), receiver_type.clone());
                    }
                    if !call.semantic_tags.is_empty() {
                        properties.insert("semanticTags".to_string(), call.semantic_tags.join(","));
                    }
                    if call.async_boundary {
                        properties.insert("asyncBoundary".to_string(), "true".to_string());
                    }
                    if call.task_boundary {
                        properties.insert("taskBoundary".to_string(), "true".to_string());
                    }
                    let edge_id = stable_id(
                        "cg-edge",
                        &[&function.id, &target_id, &block.label, &call.call_type],
                    );
                    edges
                        .entry(edge_id.clone())
                        .or_insert_with(|| CallGraphEdge {
                            id: edge_id,
                            source_id: function.id.clone(),
                            target_id: target_id.clone(),
                            call_type: callgraph_call_type(call),
                            line: function.position.line,
                            column: function.position.column,
                            callee_text: Some(call.callee_display.clone()),
                            receiver: call.receiver_type.clone(),
                            method: None,
                            candidate_count: None,
                            emitted_candidate_count: None,
                            dispatch_trait: call.dispatch_trait.clone(),
                            properties,
                        });
                }
            }
        }
    }
    // HIR calls can come from body owners that have no MIR function here, such
    // as the anon const behind `[0u8; width() * 2]`. Give those callers a node
    // from their declaration so every edge's source exists.
    let declarations_by_id = declarations
        .iter()
        .map(|declaration| (declaration.id.as_str(), declaration))
        .collect::<HashMap<_, _>>();
    for call in hir_calls {
        if !nodes.contains_key(&call.source_id)
            && let Some(declaration) = declarations_by_id.get(call.source_id.as_str())
        {
            nodes.insert(
                call.source_id.clone(),
                CallGraphNode {
                    id: declaration.id.clone(),
                    name: declaration.name.clone(),
                    qualified_name: declaration.qualified_name.clone(),
                    canonical_name: rusi_schema::canonical_name(&declaration.qualified_name),
                    kind: declaration.kind.clone(),
                    package_path: declaration.package_path.clone(),
                    purl: String::new(),
                    file_path: declaration.file_path.clone(),
                    local: true,
                    external: false,
                    receiver: None,
                    position: declaration.position.clone(),
                },
            );
        }
    }
    for call in hir_calls {
        let targets = if call.resolved.target_ids.is_empty() {
            vec![(
                stable_id("cg-node", &["external", &call.resolved.callee_display]),
                call.resolved.callee_display.clone(),
                false,
            )]
        } else {
            call.resolved
                .target_ids
                .iter()
                .enumerate()
                .map(|(idx, id)| {
                    (
                        id.clone(),
                        call.resolved
                            .target_names
                            .get(idx)
                            .cloned()
                            .unwrap_or_else(|| call.resolved.callee_display.clone()),
                        local_ids.contains(id),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (target_id, target_name, local) in targets {
            if !local {
                nodes
                    .entry(target_id.clone())
                    .or_insert_with(|| CallGraphNode {
                        id: target_id.clone(),
                        name: last_segment(&target_name).to_string(),
                        qualified_name: target_name.clone(),
                        canonical_name: rusi_schema::canonical_name(&target_name),
                        kind: if call.resolved.call_type == "native" {
                            "foreign-function".to_string()
                        } else {
                            "external-function".to_string()
                        },
                        package_path: inferred_package_path(&target_name),
                        purl: String::new(),
                        file_path: call.file_path.clone(),
                        local: false,
                        external: true,
                        receiver: call.resolved.receiver_type.clone(),
                        position: call.position.clone(),
                    });
            }
            let mut properties = IndexMap::new();
            properties.insert(
                "calleeText".to_string(),
                call.resolved.callee_display.clone(),
            );
            properties.insert(
                "dispatchConfidence".to_string(),
                call.resolved.dispatch_confidence.clone(),
            );
            properties.insert(
                "specializationKey".to_string(),
                call.resolved.specialization_key.clone(),
            );
            properties.insert(
                "edgePrecision".to_string(),
                match call.resolved.target_ids.len() {
                    0 => "unknown".to_string(),
                    1 => "exact".to_string(),
                    _ => "bounded".to_string(),
                },
            );
            properties.insert("sourceLevel".to_string(), "true".to_string());
            if !call.resolved.target_names.is_empty() {
                properties.insert(
                    "candidateTargets".to_string(),
                    call.resolved.target_names.join(","),
                );
            }
            if !call.resolved.candidate_receivers.is_empty() {
                properties.insert(
                    "candidateReceiverTypes".to_string(),
                    call.resolved.candidate_receivers.join(","),
                );
            }
            if let Some(receiver_type) = &call.resolved.receiver_type {
                properties.insert("receiverType".to_string(), receiver_type.clone());
            }
            if !call.resolved.semantic_tags.is_empty() {
                properties.insert(
                    "semanticTags".to_string(),
                    call.resolved.semantic_tags.join(","),
                );
            }
            if call.resolved.async_boundary {
                properties.insert("asyncBoundary".to_string(), "true".to_string());
            }
            if call.resolved.task_boundary {
                properties.insert("taskBoundary".to_string(), "true".to_string());
            }
            let edge_id = stable_id(
                "cg-edge",
                &[
                    &call.source_id,
                    &target_id,
                    &call.position.line.to_string(),
                    &call.position.column.to_string(),
                    "hir",
                ],
            );
            edges
                .entry(edge_id.clone())
                .or_insert_with(|| CallGraphEdge {
                    id: edge_id,
                    source_id: call.source_id.clone(),
                    target_id: target_id.clone(),
                    call_type: if call.resolved.async_boundary || call.resolved.task_boundary {
                        "async-logical".to_string()
                    } else if call.resolved.target_ids.is_empty() {
                        format!("{}-unknown", call.resolved.call_type)
                    } else if call.resolved.target_ids.len() == 1 {
                        format!("{}-exact", call.resolved.call_type)
                    } else {
                        format!("{}-bounded", call.resolved.call_type)
                    },
                    line: call.position.line,
                    column: call.position.column,
                    callee_text: Some(call.resolved.callee_display.clone()),
                    receiver: call.resolved.receiver_type.clone(),
                    method: None,
                    candidate_count: None,
                    emitted_candidate_count: None,
                    dispatch_trait: call.resolved.dispatch_trait.clone(),
                    properties,
                });
        }
    }
    let mut nodes = nodes.into_values().collect::<Vec<_>>();
    // Edges name their endpoints by node id, so reconciliation needs the node
    // table to reason about what a target actually is.
    let target_names: HashMap<String, String> = nodes
        .iter()
        .map(|node| (node.id.clone(), node.qualified_name.clone()))
        .collect();
    // Callsite and devirtualization tables upstream are hash maps, so edges
    // arrive in a run-dependent order. Sorting by id makes both the output and
    // reconciliation's tie-breaking between equally ranked duplicates stable.
    let mut edges = edges.into_values().collect::<Vec<_>>();
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    // Reconciliation keeps a replacing edge in the slot of the one it
    // displaced, so re-sort for a stable output order.
    let mut edges = reconcile_edges(edges, &target_names);
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    // External nodes exist only as edge targets. Reconciliation can drop the
    // last edge to one (an abstract `Trait::method` superseded by concrete
    // impl edges), which would otherwise leave an orphan node behind in the
    // runs where that stale edge happened to be emitted.
    let referenced: HashSet<&str> = edges
        .iter()
        .flat_map(|edge| [edge.source_id.as_str(), edge.target_id.as_str()])
        .collect();
    nodes.retain(|node| node.local || referenced.contains(node.id.as_str()));
    CallGraph {
        mode: "embedded-hir-mir".to_string(),
        stats: GraphStats {
            node_count: nodes.len(),
            edge_count: edges.len(),
        },
        nodes,
        edges,
        diagnostics: Vec::new(),
    }
}

/// Reconcile the union of HIR- and MIR-derived edges (P2/P10). The two passes
/// can emit the same logical caller -> callee edge, and — after P2
/// devirtualization — a stale edge to an abstract trait item can coexist with
/// the concrete impl edges that supersede it. This collapses both:
///
///   1. Duplicate edges with the same `(source_id, target_id)` are merged,
///      keeping the one whose `call_type` carries the most resolution.
///   2. An edge whose target is an abstract trait item (`Trait::method`, emitted
///      as an external node) is dropped when the same source already has a
///      concrete edge to an impl of that same method (`<Type as Trait>::method`),
///      i.e. the P2 devirtualization result.
fn reconcile_edges(
    edges: Vec<CallGraphEdge>,
    target_names: &HashMap<String, String>,
) -> Vec<CallGraphEdge> {
    let target_name = |edge: &CallGraphEdge| {
        target_names
            .get(&edge.target_id)
            .cloned()
            .unwrap_or_default()
    };
    // Pass 1: collapse (source_id, target_id) duplicates.
    let mut collapsed: IndexMap<(String, String), CallGraphEdge> = IndexMap::new();
    for edge in edges {
        let key = (edge.source_id.clone(), edge.target_id.clone());
        match collapsed.get_mut(&key) {
            Some(existing) => {
                // On a rank tie prefer the HIR edge: it carries the callsite's
                // own line and column, where a MIR edge carries the caller's.
                let is_hir = |edge: &CallGraphEdge| {
                    edge.properties.get("sourceLevel").map(String::as_str) == Some("true")
                };
                let incoming = (call_type_resolution_rank(&edge.call_type), is_hir(&edge));
                let current = (
                    call_type_resolution_rank(&existing.call_type),
                    is_hir(existing),
                );
                if incoming > current {
                    *existing = edge;
                }
            }
            None => {
                collapsed.insert(key, edge);
            }
        }
    }

    // Pass 2: drop abstract trait-item edges superseded by a concrete impl edge
    // to the same method from the same source.
    let concrete: HashSet<(String, String)> = collapsed
        .values()
        .filter(|edge| target_is_concrete_impl(&target_name(edge)))
        .map(|edge| (edge.source_id.clone(), method_suffix(&target_name(edge))))
        .collect();
    collapsed
        .into_values()
        .filter(|edge| {
            if target_is_concrete_impl(&target_name(edge)) {
                return true;
            }
            !concrete.contains(&(edge.source_id.clone(), method_suffix(&target_name(edge))))
        })
        .collect()
}

/// Higher means the call was resolved more precisely; used to pick a winner when
/// collapsing duplicate edges. A type-resolved dispatch kind (dyn or a
/// devirtualized trait call) outranks a plain `static` edge, because the latter
/// may be a MIR string-match fallback guess; within a kind, an exact single
/// target outranks a bounded candidate set, which outranks an unknown target.
fn call_type_resolution_rank(call_type: &str) -> usize {
    let kind_bonus =
        if call_type.starts_with("dyn-dispatch") || call_type.starts_with("trait-static") {
            10
        } else {
            0
        };
    let detail = if call_type.ends_with("-unknown") {
        0
    } else if call_type.ends_with("-bounded") {
        2
    } else if call_type.ends_with("-exact") {
        3
    } else {
        1
    };
    kind_bonus + detail
}

/// A concrete impl target is spelled `<Type as Trait>::method`; an abstract
/// trait-item target is spelled `Trait::method`.
fn target_is_concrete_impl(target_name: &str) -> bool {
    target_name.starts_with('<') && target_name.contains(" as ")
}

fn method_suffix(target_name: &str) -> String {
    last_segment(&canonical_call_symbol(target_name)).to_string()
}

fn build_data_flow(
    functions: &[MirFunction],
    diagnostics: &mut Vec<Diagnostic>,
    debug: bool,
) -> DataFlowEvidence {
    let patterns = built_in_patterns();
    let local_ids = functions
        .iter()
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>();
    let function_map = functions
        .iter()
        .map(|f| (f.id.clone(), f))
        .collect::<HashMap<_, _>>();
    let ctx = FlowContext::new(functions, &patterns, &local_ids, &function_map);
    debug_log(
        debug,
        format_args!(
            "pass=compiler-dataflow-summaries functions={}",
            functions.len()
        ),
    );
    let summaries = infer_summaries(functions, &ctx, debug);
    let mut builder = DataFlowBuilder::new(patterns.clone(), summaries.clone(), &ctx);
    debug_log(
        debug,
        format_args!(
            "pass=compiler-dataflow-materialize functions={}",
            functions.len()
        ),
    );
    builder.materialize(functions, diagnostics, debug);
    debug_log(debug, format_args!("pass=compiler-dataflow-finish"));
    builder.finish()
}

/// Summarizes every function to a fixpoint over the call graph.
///
/// Functions are evaluated callees first, with the min-rank worklist from
/// `rusi_schema::fixpoint`: a call chain of any depth settles in one pass,
/// and only recursion cycles are revisited. Each evaluation records the
/// summaries it read; when a summary grows, exactly those readers are marked
/// dirty again. Summaries only ever grow and draw from finite domains, so no
/// round limit is needed (see [`FunctionSummary::join`] and
/// [`SummaryPass::in_cycle`]).
fn infer_summaries(
    functions: &[MirFunction],
    ctx: &FlowContext<'_>,
    debug: bool,
) -> BTreeMap<String, FunctionSummary> {
    let (summaries, evaluations) = summary_fixpoint(functions, ctx, debug);
    debug_log(
        debug,
        format_args!(
            "pass=compiler-dataflow-summary-fixpoint functions={} evaluations={evaluations}",
            functions.len()
        ),
    );
    summaries
}

/// [`infer_summaries`], returning how many evaluations the fixpoint took.
fn summary_fixpoint(
    functions: &[MirFunction],
    ctx: &FlowContext<'_>,
    debug: bool,
) -> (BTreeMap<String, FunctionSummary>, usize) {
    let position: HashMap<String, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.id.clone(), index))
        .collect();
    let mut summaries = functions
        .iter()
        .map(|f| (f.id.clone(), FunctionSummary::with_context(f)))
        .collect::<BTreeMap<_, _>>();
    let call_order = callee_first_order(functions.len(), |index| {
        summary_dependencies(&functions[index], ctx)
            .into_iter()
            .filter_map(|id| position.get(&id).copied())
            .collect::<Vec<_>>()
    });
    let component_of: HashMap<&str, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.id.as_str(), call_order.component[index]))
        .collect();
    let mut worklist = MinRankWorklist::new(functions.len(), call_order.order.clone());
    let mut dependents = Dependents::new(functions.len());
    while let Some(index) = worklist.pop() {
        let function = &functions[index];
        let reads = TrackedReads::new(&summaries, &position);
        let pass = SummaryPass {
            ctx,
            summaries: &reads,
            component_of: &component_of,
            component: call_order.component[index],
        };
        let next = summarize_function(function, &pass);
        if debug && worklist.evaluations().is_multiple_of(1_000) {
            debug_log(
                debug,
                format_args!(
                    "pass=compiler-dataflow-summary-progress evaluations={} function={} fields={} writes={}",
                    worklist.evaluations(),
                    function.qualified_name,
                    next.field_to_return.len(),
                    next.param_to_field_write.len(),
                ),
            );
        }
        dependents.record(index, reads.into_reads());
        let entry = summaries
            .get_mut(&function.id)
            .expect("every function has a summary");
        if entry.join(next) {
            for reader in dependents.readers(index) {
                worklist.mark_dirty(reader);
            }
        }
    }
    let evaluations = worklist.evaluations();
    (summaries, evaluations)
}

/// The functions whose summaries `function`'s summary may read: the local
/// targets of its calls and the closure bodies nested in it. Only the order
/// of evaluation depends on this; the reads themselves are recorded.
fn summary_dependencies(function: &MirFunction, ctx: &FlowContext<'_>) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    for (block_index, block) in function.blocks.iter().enumerate() {
        for (op_index, op) in block.ops.iter().enumerate() {
            if let MirOp::Call(_) = op {
                dependencies.extend(
                    ctx.call_facts(function, block_index, op_index)
                        .targets
                        .iter()
                        .filter(|target| ctx.local_ids.contains(*target))
                        .cloned(),
                );
            }
        }
    }
    if let Some(nested) = ctx.nested_bodies.get(&function.qualified_name) {
        dependencies.extend(nested.iter().cloned());
    }
    dependencies
}

fn summarize_function(function: &MirFunction, pass: &SummaryPass<'_, '_>) -> FunctionSummary {
    let mut summary = FunctionSummary::with_context(function);
    let mut observed_param_projections = BTreeSet::new();
    let graph = pass.ctx.block_graph(function);
    let mut in_states: Vec<Option<AbstractState>> = vec![None; function.blocks.len()];
    if let Some(entry) = in_states.first_mut() {
        let mut state = AbstractState::default();
        for (idx, name) in function.param_names.iter().enumerate() {
            state.taints.insert(
                PlacePath {
                    base: name.clone(),
                    projections: Vec::new(),
                },
                BTreeSet::from([AbstractOrigin::Param(idx)]),
            );
        }
        *entry = Some(state);
    }
    // Entry states only grow, over places and origins drawn from this body,
    // so the worklist empties without an iteration limit.
    let mut worklist = MinRankWorklist::new(function.blocks.len(), graph.order.clone());
    while let Some(block) = worklist.pop() {
        let Some(state) = in_states[block].clone() else {
            continue;
        };
        let out = transfer_abstract(function, block, state, pass);
        for &successor in &graph.successors[block] {
            let first_visit = in_states[successor].is_none();
            let entry = in_states[successor].get_or_insert_with(AbstractState::default);
            if merge_abstract(entry, &out) || first_visit {
                worklist.mark_dirty(successor);
            }
        }
    }
    for (block_index, (block, state)) in function.blocks.iter().zip(in_states).enumerate() {
        let Some(mut state) = state else {
            continue;
        };
        for (op_index, op) in block.ops.iter().enumerate() {
            match op {
                MirOp::Assign(assign) => {
                    if assign.dest.base == "_0" {
                        for source in &assign.sources {
                            let source = resolve_aliases(&state.aliases, source);
                            if let Some(field) = projected_param_place(function, &source) {
                                summary.field_to_return.insert(field);
                            }
                        }
                    }
                    for source in &assign.sources {
                        let source = resolve_aliases(&state.aliases, source);
                        if let Some(field) = projected_param_place(function, &source) {
                            observed_param_projections.insert(field);
                        }
                    }
                    let dest = resolve_aliases(&state.aliases, &assign.dest);
                    if let Some(field) = projected_param_place(function, &dest) {
                        for source in &assign.sources {
                            for origin in read_abstract(&state, source) {
                                if let AbstractOrigin::Param(index) = origin {
                                    summary
                                        .param_to_field_write
                                        .entry(field.clone())
                                        .or_default()
                                        .insert(index);
                                }
                            }
                        }
                    }
                    apply_assign_abstract(assign, &mut state)
                }
                MirOp::Kill(place) => kill_abstract(&mut state, place),
                MirOp::Call(call) => {
                    for arg in &call.args {
                        if let Some(place) = &arg.place
                            && let Some(field) = projected_param_place(
                                function,
                                &resolve_aliases(&state.aliases, place),
                            )
                        {
                            observed_param_projections.insert(field);
                        }
                    }
                    let facts = pass.ctx.call_facts(function, block_index, op_index);
                    let out = eval_call_abstract(call, facts, &state, pass, &mut summary);
                    apply_source_arguments_abstract(call, facts, &mut state, &mut summary);
                    if call.semantic_tags.iter().any(|tag| tag == "builder")
                        && let Some(receiver_place) =
                            call.args.first().and_then(|arg| arg.place.as_ref())
                    {
                        write_abstract(&mut state, receiver_place, out.clone(), true);
                    }
                    overwrite_abstract(&mut state, &call.dest, out);
                }
            }
        }
        if block.returns {
            let return_place = PlacePath {
                base: "_0".to_string(),
                projections: Vec::new(),
            };
            for origin in read_abstract(&state, &return_place) {
                match origin {
                    AbstractOrigin::Param(idx) => {
                        summary.param_to_return.insert(idx);
                    }
                    AbstractOrigin::Source(category) => {
                        summary.returns_source_categories.insert(category);
                    }
                }
            }
        }
    }
    if !summary.param_to_return.is_empty() && summary.field_to_return.is_empty() {
        summary.field_to_return.extend(observed_param_projections);
    }
    if !summary.field_to_return.is_empty() {
        summary.effect_shapes.insert("field-return".to_string());
    }
    if !summary.param_to_field_write.is_empty() {
        summary
            .effect_shapes
            .insert("param-field-write".to_string());
    }
    if should_lift_observed_sources_to_return(function, &summary) {
        summary
            .returns_source_categories
            .extend(summary.observed_source_categories.iter().cloned());
    }
    lift_async_body_summary(function, pass, &mut summary);
    derive_builder_execution_summary(&mut summary);
    derive_observed_source_to_sink_summary(&mut summary);
    summary
}

fn derive_builder_execution_summary(summary: &mut FunctionSummary) {
    if !summary
        .semantic_tags
        .iter()
        .any(|tag| tag == "builder-exec")
    {
        return;
    }
    let mut configured_parameter_indexes = BTreeSet::new();
    for category in ["process-env", "process-working-directory"] {
        if let Some(indexes) = summary.param_to_sink.get(category) {
            configured_parameter_indexes.extend(indexes.iter().copied());
        }
    }
    if !configured_parameter_indexes.is_empty() {
        summary
            .param_to_sink
            .entry("process-exec".to_string())
            .or_default()
            .extend(configured_parameter_indexes);
    }
}

fn derive_observed_source_to_sink_summary(summary: &mut FunctionSummary) {
    if summary.observed_source_categories.is_empty() || summary.param_to_sink.is_empty() {
        return;
    }
    for sink_category in summary.param_to_sink.keys() {
        summary
            .source_to_sink
            .entry(sink_category.clone())
            .or_default()
            .extend(summary.observed_source_categories.iter().cloned());
    }
}

fn transfer_abstract(
    function: &MirFunction,
    block: usize,
    mut state: AbstractState,
    pass: &SummaryPass<'_, '_>,
) -> AbstractState {
    for (op_index, op) in function.blocks[block].ops.iter().enumerate() {
        match op {
            MirOp::Assign(assign) => apply_assign_abstract(assign, &mut state),
            MirOp::Kill(place) => kill_abstract(&mut state, place),
            MirOp::Call(call) => {
                let facts = pass.ctx.call_facts(function, block, op_index);
                let mut scratch = FunctionSummary::default();
                let mut out = eval_call_abstract(call, facts, &state, pass, &mut scratch);
                apply_source_arguments_abstract(call, facts, &mut state, &mut scratch);
                if call.semantic_tags.iter().any(|tag| tag == "builder")
                    && let Some(receiver_place) =
                        call.args.first().and_then(|arg| arg.place.as_ref())
                {
                    write_abstract(&mut state, receiver_place, out.clone(), true);
                }
                if let Some(slot) = channel_slot_for_call(call, &state.aliases) {
                    if is_channel_send(call)
                        && let Some(place) = call.args.get(1).and_then(|arg| arg.place.as_ref())
                    {
                        let value = read_abstract(&state, place);
                        write_abstract(&mut state, &slot, value, true);
                    }
                    if is_channel_recv(call) {
                        out.extend(read_abstract(&state, &slot));
                    }
                }
                overwrite_abstract(&mut state, &call.dest, out);
            }
        }
    }
    state
}

fn eval_call_abstract(
    call: &MirCall,
    facts: &CallFacts,
    state: &AbstractState,
    pass: &SummaryPass<'_, '_>,
    summary_out: &mut FunctionSummary,
) -> BTreeSet<AbstractOrigin> {
    summary_out.effect_shapes.insert(facts.effect_shape.clone());
    for tag in &call.semantic_tags {
        summary_out.semantic_tags.insert(tag.clone());
    }
    for tag in &facts.model_tags {
        summary_out.semantic_tags.insert(tag.to_string());
    }
    let mut out = BTreeSet::new();
    if let Some(source_category) = &facts.source_category {
        summary_out
            .observed_source_categories
            .insert(source_category.clone());
        out.insert(AbstractOrigin::Source(source_category.clone()));
    }
    if facts.passthrough || facts.semantic_passthrough {
        for arg in &call.args {
            if let Some(place) = &arg.place {
                out.extend(read_abstract(state, place));
            }
        }
    }
    if call.semantic_tags.iter().any(|tag| tag == "builder") {
        if let Some(receiver_place) = call.args.first().and_then(|arg| arg.place.as_ref()) {
            out.extend(read_abstract(state, receiver_place));
        }
        for arg in call.args.iter().skip(1) {
            if let Some(place) = &arg.place {
                out.extend(read_abstract(state, place));
            }
        }
    }
    for (sink_category, args) in &facts.sinks {
        for &arg_index in args {
            if let Some(place) = call.args.get(arg_index).and_then(|a| a.place.as_ref()) {
                for origin in read_abstract(state, place) {
                    match origin {
                        AbstractOrigin::Param(index) => {
                            summary_out
                                .param_to_sink
                                .entry(sink_category.clone())
                                .or_default()
                                .insert(index);
                        }
                        AbstractOrigin::Source(source_category) => {
                            summary_out
                                .source_to_sink
                                .entry(sink_category.clone())
                                .or_default()
                                .insert(source_category);
                        }
                    }
                }
            }
        }
    }
    if let Some(receiver_place) = call.args.first().and_then(|arg| arg.place.as_ref())
        && call.semantic_tags.iter().any(|tag| tag == "builder")
    {
        for arg in call.args.iter().skip(1) {
            if let Some(place) = &arg.place {
                for origin in read_abstract(state, place) {
                    if let AbstractOrigin::Param(index) = origin {
                        summary_out
                            .param_to_field_write
                            .entry(receiver_place.clone())
                            .or_default()
                            .insert(index);
                    }
                }
            }
        }
    }
    for target in &facts.targets {
        if pass.ctx.local_ids.contains(target)
            && let Some(summary) = pass.summaries.get(target)
            && let Some(callee) = pass.ctx.function_map.get(target)
        {
            let widen = pass.in_cycle(target);
            summary_out
                .effect_shapes
                .extend(summary.effect_shapes.iter().cloned());
            summary_out
                .semantic_tags
                .extend(summary.semantic_tags.iter().cloned());
            for (sink_category, source_categories) in &summary.source_to_sink {
                summary_out
                    .source_to_sink
                    .entry(sink_category.clone())
                    .or_default()
                    .extend(source_categories.iter().cloned());
            }
            if should_propagate_candidate_source_returns(call) {
                summary_out
                    .observed_source_categories
                    .extend(summary.observed_source_categories.iter().cloned());
                for category in &summary.returns_source_categories {
                    out.insert(AbstractOrigin::Source(category.clone()));
                }
            }
            for idx in &summary.param_to_return {
                if let Some(place) = call.args.get(*idx).and_then(|a| a.place.as_ref()) {
                    out.extend(read_abstract(state, place));
                }
            }
            for field in &summary.field_to_return {
                if let Some(rebased) = rebase_summary_place(
                    call.args.as_slice(),
                    callee,
                    field,
                    Some(&state.aliases),
                    widen,
                ) {
                    summary_out.field_to_return.insert(rebased);
                }
            }
            for (sink_category, parameter_indexes) in &summary.param_to_sink {
                for parameter_index in parameter_indexes {
                    if let Some(place) = call
                        .args
                        .get(*parameter_index)
                        .and_then(|a| a.place.as_ref())
                    {
                        for origin in read_abstract(state, place) {
                            match origin {
                                AbstractOrigin::Param(index) => {
                                    summary_out
                                        .param_to_sink
                                        .entry(sink_category.clone())
                                        .or_default()
                                        .insert(index);
                                }
                                AbstractOrigin::Source(source_category) => {
                                    summary_out
                                        .source_to_sink
                                        .entry(sink_category.clone())
                                        .or_default()
                                        .insert(source_category);
                                }
                            }
                        }
                    }
                }
            }
            for (field, parameter_indexes) in &summary.param_to_field_write {
                let Some(rebased_field) = rebase_summary_place(
                    call.args.as_slice(),
                    callee,
                    field,
                    Some(&state.aliases),
                    widen,
                ) else {
                    continue;
                };
                for parameter_index in parameter_indexes {
                    if let Some(place) = call
                        .args
                        .get(*parameter_index)
                        .and_then(|a| a.place.as_ref())
                    {
                        for origin in read_abstract(state, place) {
                            if let AbstractOrigin::Param(index) = origin {
                                summary_out
                                    .param_to_field_write
                                    .entry(rebased_field.clone())
                                    .or_default()
                                    .insert(index);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(slot) = channel_slot_for_call(call, &state.aliases) {
        if is_channel_recv(call) {
            out.extend(read_abstract(state, &slot));
            summary_out.field_to_return.insert(slot.clone());
            summary_out.effect_shapes.insert("channel-recv".to_string());
        }
        if is_channel_send(call) {
            if let Some(place) = call.args.get(1).and_then(|arg| arg.place.as_ref()) {
                for origin in read_abstract(state, place) {
                    if let AbstractOrigin::Param(index) = origin {
                        summary_out
                            .param_to_field_write
                            .entry(slot.clone())
                            .or_default()
                            .insert(index);
                    }
                }
            }
            summary_out.effect_shapes.insert("channel-send".to_string());
        }
    }
    out
}

fn apply_source_arguments_abstract(
    call: &MirCall,
    facts: &CallFacts,
    state: &mut AbstractState,
    summary_out: &mut FunctionSummary,
) {
    for (category, arg_indexes) in &facts.source_arguments {
        summary_out
            .observed_source_categories
            .insert(category.clone());
        for &arg_index in arg_indexes {
            if let Some(place) = call.args.get(arg_index).and_then(|arg| arg.place.as_ref()) {
                let place = resolve_aliases(&state.aliases, place);
                write_abstract(
                    state,
                    &place,
                    BTreeSet::from([AbstractOrigin::Source(category.clone())]),
                    true,
                );
            }
        }
    }
}

fn apply_assign_abstract(assign: &AssignAction, state: &mut AbstractState) {
    let mut taint = BTreeSet::new();
    for source in &assign.sources {
        taint.extend(read_abstract(state, source));
    }
    write_abstract(
        state,
        &assign.dest,
        taint,
        assign.dest.is_indirect() || assign.alias.is_some(),
    );
    if let Some(alias) = &assign.alias {
        state.aliases.insert(assign.dest.clone(), alias.clone());
    } else {
        state.aliases.remove(&assign.dest);
    }
    for (field, sources) in &assign.field_sources {
        let mut field_taint = BTreeSet::new();
        for source in sources {
            field_taint.extend(read_abstract(state, source));
        }
        write_abstract(state, field, field_taint, field.is_indirect());
    }
}

fn overwrite_abstract(
    state: &mut AbstractState,
    place: &PlacePath,
    value: BTreeSet<AbstractOrigin>,
) {
    state
        .taints
        .retain(|existing, _| !same_or_descendant(existing, place));
    state.taints.insert(place.clone(), value);
}

fn weak_update_abstract(
    state: &mut AbstractState,
    place: &PlacePath,
    value: BTreeSet<AbstractOrigin>,
) {
    let entry = state.taints.entry(place.clone()).or_default();
    entry.extend(value);
}

fn write_abstract(
    state: &mut AbstractState,
    place: &PlacePath,
    value: BTreeSet<AbstractOrigin>,
    weak: bool,
) {
    if weak {
        weak_update_abstract(state, place, value);
    } else {
        overwrite_abstract(state, place, value);
    }
}

fn kill_abstract(state: &mut AbstractState, place: &PlacePath) {
    state
        .taints
        .retain(|existing, _| !same_or_descendant(existing, place));
    state
        .aliases
        .retain(|existing, _| !same_or_descendant(existing, place));
}

fn read_abstract(state: &AbstractState, place: &PlacePath) -> BTreeSet<AbstractOrigin> {
    let resolved = resolve_aliases(&state.aliases, place);
    let mut origins = BTreeSet::new();
    if let Some(values) = state.taints.get(&resolved) {
        origins.extend(values.clone());
    }
    for (existing, values) in &state.taints {
        if same_or_descendant(&resolved, existing) || same_or_descendant(existing, &resolved) {
            origins.extend(values.clone());
        }
    }
    origins
}

fn merge_abstract(target: &mut AbstractState, incoming: &AbstractState) -> bool {
    let mut changed = false;
    for (place, values) in &incoming.taints {
        let entry = target.taints.entry(place.clone()).or_default();
        let before = entry.len();
        entry.extend(values.clone());
        if entry.len() != before {
            changed = true;
        }
    }
    for (place, alias) in &incoming.aliases {
        if !target.aliases.contains_key(place) {
            target.aliases.insert(place.clone(), alias.clone());
            changed = true;
        }
    }
    changed
}

struct DataFlowBuilder<'a> {
    patterns: DataFlowPatternSet,
    summaries: BTreeMap<String, FunctionSummary>,
    ctx: &'a FlowContext<'a>,
    nodes: IndexMap<String, DataFlowNode>,
    edges: IndexMap<String, DataFlowEdge>,
    slices: IndexMap<String, DataFlowSlice>,
    /// Whether blocks are transferred to emit (see
    /// [`DataFlowBuilder::materialize_function`]). While a function's
    /// fixpoint is computed, transfers record no node, edge, slice or
    /// diagnostic.
    emitting: bool,
}

impl<'a> DataFlowBuilder<'a> {
    fn new(
        patterns: DataFlowPatternSet,
        summaries: BTreeMap<String, FunctionSummary>,
        ctx: &'a FlowContext<'a>,
    ) -> Self {
        Self {
            patterns,
            summaries,
            ctx,
            nodes: IndexMap::new(),
            edges: IndexMap::new(),
            slices: IndexMap::new(),
            emitting: true,
        }
    }

    fn materialize(
        &mut self,
        functions: &[MirFunction],
        diagnostics: &mut Vec<Diagnostic>,
        debug: bool,
    ) {
        for function in functions {
            debug_log(
                debug,
                format_args!(
                    "pass=compiler-dataflow-materialize-function file={} function={}",
                    function.file_path, function.qualified_name
                ),
            );
            self.materialize_function(function, diagnostics);
        }
    }

    /// Brings a function's block entry states to a fixpoint, then emits
    /// what its sinks witness from the fixpoint alone, the way
    /// [`summarize_function`] collects a summary. The worklist only computes
    /// states; one last pass over the reachable blocks, each from its
    /// settled entry state, records every node, edge, slice and diagnostic.
    /// Each call is reported once, from the state the fixpoint holds there,
    /// whatever order or number of visits the worklist took.
    fn materialize_function(&mut self, function: &MirFunction, diagnostics: &mut Vec<Diagnostic>) {
        let graph = self.ctx.block_graph(function);
        let mut in_states: Vec<Option<ConcreteState>> = vec![None; function.blocks.len()];
        if let Some(entry) = in_states.first_mut() {
            *entry = Some(ConcreteState::default());
        }
        self.emitting = false;
        let mut worklist = MinRankWorklist::new(function.blocks.len(), graph.order.clone());
        while let Some(block) = worklist.pop() {
            let Some(state) = in_states[block].clone() else {
                continue;
            };
            let out = self.transfer_concrete(function, block, state, diagnostics);
            for &successor in &graph.successors[block] {
                let first_visit = in_states[successor].is_none();
                let entry = in_states[successor].get_or_insert_with(ConcreteState::default);
                if merge_concrete(entry, &out) || first_visit {
                    worklist.mark_dirty(successor);
                }
            }
        }
        self.emitting = true;
        for &block in &graph.order {
            if let Some(state) = in_states[block].take() {
                self.transfer_concrete(function, block, state, diagnostics);
            }
        }
    }

    fn transfer_concrete(
        &mut self,
        function: &MirFunction,
        block: usize,
        mut state: ConcreteState,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> ConcreteState {
        for (op_index, op) in function.blocks[block].ops.iter().enumerate() {
            match op {
                MirOp::Assign(assign) => apply_assign_concrete(function, assign, &mut state),
                MirOp::Kill(place) => kill_concrete(&mut state, place),
                MirOp::Call(call) => {
                    let ctx = self.ctx;
                    let facts = ctx.call_facts(function, block, op_index);
                    let direct_source_path = facts.source_category.as_ref().map(|category| {
                        self.new_source_path(
                            function,
                            &call.callee_display,
                            category,
                            call.dest_type.clone(),
                            None,
                        )
                    });
                    self.apply_source_arguments(function, call, facts, &mut state);
                    for (sink_category, args) in &facts.sinks {
                        for &arg_index in args {
                            if let Some(place) =
                                call.args.get(arg_index).and_then(|a| a.place.as_ref())
                            {
                                let taint = read_concrete(&state, place);
                                self.emit_sink(
                                    function,
                                    &taint,
                                    &call.callee_display,
                                    sink_category,
                                    arg_index,
                                    call.args.get(arg_index).and_then(|a| a.type_name.clone()),
                                );
                            }
                        }
                    }
                    let mut paths = direct_source_path.into_iter().collect::<Vec<_>>();
                    if facts.passthrough || facts.semantic_passthrough {
                        for arg in &call.args {
                            if let Some(place) = &arg.place {
                                paths.extend(read_concrete(&state, place).paths);
                            }
                        }
                    }
                    if call.semantic_tags.iter().any(|tag| tag == "builder") {
                        if let Some(receiver_place) =
                            call.args.first().and_then(|arg| arg.place.as_ref())
                        {
                            paths.extend(read_concrete(&state, receiver_place).paths);
                        }
                        for arg in call.args.iter().skip(1) {
                            if let Some(place) = &arg.place {
                                paths.extend(read_concrete(&state, place).paths);
                            }
                        }
                        if let Some(receiver_place) =
                            call.args.first().and_then(|arg| arg.place.as_ref())
                        {
                            let mut builder_taint = ConcreteTaint {
                                paths: paths.clone(),
                            };
                            builder_taint
                                .paths
                                .sort_by(|left, right| left.origin_key.cmp(&right.origin_key));
                            builder_taint
                                .paths
                                .dedup_by(|left, right| left.origin_key == right.origin_key);
                            write_concrete(&mut state, receiver_place, builder_taint, true);
                        }
                    }
                    if let Some(slot) = channel_slot_for_call(call, &state.aliases) {
                        if is_channel_send(call)
                            && let Some(place) = call.args.get(1).and_then(|arg| arg.place.as_ref())
                        {
                            let taint = read_concrete(&state, place);
                            write_concrete(&mut state, &slot, taint, true);
                        }
                        if is_channel_recv(call) {
                            paths.extend(read_concrete(&state, &slot).paths);
                        }
                    }
                    let mut reached_local_target = false;
                    for target in &facts.targets {
                        if ctx.local_ids.contains(target)
                            && let Some(summary) = self.summaries.get(target).cloned()
                        {
                            reached_local_target = true;
                            let callee = ctx.function_map.get(target).copied();
                            let callee_name = ctx
                                .function_map
                                .get(target)
                                .map(|f| f.qualified_name.clone())
                                .unwrap_or_else(|| call.callee_display.clone());
                            if should_propagate_candidate_source_returns(call) {
                                for category in summary.returns_source_categories {
                                    paths.push(self.new_source_path(
                                        function,
                                        &callee_name,
                                        &category,
                                        call.dest_type.clone(),
                                        None,
                                    ));
                                }
                            }
                            for (sink_category, source_categories) in summary.source_to_sink {
                                for source_category in source_categories {
                                    let path = self.new_source_path(
                                        function,
                                        &callee_name,
                                        &source_category,
                                        call.dest_type.clone(),
                                        None,
                                    );
                                    self.emit_sink(
                                        function,
                                        &ConcreteTaint { paths: vec![path] },
                                        &callee_name,
                                        &sink_category,
                                        0,
                                        None,
                                    );
                                }
                            }
                            for idx in summary.param_to_return {
                                if let Some(place) =
                                    call.args.get(idx).and_then(|a| a.place.as_ref())
                                {
                                    let arg_taint = read_concrete(&state, place);
                                    for mut path in arg_taint.paths {
                                        let node_id = stable_id(
                                            "df-node",
                                            &[
                                                &function.id,
                                                &callee_name,
                                                &format!("param-to-return-{}", idx),
                                                &function.position.line.to_string(),
                                                &function.position.column.to_string(),
                                            ],
                                        );
                                        let call_node = DataFlowNode {
                                            id: node_id.clone(),
                                            kind: "call_return".to_string(),
                                            name: callee_name.clone(),
                                            package_path: function.package_path.clone(),
                                            purl: String::new(),
                                            function: function.qualified_name.clone(),
                                            position: function.position.clone(),
                                            source: false,
                                            sink: false,
                                            category: String::new(),
                                            parameter_index: Some(idx),
                                            type_name: None,
                                            properties: IndexMap::new(),
                                        };
                                        if let Some(last_step) = path.steps.last() {
                                            let edge_id = stable_id(
                                                "df-edge",
                                                &[&last_step.node.id, &node_id, "call_return"],
                                            );
                                            let edge = DataFlowEdge {
                                                id: edge_id,
                                                source_id: last_step.node.id.clone(),
                                                target_id: node_id.clone(),
                                                kind: "call_return".to_string(),
                                                properties: IndexMap::new(),
                                            };
                                            path.steps.push(TaintStep {
                                                node: call_node,
                                                edge: Some(edge),
                                            });
                                        }
                                        paths.push(path);
                                    }
                                }
                            }
                            for field in &summary.field_to_return {
                                if let Some(rebased) = callee.and_then(|callee| {
                                    rebase_summary_place(
                                        call.args.as_slice(),
                                        callee,
                                        field,
                                        Some(&state.aliases),
                                        false,
                                    )
                                }) {
                                    paths.extend(read_concrete(&state, &rebased).paths);
                                }
                            }
                            for (sink_category, parameter_indexes) in summary.param_to_sink {
                                for parameter_index in parameter_indexes {
                                    if let Some(place) = call
                                        .args
                                        .get(parameter_index)
                                        .and_then(|a| a.place.as_ref())
                                    {
                                        let taint = read_concrete(&state, place);
                                        self.emit_sink(
                                            function,
                                            &taint,
                                            &callee_name,
                                            &sink_category,
                                            parameter_index,
                                            call.args
                                                .get(parameter_index)
                                                .and_then(|a| a.type_name.clone()),
                                        );
                                    }
                                }
                            }
                            for (field, parameter_indexes) in summary.param_to_field_write {
                                let Some(rebased_field) = callee.and_then(|callee| {
                                    rebase_summary_place(
                                        call.args.as_slice(),
                                        callee,
                                        &field,
                                        Some(&state.aliases),
                                        false,
                                    )
                                }) else {
                                    continue;
                                };
                                let mut field_paths = Vec::new();
                                for parameter_index in parameter_indexes {
                                    if let Some(place) = call
                                        .args
                                        .get(parameter_index)
                                        .and_then(|a| a.place.as_ref())
                                    {
                                        field_paths.extend(read_concrete(&state, place).paths);
                                    }
                                }
                                if !field_paths.is_empty() {
                                    field_paths.sort_by(|left, right| {
                                        left.origin_key.cmp(&right.origin_key)
                                    });
                                    field_paths.dedup_by(|left, right| {
                                        left.origin_key == right.origin_key
                                    });
                                    write_concrete(
                                        &mut state,
                                        &rebased_field,
                                        ConcreteTaint { paths: field_paths },
                                        rebased_field.is_indirect(),
                                    );
                                }
                            }
                        }
                    }
                    // A call with no resolved target is only unresolved for
                    // data flow when no candidate stood in for one either.
                    if self.emitting
                        && call.target_ids.is_empty()
                        && !reached_local_target
                        && facts.source_category.is_none()
                        && !facts.passthrough
                        && facts.model_tags.is_empty()
                        && should_emit_unresolved_dataflow_diagnostic(&call.callee_display)
                    {
                        diagnostics.push(Diagnostic {
                            kind: "resolution".to_string(),
                            message: format!("unresolved embedded compiler call during data-flow materialization: {}", call.callee_display),
                            package_path: Some(function.package_path.clone()),
                            file_path: Some(function.file_path.clone()),
                            position: Some(function.position.clone()),
                        });
                    }
                    overwrite_concrete(&mut state, &call.dest, ConcreteTaint { paths });
                }
            }
        }
        state
    }

    fn new_source_path(
        &mut self,
        function: &MirFunction,
        name: &str,
        category: &str,
        type_name: Option<String>,
        parameter_index: Option<usize>,
    ) -> TaintPath {
        let node_id = stable_id(
            "df-node",
            &[
                &function.id,
                name,
                category,
                type_name.as_deref().unwrap_or("_"),
            ],
        );
        let build = || {
            let mut properties = IndexMap::from([
                (
                    "specializationKey".to_string(),
                    specialization_key_for_function(function),
                ),
                (
                    "receiverType".to_string(),
                    receiver_type_for_function(function).unwrap_or_default(),
                ),
                ("analysisBackend".to_string(), "embedded-mir".to_string()),
            ]);
            add_model_properties(&mut properties, name);
            DataFlowNode {
                id: node_id.clone(),
                kind: "source".to_string(),
                name: name.to_string(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                function: function.qualified_name.clone(),
                position: function.position.clone(),
                source: true,
                sink: false,
                category: category.to_string(),
                parameter_index,
                type_name: type_name.clone(),
                properties,
            }
        };
        let node = match self.nodes.get(&node_id) {
            Some(node) => node.clone(),
            None if self.emitting => self
                .nodes
                .entry(node_id.clone())
                .or_insert_with(build)
                .clone(),
            None => build(),
        };
        TaintPath {
            origin_key: format!("{}:{}:{}", function.id, name, category),
            category: category.to_string(),
            steps: vec![TaintStep { node, edge: None }],
        }
    }

    fn apply_source_arguments(
        &mut self,
        function: &MirFunction,
        call: &MirCall,
        facts: &CallFacts,
        state: &mut ConcreteState,
    ) {
        for (category, arg_indexes) in &facts.source_arguments {
            for &arg_index in arg_indexes {
                if let Some(place) = call.args.get(arg_index).and_then(|arg| arg.place.as_ref()) {
                    let path = self.new_source_path(
                        function,
                        &call.callee_display,
                        category,
                        call.args
                            .get(arg_index)
                            .and_then(|arg| arg.type_name.clone()),
                        Some(arg_index),
                    );
                    let place = resolve_aliases(&state.aliases, place);
                    write_concrete(state, &place, ConcreteTaint { paths: vec![path] }, true);
                }
            }
        }
    }

    fn emit_sink(
        &mut self,
        function: &MirFunction,
        taint: &ConcreteTaint,
        sink_name: &str,
        sink_category: &str,
        parameter_index: usize,
        sink_type: Option<String>,
    ) {
        if taint.paths.is_empty() || !self.emitting {
            return;
        }
        let sink_node_id = stable_id(
            "df-node",
            &[
                &function.id,
                sink_name,
                sink_category,
                &parameter_index.to_string(),
                sink_type.as_deref().unwrap_or("_"),
            ],
        );
        let mut properties = IndexMap::from([
            (
                "specializationKey".to_string(),
                specialization_key_for_function(function),
            ),
            (
                "dispatchConfidence".to_string(),
                taint_dispatch_confidence(taint),
            ),
            ("analysisBackend".to_string(), "embedded-mir".to_string()),
        ]);
        add_model_properties(&mut properties, sink_name);
        let sink_node = DataFlowNode {
            id: sink_node_id.clone(),
            kind: "sink".to_string(),
            name: sink_name.to_string(),
            package_path: function.package_path.clone(),
            purl: String::new(),
            function: function.qualified_name.clone(),
            position: function.position.clone(),
            source: false,
            sink: true,
            category: sink_category.to_string(),
            parameter_index: Some(parameter_index),
            type_name: sink_type.clone(),
            properties,
        };

        for path in &taint.paths {
            let mut final_path = path.clone();
            if let Some(last_step) = final_path.steps.last() {
                let edge_id = stable_id(
                    "df-edge",
                    &[&last_step.node.id, &sink_node_id, sink_category],
                );
                let mut edge_properties = IndexMap::new();
                edge_properties.insert(
                    "dispatchConfidence".to_string(),
                    taint_dispatch_confidence(taint),
                );
                let edge = DataFlowEdge {
                    id: edge_id.clone(),
                    source_id: last_step.node.id.clone(),
                    target_id: sink_node_id.clone(),
                    kind: "taint".to_string(),
                    properties: edge_properties,
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

            // Register all nodes and edges in the final path
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
            let mut slice_properties = IndexMap::new();
            slice_properties.insert(
                "specializationKey".to_string(),
                specialization_key_for_function(function),
            );
            slice_properties.insert(
                "dispatchConfidence".to_string(),
                taint_dispatch_confidence(taint),
            );
            slice_properties.insert("analysisBackend".to_string(), "embedded-mir".to_string());
            add_model_properties(&mut slice_properties, sink_name);
            if modeled_native_boundary(sink_name)
                || modeled_native_boundary(&final_path.steps[0].node.name)
            {
                slice_properties.insert("nativeBoundary".to_string(), "true".to_string());
            }

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
                    sink_function: function.qualified_name.clone(),
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
                    sink_parameter_index: Some(parameter_index),
                    source_type_name: first_node.type_name.clone(),
                    sink_type_name: sink_type.clone(),
                    rule_name: format!("{}-to-{}", final_path.category, sink_category),
                    description: format!(
                        "{} data can flow from {} to {} parameter {}",
                        final_path.category, first_node.name, sink_name, parameter_index
                    ),
                    properties: slice_properties,
                });
        }
    }

    fn finish(self) -> DataFlowEvidence {
        let mut summaries = self
            .summaries
            .into_iter()
            .map(|(function_id, summary)| {
                let function = self
                    .ctx
                    .function_map
                    .get(&function_id)
                    .expect("function exists");
                DataFlowMethodSummary {
                    function_id,
                    function: function.qualified_name.clone(),
                    package_path: function.package_path.clone(),
                    purl: String::new(),
                    parameter_names: function.param_names.clone(),
                    parameter_types: function.param_types.clone(),
                    return_type: function.return_type.clone(),
                    param_to_return: summary.param_to_return.into_iter().collect(),
                    param_to_sink: summary
                        .param_to_sink
                        .into_iter()
                        .map(|(category, indexes)| (category, indexes.into_iter().collect()))
                        .collect(),
                    source_returns: summary.returns_source_categories.into_iter().collect(),
                    properties: IndexMap::from([
                        (
                            "specializationKey".to_string(),
                            if summary.specialization_key.is_empty() {
                                specialization_key_for_function(function)
                            } else {
                                summary.specialization_key.clone()
                            },
                        ),
                        (
                            "receiverType".to_string(),
                            summary.receiver_type.clone().unwrap_or_default(),
                        ),
                        (
                            "effectShapes".to_string(),
                            summary
                                .effect_shapes
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        (
                            "observedSources".to_string(),
                            summary
                                .observed_source_categories
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        (
                            "semanticTags".to_string(),
                            summary
                                .semantic_tags
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        (
                            "fieldToReturn".to_string(),
                            summary
                                .field_to_return
                                .iter()
                                .map(PlacePath::render)
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        (
                            "paramToFieldWrite".to_string(),
                            summary
                                .param_to_field_write
                                .iter()
                                .map(|(field, indexes)| {
                                    format!(
                                        "{}:{}",
                                        field.render(),
                                        indexes
                                            .iter()
                                            .map(|index| index.to_string())
                                            .collect::<Vec<_>>()
                                            .join("|")
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        (
                            "sourceToSink".to_string(),
                            summary
                                .source_to_sink
                                .iter()
                                .map(|(sink_category, source_categories)| {
                                    format!(
                                        "{}:{}",
                                        sink_category,
                                        source_categories
                                            .iter()
                                            .cloned()
                                            .collect::<Vec<_>>()
                                            .join("|")
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                    ]),
                }
            })
            .collect::<Vec<_>>();
        summaries.sort_by(|l, r| l.function_id.cmp(&r.function_id));
        let nodes = self.nodes.into_values().collect::<Vec<_>>();
        let edges = self.edges.into_values().collect::<Vec<_>>();
        let slices = self.slices.into_values().collect::<Vec<_>>();
        let source_count = nodes.iter().filter(|node| node.source).count();
        let sink_count = nodes.iter().filter(|node| node.sink).count();
        let slice_count = slices.len();
        let node_count = nodes.len();
        let edge_count = edges.len();
        let summary_count = summaries.len();
        DataFlowEvidence {
            mode: "embedded-mir".to_string(),
            patterns: self.patterns,
            nodes,
            edges,
            slices,
            summaries,
            diagnostics: Vec::new(),
            stats: DataFlowStats {
                source_count,
                sink_count,
                slice_count,
                node_count,
                edge_count,
                summary_count,
            },
        }
    }
}

fn apply_assign_concrete(function: &MirFunction, assign: &AssignAction, state: &mut ConcreteState) {
    let mut taint = ConcreteTaint::default();
    for source in &assign.sources {
        taint.paths.extend(read_concrete(state, source).paths);
    }
    if !taint.paths.is_empty() {
        let node_id = stable_id(
            "df-node",
            &[
                &function.id,
                &assign.dest.render(),
                "local",
                &function.position.line.to_string(),
                &function.position.column.to_string(),
            ],
        );
        let target_node = DataFlowNode {
            id: node_id.clone(),
            kind: "local".to_string(),
            name: assign.dest.render(),
            package_path: function.package_path.clone(),
            purl: String::new(),
            function: function.qualified_name.clone(),
            position: function.position.clone(),
            source: false,
            sink: false,
            category: String::new(),
            parameter_index: None,
            type_name: None,
            properties: IndexMap::new(),
        };
        for path in &mut taint.paths {
            if let Some(last_step) = path.steps.last() {
                let edge_id = stable_id("df-edge", &[&last_step.node.id, &node_id, "assign"]);
                let edge = DataFlowEdge {
                    id: edge_id,
                    source_id: last_step.node.id.clone(),
                    target_id: node_id.clone(),
                    kind: "assign".to_string(),
                    properties: IndexMap::new(),
                };
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
    }
    write_concrete(
        state,
        &assign.dest,
        taint,
        assign.dest.is_indirect() || assign.alias.is_some(),
    );
    if let Some(alias) = &assign.alias {
        state.aliases.insert(assign.dest.clone(), alias.clone());
    } else {
        state.aliases.remove(&assign.dest);
    }
    for (field, sources) in &assign.field_sources {
        let mut field_taint = ConcreteTaint::default();
        for source in sources {
            field_taint.paths.extend(read_concrete(state, source).paths);
        }
        if !field_taint.paths.is_empty() {
            let node_id = stable_id(
                "df-node",
                &[
                    &function.id,
                    &field.render(),
                    "field-assign",
                    &function.position.line.to_string(),
                    &function.position.column.to_string(),
                ],
            );
            let target_node = DataFlowNode {
                id: node_id.clone(),
                kind: "local".to_string(),
                name: field.render(),
                package_path: function.package_path.clone(),
                purl: String::new(),
                function: function.qualified_name.clone(),
                position: function.position.clone(),
                source: false,
                sink: false,
                category: String::new(),
                parameter_index: None,
                type_name: None,
                properties: IndexMap::new(),
            };
            for path in &mut field_taint.paths {
                if let Some(last_step) = path.steps.last() {
                    let edge_id = stable_id("df-edge", &[&last_step.node.id, &node_id, "assign"]);
                    let edge = DataFlowEdge {
                        id: edge_id,
                        source_id: last_step.node.id.clone(),
                        target_id: node_id.clone(),
                        kind: "assign".to_string(),
                        properties: IndexMap::new(),
                    };
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
        }
        write_concrete(state, field, field_taint, field.is_indirect());
    }
}

fn overwrite_concrete(state: &mut ConcreteState, place: &PlacePath, value: ConcreteTaint) {
    state
        .taints
        .retain(|existing, _| !same_or_descendant(existing, place));
    state.taints.insert(place.clone(), value);
}

fn weak_update_concrete(state: &mut ConcreteState, place: &PlacePath, value: ConcreteTaint) {
    let entry = state.taints.entry(place.clone()).or_default();
    for path in value.paths {
        if !entry
            .paths
            .iter()
            .any(|existing| existing.origin_key == path.origin_key)
        {
            entry.paths.push(path);
        }
    }
}

fn write_concrete(state: &mut ConcreteState, place: &PlacePath, value: ConcreteTaint, weak: bool) {
    if weak {
        weak_update_concrete(state, place, value);
    } else {
        overwrite_concrete(state, place, value);
    }
}

fn receiver_type_for_function(function: &MirFunction) -> Option<String> {
    function
        .param_types
        .first()
        .filter(|first| first.contains("Self") || first.contains("&") || first.contains("::"))
        .cloned()
}

fn specialization_key_for_function(function: &MirFunction) -> String {
    specialization_key_from_parts(
        receiver_type_for_function(function).as_deref(),
        &Vec::new(),
        std::slice::from_ref(&function.qualified_name),
    )
}

fn lift_async_body_summary(
    function: &MirFunction,
    pass: &SummaryPass<'_, '_>,
    summary_out: &mut FunctionSummary,
) {
    let mut lifted_descendant_sink = false;
    let nested = pass
        .ctx
        .nested_bodies
        .get(&function.qualified_name)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for function_id in nested {
        let Some(child_summary) = pass.summaries.get(function_id) else {
            continue;
        };
        summary_out
            .returns_source_categories
            .extend(child_summary.returns_source_categories.iter().cloned());
        summary_out
            .observed_source_categories
            .extend(child_summary.observed_source_categories.iter().cloned());
        summary_out
            .effect_shapes
            .extend(child_summary.effect_shapes.iter().cloned());
        summary_out
            .semantic_tags
            .extend(child_summary.semantic_tags.iter().cloned());
        for (sink_category, source_categories) in &child_summary.source_to_sink {
            summary_out
                .source_to_sink
                .entry(sink_category.clone())
                .or_default()
                .extend(source_categories.iter().cloned());
            lifted_descendant_sink = true;
        }
        for index in &child_summary.param_to_return {
            if *index > 0 {
                summary_out.param_to_return.insert(index - 1);
            }
        }
        for (category, indexes) in &child_summary.param_to_sink {
            for index in indexes {
                if *index > 0 {
                    summary_out
                        .param_to_sink
                        .entry(category.clone())
                        .or_default()
                        .insert(index - 1);
                    lifted_descendant_sink = true;
                }
            }
        }
        for (field, indexes) in &child_summary.param_to_field_write {
            for index in indexes {
                if *index > 0 {
                    summary_out
                        .param_to_field_write
                        .entry(field.clone())
                        .or_default()
                        .insert(index - 1);
                }
            }
        }
    }
    if should_lift_observed_sources_to_return(function, summary_out) {
        summary_out
            .returns_source_categories
            .extend(summary_out.observed_source_categories.iter().cloned());
    }
    if lifted_descendant_sink {
        summary_out
            .effect_shapes
            .insert("async-descendant-sink".to_string());
    }
}

fn should_lift_observed_sources_to_return(
    function: &MirFunction,
    summary: &FunctionSummary,
) -> bool {
    !summary.observed_source_categories.is_empty()
        && (is_async_or_future_function(function)
            || summary.effect_shapes.contains("source-return")
            || summary
                .effect_shapes
                .iter()
                .any(|shape| shape.contains("source-return")))
}

fn is_async_or_future_function(function: &MirFunction) -> bool {
    function.return_type.contains("Future")
        || function.return_type.contains("Coroutine")
        || function.return_type.contains("Poll")
        || function.qualified_name.contains("{async fn body of")
        || receiver_type_for_function(function)
            .as_deref()
            .is_some_and(|receiver| {
                receiver.contains("{async fn body of")
                    || receiver.contains("Future")
                    || receiver.contains("Coroutine")
            })
}

fn channel_slot_for_call(
    call: &MirCall,
    aliases: &HashMap<PlacePath, PlacePath>,
) -> Option<PlacePath> {
    let receiver = call.args.first().and_then(|arg| arg.place.as_ref())?;
    let resolved = resolve_aliases(aliases, receiver);
    let parent = resolved.parent()?;
    Some(parent.synthetic_field("__channel"))
}

fn is_channel_send(call: &MirCall) -> bool {
    call.semantic_tags.iter().any(|tag| tag == "channel")
        && call_matches_last_segment(call, &["send"])
}

fn is_channel_recv(call: &MirCall) -> bool {
    call.semantic_tags.iter().any(|tag| tag == "channel")
        && call_matches_last_segment(call, &["recv", "try_recv", "recv_timeout"])
}

fn call_matches_last_segment(call: &MirCall, candidates: &[&str]) -> bool {
    std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
        .map(normalize_symbol)
        .any(|symbol| {
            candidates
                .iter()
                .any(|candidate| last_segment(&symbol) == *candidate)
        })
}

fn projected_param_place(function: &MirFunction, place: &PlacePath) -> Option<PlacePath> {
    if place.projections.is_empty() {
        return None;
    }
    function
        .param_names
        .iter()
        .any(|name| name == &place.base)
        .then(|| place.clone())
}

/// Maps a place in `callee`'s summary, rooted at one of its parameters, onto
/// the argument the call passes for that parameter.
///
/// With `widen`, the result stops at the argument itself instead of
/// descending into the callee's projections. Callers widen for a callee in
/// their own recursion cycle: the argument places are drawn from the caller's
/// body, so the places a cycle can accumulate stay finite, where appending
/// the callee's projections on every trip around the cycle would not. The
/// argument covers every place under it, so widening only coarsens.
fn rebase_summary_place(
    args: &[CallArg],
    callee: &MirFunction,
    place: &PlacePath,
    aliases: Option<&HashMap<PlacePath, PlacePath>>,
    widen: bool,
) -> Option<PlacePath> {
    let parameter_index = callee
        .param_names
        .iter()
        .position(|name| name == &place.base)?;
    let actual = args.get(parameter_index)?.place.as_ref()?;
    let actual = aliases
        .map(|aliases| resolve_aliases(aliases, actual))
        .unwrap_or_else(|| actual.clone());
    let mut rebased = actual;
    if !widen {
        rebased
            .projections
            .extend(place.projections.iter().cloned());
    }
    Some(rebased)
}

/// The local functions a call may reach, for the data-flow passes: its
/// resolved targets plus, for a trait or unresolved call, every impl method
/// its name can denote. The set is not truncated; an ambiguous call reaches
/// all of its candidates, in id order.
fn candidate_dataflow_targets(call: &MirCall, ctx: &FlowContext<'_>) -> Vec<String> {
    let mut targets = BTreeSet::new();
    for target in &call.target_ids {
        if ctx.local_ids.contains(target) {
            targets.insert(target.clone());
        }
    }
    for symbol in std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
    {
        let normalized = canonical_call_symbol(symbol);
        if let Some((trait_name, method_name)) = impl_trait_method_parts(symbol) {
            targets.extend(
                ctx.trait_method_impls(&trait_name, &method_name)
                    .iter()
                    .cloned(),
            );
        } else if let Some((trait_name, method_name)) = trait_method_parts(&normalized) {
            targets.extend(
                ctx.trait_method_impls(trait_name, method_name)
                    .iter()
                    .cloned(),
            );
        } else {
            let method_name = last_segment(&normalized);
            if should_expand_bare_method_candidate(call, method_name) {
                targets.extend(ctx.method_impls(method_name).iter().cloned());
            }
        }
    }
    targets.into_iter().collect()
}

/// Splits `<Type as Trait>::method` into the trait's last path segment and
/// the method name.
///
/// The `as` is the one at the top nesting level of the leading angle
/// brackets, read with its surrounding spaces, so neither a generic argument
/// (`<Vec<T> as Trait>`), a qualified self type (`<<T as A>::Out as B>`), nor
/// a name that merely contains the letters (`Database`, `Class`) is taken for
/// it.
fn impl_trait_method_parts(symbol: &str) -> Option<(String, String)> {
    let inner = symbol.trim().strip_prefix('<')?;
    let mut depth = 0usize;
    let mut previous = '\0';
    let mut split = None;
    let mut close = None;
    for (index, ch) in inner.char_indices() {
        match ch {
            '<' => depth += 1,
            // The arrow of a function type (`<fn() -> T as Trait>`).
            '>' if previous == '-' => {}
            '>' if depth == 0 => {
                close = Some(index);
                break;
            }
            '>' => depth -= 1,
            ' ' if depth == 0 && inner[index..].starts_with(" as ") => split = Some(index),
            _ => {}
        }
        previous = ch;
    }
    let (split, close) = (split?, close?);
    let trait_path = inner[split + " as ".len()..close].trim();
    let trait_name = last_segment(&strip_generic_arguments(trait_path)).to_string();
    let method = normalize_symbol(inner[close + 1..].strip_prefix("::")?);
    if trait_name.is_empty() || method.is_empty() {
        return None;
    }
    Some((trait_name, method))
}

fn should_expand_bare_method_candidate(call: &MirCall, method_name: &str) -> bool {
    let trait_or_dyn = call.call_type == "dyn-dispatch"
        || call.call_type == "trait-static"
        || call.semantic_tags.iter().any(|tag| tag == "trait-dispatch");
    if method_name.is_empty() || (call.target_ids.len() == 1 && !trait_or_dyn) {
        return false;
    }
    if matches!(
        method_name,
        "as_ref"
            | "clone"
            | "default"
            | "deref"
            | "drop"
            | "fmt"
            | "from"
            | "into"
            | "new"
            | "poll"
            | "poll_next"
            | "ready"
            | "size_hint"
    ) {
        return false;
    }
    trait_or_dyn || call.call_type == "unresolved"
}

fn trait_method_parts(symbol: &str) -> Option<(&str, &str)> {
    let (owner, method) = symbol.rsplit_once("::")?;
    if owner.is_empty() || method.is_empty() {
        return None;
    }
    if owner.starts_with('<') {
        return None;
    }
    Some((last_segment(owner), method))
}

fn semantic_passthrough(call: &MirCall) -> bool {
    call.semantic_tags
        .iter()
        .any(|tag| tag == "passthrough" || tag == "combinator" || tag == "callable")
}

fn should_propagate_candidate_source_returns(call: &MirCall) -> bool {
    !(call.call_type == "closure" && call.target_ids.len() > 1)
}

fn should_emit_unresolved_dataflow_diagnostic(symbol: &str) -> bool {
    let normalized = normalize_symbol(symbol);
    if normalized.is_empty() || normalized == "<unknown-call>" {
        return false;
    }
    if normalized.contains("tracing::")
        || normalized.contains("tracing_core::")
        || normalized.starts_with("core::panicking::")
        || normalized.starts_with("std::fmt::")
        || normalized.starts_with("std::hint::")
        || normalized.starts_with("std::io::_print")
        || normalized.contains("clap::builder::")
        || normalized.contains("std::option::Option")
        || normalized.contains("core::option::Option")
        || normalized.contains("std::cmp::PartialOrd")
        || normalized.contains("__macro_support")
        || normalized.contains("__tokio_select_util")
        || normalized.contains("<implstd::fmt::")
    {
        return false;
    }
    true
}

fn taint_dispatch_confidence(taint: &ConcreteTaint) -> String {
    match taint.paths.len() {
        0 => "low".to_string(),
        1 => "high".to_string(),
        2..=4 => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn kill_concrete(state: &mut ConcreteState, place: &PlacePath) {
    state
        .taints
        .retain(|existing, _| !same_or_descendant(existing, place));
    state
        .aliases
        .retain(|existing, _| !same_or_descendant(existing, place));
}

fn read_concrete(state: &ConcreteState, place: &PlacePath) -> ConcreteTaint {
    let resolved = resolve_aliases(&state.aliases, place);
    let mut paths = Vec::new();
    if let Some(values) = state.taints.get(&resolved) {
        paths.extend(values.paths.clone());
    }
    for (existing, values) in &state.taints {
        if same_or_descendant(&resolved, existing) || same_or_descendant(existing, &resolved) {
            paths.extend(values.paths.clone());
        }
    }
    paths.sort_by(|l, r| l.origin_key.cmp(&r.origin_key));
    paths.dedup_by(|l, r| l.origin_key == r.origin_key);
    ConcreteTaint { paths }
}

/// Joins `incoming` into a block's entry state and reports whether it grew.
///
/// A place keeps the witness it holds for an origin and gains only origins
/// it did not carry, and an alias keeps the first place it was given, so the
/// state grows only by new place and origin pairs and new alias entries.
/// The places are the body's own MIR places and summary places rebased onto
/// its arguments, resolved through those first aliases, and the summaries
/// are already fixed when a body is materialized, so the pairs are finite:
/// that, and not any bound on witnesses, is why the concrete fixpoint ends.
fn merge_concrete(target: &mut ConcreteState, incoming: &ConcreteState) -> bool {
    let mut changed = false;
    for (place, taint) in &incoming.taints {
        let entry = target.taints.entry(place.clone()).or_default();
        let before = entry.paths.len();
        for path in &taint.paths {
            if !entry
                .paths
                .iter()
                .any(|existing| existing.origin_key == path.origin_key)
            {
                entry.paths.push(path.clone());
            }
        }
        if entry.paths.len() != before {
            changed = true;
        }
    }
    for (place, alias) in &incoming.aliases {
        if !target.aliases.contains_key(place) {
            target.aliases.insert(place.clone(), alias.clone());
            changed = true;
        }
    }
    changed
}

/// Follows alias entries from `place` until none applies, longest matching
/// prefix first. Every hop consumes a distinct entry, and a chain that comes
/// back to an entry it already used is a cycle, so the chase ends after at
/// most one hop per entry.
fn resolve_aliases(aliases: &HashMap<PlacePath, PlacePath>, place: &PlacePath) -> PlacePath {
    let mut current = place.clone();
    let mut used: Vec<PlacePath> = Vec::new();
    'chase: loop {
        for prefix_len in (0..=current.projections.len()).rev() {
            let prefix = PlacePath {
                base: current.base.clone(),
                projections: current.projections[..prefix_len].to_vec(),
            };
            let Some(alias) = aliases.get(&prefix) else {
                continue;
            };
            if used.contains(&prefix) {
                break 'chase;
            }
            let mut next = alias.clone();
            next.projections
                .extend(current.projections[prefix_len..].iter().cloned());
            used.push(prefix);
            current = next;
            continue 'chase;
        }
        break;
    }
    current
}

fn same_or_descendant(left: &PlacePath, right: &PlacePath) -> bool {
    left.base == right.base
        && left.projections.len() >= right.projections.len()
        && left
            .projections
            .iter()
            .zip(&right.projections)
            .all(|(l, r)| l == r)
}

#[derive(Debug, Clone)]
struct CryptoRule {
    kind: &'static str,
    algorithm: &'static str,
    provider: &'static str,
    operation: &'static str,
    symbol: &'static str,
    finding: Option<(&'static str, &'static str, &'static str)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowModelKind {
    Source,
    SourceArgument,
    Sink,
    Passthrough,
    Builder,
    NativeSource,
    NativeSink,
}

#[derive(Debug, Clone, Copy)]
struct FlowModel {
    symbol: &'static str,
    kind: FlowModelKind,
    category: &'static str,
    relevant_arguments: &'static [usize],
    tags: &'static [&'static str],
    confidence: &'static str,
}

fn classify_crypto_symbol(symbol: &str) -> Option<CryptoRule> {
    let normalized = normalize_symbol(symbol);
    if normalized.ends_with("sha2::Sha256::digest")
        || normalized.ends_with("Sha256::digest")
        || normalized.ends_with("sha2::Digest::digest")
        || normalized.ends_with("sha2::digest::Digest::update")
        || normalized.ends_with("Digest::update")
    {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "SHA-256",
            provider: "sha2",
            operation: "digest",
            symbol: "sha2::Sha256::digest",
            finding: None,
        })
    } else if normalized.ends_with("sha2::Sha512::digest") || normalized.ends_with("Sha512::digest")
    {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "SHA-512",
            provider: "sha2",
            operation: "digest",
            symbol: "sha2::Sha512::digest",
            finding: None,
        })
    } else if normalized.ends_with("sha1::Sha1::digest") || normalized.ends_with("Sha1::digest") {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "SHA-1",
            provider: "sha1",
            operation: "digest",
            symbol: "sha1::Sha1::digest",
            finding: Some(("weak-crypto", "high", "SHA-1 usage detected")),
        })
    } else if normalized.ends_with("md5::compute") {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "MD5",
            provider: "md5",
            operation: "digest",
            symbol: "md5::compute",
            finding: Some(("weak-crypto", "high", "MD5 usage detected")),
        })
    } else if normalized.ends_with("blake3::hash") {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "BLAKE3",
            provider: "blake3",
            operation: "digest",
            symbol: "blake3::hash",
            finding: None,
        })
    } else if normalized.ends_with("ring::digest::digest") {
        Some(CryptoRule {
            kind: "hash",
            algorithm: "SHA-256",
            provider: "ring",
            operation: "digest",
            symbol: "ring::digest::digest",
            finding: None,
        })
    } else if normalized.ends_with("aes_gcm::aead::KeyInit::new_from_slice")
        || normalized.ends_with("aes_gcm::Aes256Gcm::new_from_slice")
    {
        Some(CryptoRule {
            kind: "aead",
            algorithm: "AES-GCM",
            provider: "aes-gcm",
            operation: "key-init",
            symbol: "aes_gcm::aead::KeyInit::new_from_slice",
            finding: None,
        })
    } else if normalized.ends_with("chacha20poly1305::aead::KeyInit::new_from_slice")
        || normalized.ends_with("chacha20poly1305::ChaCha20Poly1305::new_from_slice")
    {
        Some(CryptoRule {
            kind: "aead",
            algorithm: "ChaCha20-Poly1305",
            provider: "chacha20poly1305",
            operation: "key-init",
            symbol: "chacha20poly1305::aead::KeyInit::new_from_slice",
            finding: None,
        })
    } else if normalized.ends_with("ring::aead::UnboundKey::new") {
        Some(CryptoRule {
            kind: "aead",
            algorithm: "Ring-AEAD",
            provider: "ring",
            operation: "key-init",
            symbol: "ring::aead::UnboundKey::new",
            finding: None,
        })
    } else if normalized.ends_with("hmac::Mac::new_from_slice") {
        Some(CryptoRule {
            kind: "mac",
            algorithm: "HMAC",
            provider: "hmac",
            operation: "key-init",
            symbol: "hmac::Mac::new_from_slice",
            finding: None,
        })
    } else if normalized.ends_with("pbkdf2::pbkdf2_hmac") {
        Some(CryptoRule {
            kind: "kdf",
            algorithm: "PBKDF2",
            provider: "pbkdf2",
            operation: "derive",
            symbol: "pbkdf2::pbkdf2_hmac",
            finding: None,
        })
    } else if normalized.ends_with("argon2::Argon2::hash_password")
        || normalized.ends_with("argon2::password_hash::PasswordHasher::hash_password")
    {
        Some(CryptoRule {
            kind: "kdf",
            algorithm: "Argon2",
            provider: "argon2",
            operation: "hash-password",
            symbol: "argon2::Argon2::hash_password",
            finding: None,
        })
    } else if normalized.ends_with("jsonwebtoken::EncodingKey::from_secret") {
        Some(CryptoRule {
            kind: "token",
            algorithm: "JWT",
            provider: "jsonwebtoken",
            operation: "encode-key",
            symbol: "jsonwebtoken::EncodingKey::from_secret",
            finding: None,
        })
    } else if normalized.ends_with("rustls::ClientConfig::builder")
        || normalized.ends_with("rustls::ServerConfig::builder")
    {
        Some(CryptoRule {
            kind: "protocol",
            algorithm: "TLS",
            provider: "rustls",
            operation: "config-builder",
            symbol: "rustls::ClientConfig::builder",
            finding: None,
        })
    } else if normalized.ends_with("rsa::RsaPrivateKey::new") {
        Some(CryptoRule {
            kind: "asymmetric",
            algorithm: "RSA",
            provider: "rsa",
            operation: "keygen",
            symbol: "rsa::RsaPrivateKey::new",
            finding: None,
        })
    } else if normalized.ends_with("ed25519_dalek::SigningKey::from_bytes") {
        Some(CryptoRule {
            kind: "asymmetric",
            algorithm: "Ed25519",
            provider: "ed25519_dalek",
            operation: "key-init",
            symbol: "ed25519_dalek::SigningKey::from_bytes",
            finding: None,
        })
    } else {
        None
    }
}

fn source_category(call: &MirCall) -> Option<String> {
    std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
        .find_map(|symbol| {
            matching_flow_models(symbol)
                .into_iter()
                .find(|model| {
                    model_allowed_for_call(call, model)
                        && matches!(
                            model.kind,
                            FlowModelKind::Source | FlowModelKind::NativeSource
                        )
                })
                .map(|model| model.category.to_string())
        })
}

fn source_argument_matches(call: &MirCall) -> Vec<(String, Vec<usize>)> {
    let mut results = Vec::new();
    for symbol in std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
    {
        for model in matching_flow_models(symbol) {
            if model_allowed_for_call(call, model)
                && matches!(model.kind, FlowModelKind::SourceArgument)
            {
                results.push((
                    model.category.to_string(),
                    model.relevant_arguments.to_vec(),
                ));
            }
        }
    }
    results
}

fn sink_matches(
    call: &MirCall,
    patterns: &DataFlowPatternSet,
) -> Option<Vec<(String, Vec<usize>)>> {
    let mut results = Vec::new();
    for symbol in std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
    {
        for model in matching_flow_models(symbol) {
            if model_allowed_for_call(call, model)
                && matches!(model.kind, FlowModelKind::Sink | FlowModelKind::NativeSink)
            {
                results.push((
                    model.category.to_string(),
                    model.relevant_arguments.to_vec(),
                ));
            }
        }
        if call.call_type == "native" {
            results.push(("native-call".to_string(), (0..call.args.len()).collect()));
        }
    }
    if results.is_empty() {
        let normalized = normalize_symbol(&call.callee_display);
        for pattern in &patterns.sinks {
            let candidate = normalize_symbol(&pattern.pattern);
            if !candidate.contains("::") && normalized.contains("::") {
                continue;
            }
            if call.call_type != "native"
                && !call.target_ids.is_empty()
                && matching_flow_models(&pattern.pattern)
                    .into_iter()
                    .any(|model| {
                        matches!(
                            model.kind,
                            FlowModelKind::NativeSource | FlowModelKind::NativeSink
                        ) && !model.symbol.contains("::")
                    })
            {
                continue;
            }
            if normalized == candidate || normalized.ends_with(&candidate) {
                results.push((pattern.category.clone(), pattern.relevant_arguments.clone()));
            }
        }
    }
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

fn model_allowed_for_call(call: &MirCall, model: &FlowModel) -> bool {
    if matches!(
        model.kind,
        FlowModelKind::NativeSource | FlowModelKind::NativeSink
    ) && !model.symbol.contains("::")
        && call.call_type != "native"
    {
        return false;
    }
    true
}

fn model_tags_for_call(call: &MirCall) -> BTreeSet<&'static str> {
    let mut tags = BTreeSet::new();
    for symbol in std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
    {
        for model in matching_flow_models(symbol) {
            if model_allowed_for_call(call, model) {
                tags.extend(model.tags.iter().copied());
            }
        }
    }
    tags
}

fn passthrough(call: &MirCall) -> bool {
    std::iter::once(call.callee_display.as_str())
        .chain(call.target_names.iter().map(String::as_str))
        .any(|symbol| {
            if matching_flow_models(symbol).into_iter().any(|model| {
                matches!(
                    model.kind,
                    FlowModelKind::Passthrough | FlowModelKind::Builder
                )
            }) {
                return true;
            }
            let normalized = normalize_symbol(symbol);
            matches!(
                last_segment(&normalized),
                "unwrap_or_else"
                    | "unwrap"
                    | "unwrap_or_default"
                    | "to_string"
                    | "to_owned"
                    | "into_owned"
                    | "clone"
                    | "deref"
                    | "new"
                    | "block_on"
                    | "as_ptr"
                    | "Ok"
                    | "Some"
            ) || normalized.ends_with("std::ffi::CString::new")
        })
}

fn built_in_patterns() -> DataFlowPatternSet {
    let sources = built_in_flow_models()
        .iter()
        .filter(|model| {
            matches!(
                model.kind,
                FlowModelKind::Source | FlowModelKind::NativeSource
            )
        })
        .map(|model| {
            pattern(
                "source",
                model.symbol,
                model.category,
                model.relevant_arguments.to_vec(),
            )
        })
        .collect();
    let sinks = built_in_flow_models()
        .iter()
        .filter(|model| matches!(model.kind, FlowModelKind::Sink | FlowModelKind::NativeSink))
        .map(|model| {
            pattern(
                "sink",
                model.symbol,
                model.category,
                model.relevant_arguments.to_vec(),
            )
        })
        .collect();
    let passthroughs = built_in_flow_models()
        .iter()
        .filter(|model| {
            matches!(
                model.kind,
                FlowModelKind::Passthrough | FlowModelKind::Builder
            )
        })
        .map(|model| {
            pattern(
                "passthrough",
                model.symbol,
                model.category,
                model.relevant_arguments.to_vec(),
            )
        })
        .collect();
    DataFlowPatternSet {
        sources,
        sinks,
        passthroughs,
    }
}

fn built_in_flow_models() -> &'static [FlowModel] {
    &[
        FlowModel {
            symbol: "std::env::var",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::var_os",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "os-string"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::args",
            kind: FlowModelKind::Source,
            category: "cli",
            relevant_arguments: &[],
            tags: &["source", "std"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::args_os",
            kind: FlowModelKind::Source,
            category: "cli",
            relevant_arguments: &[],
            tags: &["source", "std", "os-string"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::vars",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "env-iterator"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::vars_os",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "env-iterator", "os-string"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::current_dir",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "cwd", "path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::current_exe",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "process", "path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::temp_dir",
            kind: FlowModelKind::Source,
            category: "env",
            relevant_arguments: &[],
            tags: &["source", "std", "path", "temp"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::set_current_dir",
            kind: FlowModelKind::Sink,
            category: "process-working-directory",
            relevant_arguments: &[0],
            tags: &["sink", "std", "process", "cwd"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::set_var",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[0, 1],
            tags: &["sink", "std", "process", "env"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::env::remove_var",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[0],
            tags: &["sink", "std", "process", "env"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "clap::Parser::parse",
            kind: FlowModelKind::Source,
            category: "cli",
            relevant_arguments: &[],
            tags: &["source", "cli", "clap"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "Cli::parse",
            kind: FlowModelKind::Source,
            category: "cli",
            relevant_arguments: &[],
            tags: &["source", "cli", "clap", "derive"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::fs::read_to_string",
            kind: FlowModelKind::Source,
            category: "file",
            relevant_arguments: &[],
            tags: &["source", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read",
            kind: FlowModelKind::Source,
            category: "file",
            relevant_arguments: &[],
            tags: &["source", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read_dir",
            kind: FlowModelKind::Source,
            category: "filesystem-metadata",
            relevant_arguments: &[],
            tags: &["source", "filesystem", "directory"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read_link",
            kind: FlowModelKind::Source,
            category: "filesystem-metadata",
            relevant_arguments: &[],
            tags: &["source", "filesystem", "symlink"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::metadata",
            kind: FlowModelKind::Source,
            category: "filesystem-metadata",
            relevant_arguments: &[],
            tags: &["source", "filesystem", "metadata"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::symlink_metadata",
            kind: FlowModelKind::Source,
            category: "filesystem-metadata",
            relevant_arguments: &[],
            tags: &["source", "filesystem", "metadata", "symlink"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::canonicalize",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0],
            tags: &["passthrough", "filesystem", "path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::io::stdin",
            kind: FlowModelKind::Source,
            category: "cli",
            relevant_arguments: &[],
            tags: &["source", "stdio"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::io::Read::read",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Read::read_exact",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Read::read_to_end",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Read::read_to_string",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::BufRead::read_line",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Stdin::read_line",
            kind: FlowModelKind::SourceArgument,
            category: "cli",
            relevant_arguments: &[1],
            tags: &["source", "stdio", "argument-output"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::io::BufRead::read_until",
            kind: FlowModelKind::SourceArgument,
            category: "input",
            relevant_arguments: &[2],
            tags: &["source", "stdio", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "rand::rngs::OsRng",
            kind: FlowModelKind::Source,
            category: "entropy",
            relevant_arguments: &[],
            tags: &["source", "entropy"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "rand::rngs::OsRng::default",
            kind: FlowModelKind::Source,
            category: "entropy",
            relevant_arguments: &[],
            tags: &["source", "entropy"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "getrandom::fill",
            kind: FlowModelKind::Source,
            category: "entropy",
            relevant_arguments: &[],
            tags: &["source", "entropy"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::process::Command::new",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "process"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::arg",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[1],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::args",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[1],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::env",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[1, 2],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::envs",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[1],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::env_remove",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[1],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::env_clear",
            kind: FlowModelKind::Sink,
            category: "process-env",
            relevant_arguments: &[0],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::current_dir",
            kind: FlowModelKind::Sink,
            category: "process-working-directory",
            relevant_arguments: &[1],
            tags: &["sink", "process", "builder"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::output",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "process", "builder-exec"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::status",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "process", "builder-exec"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::process::Command::spawn",
            kind: FlowModelKind::Sink,
            category: "process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "process", "builder-exec"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::write",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read_to_string",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read_dir",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "directory", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::read_link",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "symlink", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::metadata",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "metadata", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::symlink_metadata",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "metadata", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::canonicalize",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "path", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::create_dir_all",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "directory-create"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::create_dir",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "directory-create"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::File::create",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "file-create"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::File::open",
            kind: FlowModelKind::Sink,
            category: "filesystem-read",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem", "read-path"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::OpenOptions::open",
            kind: FlowModelKind::Sink,
            category: "filesystem-open",
            relevant_arguments: &[1],
            tags: &["sink", "filesystem", "open-options"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::OpenOptions::write",
            kind: FlowModelKind::Builder,
            category: "filesystem-open-options",
            relevant_arguments: &[0],
            tags: &["builder", "filesystem", "open-options"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::OpenOptions::read",
            kind: FlowModelKind::Builder,
            category: "filesystem-open-options",
            relevant_arguments: &[0],
            tags: &["builder", "filesystem", "open-options"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::OpenOptions::append",
            kind: FlowModelKind::Builder,
            category: "filesystem-open-options",
            relevant_arguments: &[0],
            tags: &["builder", "filesystem", "open-options"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::OpenOptions::create",
            kind: FlowModelKind::Builder,
            category: "filesystem-open-options",
            relevant_arguments: &[0],
            tags: &["builder", "filesystem", "open-options"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::copy",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "copy"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::rename",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "rename"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::hard_link",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "link"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::os::unix::fs::symlink",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "symlink", "unix"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::os::windows::fs::symlink_file",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "symlink", "windows"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::os::windows::fs::symlink_dir",
            kind: FlowModelKind::Sink,
            category: "filesystem-write",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "symlink", "windows"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::remove_file",
            kind: FlowModelKind::Sink,
            category: "filesystem-delete",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::remove_dir_all",
            kind: FlowModelKind::Sink,
            category: "filesystem-delete",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::remove_dir",
            kind: FlowModelKind::Sink,
            category: "filesystem-delete",
            relevant_arguments: &[0],
            tags: &["sink", "filesystem"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::fs::set_permissions",
            kind: FlowModelKind::Sink,
            category: "filesystem-permission",
            relevant_arguments: &[0, 1],
            tags: &["sink", "filesystem", "permissions"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::TcpStream::connect",
            kind: FlowModelKind::Sink,
            category: "network-connect",
            relevant_arguments: &[0],
            tags: &["sink", "network"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::TcpListener::bind",
            kind: FlowModelKind::Sink,
            category: "network-listen",
            relevant_arguments: &[0],
            tags: &["sink", "network", "listen"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::bind",
            kind: FlowModelKind::Sink,
            category: "network-listen",
            relevant_arguments: &[0],
            tags: &["sink", "network", "udp", "listen"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::connect",
            kind: FlowModelKind::Sink,
            category: "network-connect",
            relevant_arguments: &[1],
            tags: &["sink", "network", "udp"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::send_to",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1, 2],
            tags: &["sink", "network", "udp"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::send",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["sink", "network", "udp"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::TcpStream::read",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::net::TcpStream::read_exact",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::recv",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "udp", "argument-output"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::UdpSocket::recv_from",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "udp", "argument-output"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::net::TcpStream::write",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["sink", "network"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::net::TcpStream::write_all",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["sink", "network"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Write::write",
            kind: FlowModelKind::Sink,
            category: "output",
            relevant_arguments: &[1],
            tags: &["sink", "stdio"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Write::write_all",
            kind: FlowModelKind::Sink,
            category: "output",
            relevant_arguments: &[1],
            tags: &["sink", "stdio"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::io::Write::write_fmt",
            kind: FlowModelKind::Sink,
            category: "output",
            relevant_arguments: &[1],
            tags: &["sink", "stdio", "format"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::net::TcpStream::connect",
            kind: FlowModelKind::Sink,
            category: "network-connect",
            relevant_arguments: &[0],
            tags: &["sink", "network", "tokio", "async-io"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::net::TcpListener::bind",
            kind: FlowModelKind::Sink,
            category: "network-listen",
            relevant_arguments: &[0],
            tags: &["sink", "network", "tokio", "async-io", "listen"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::io::AsyncReadExt::read_buf",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "tokio", "async-io", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::io::AsyncReadExt::read",
            kind: FlowModelKind::SourceArgument,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["source", "network", "tokio", "async-io", "argument-output"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::io::AsyncWriteExt::write_all",
            kind: FlowModelKind::Sink,
            category: "network-response",
            relevant_arguments: &[1],
            tags: &["sink", "network", "tokio", "async-io"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "tokio::io::AsyncWriteExt::write",
            kind: FlowModelKind::Sink,
            category: "network-response",
            relevant_arguments: &[1],
            tags: &["sink", "network", "tokio", "async-io"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "Connection::read_frame",
            kind: FlowModelKind::Source,
            category: "network-request",
            relevant_arguments: &[],
            tags: &["source", "network", "protocol-wrapper"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Command::from_frame",
            kind: FlowModelKind::Passthrough,
            category: "protocol-frame",
            relevant_arguments: &[0],
            tags: &["passthrough", "protocol-wrapper"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Frame::parse",
            kind: FlowModelKind::Passthrough,
            category: "protocol-frame",
            relevant_arguments: &[0],
            tags: &["passthrough", "protocol-wrapper"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Connection::write_frame",
            kind: FlowModelKind::Sink,
            category: "network-response",
            relevant_arguments: &[1],
            tags: &["sink", "network", "protocol-wrapper"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Connection::write_value",
            kind: FlowModelKind::Sink,
            category: "network-response",
            relevant_arguments: &[1],
            tags: &["sink", "network", "protocol-wrapper"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Command::apply",
            kind: FlowModelKind::Sink,
            category: "network-response",
            relevant_arguments: &[0],
            tags: &["sink", "network", "protocol-wrapper", "dispatch"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "reqwest::get",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[0],
            tags: &["sink", "network", "http"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "reqwest::Client::get",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["sink", "network", "http", "builder"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "reqwest::Client::post",
            kind: FlowModelKind::Sink,
            category: "network-request",
            relevant_arguments: &[1],
            tags: &["sink", "network", "http", "builder"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "aes_gcm::aead::KeyInit::new_from_slice",
            kind: FlowModelKind::Sink,
            category: "crypto-key",
            relevant_arguments: &[0],
            tags: &["sink", "crypto"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "aes_gcm::Aes256Gcm::new_from_slice",
            kind: FlowModelKind::Sink,
            category: "crypto-key",
            relevant_arguments: &[0],
            tags: &["sink", "crypto"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "hmac::Mac::new_from_slice",
            kind: FlowModelKind::Sink,
            category: "crypto-key",
            relevant_arguments: &[0],
            tags: &["sink", "crypto"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "ring::aead::UnboundKey::new",
            kind: FlowModelKind::Sink,
            category: "crypto-key",
            relevant_arguments: &[1],
            tags: &["sink", "crypto"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "aes_gcm::aead::Aead::encrypt",
            kind: FlowModelKind::Sink,
            category: "crypto-nonce",
            relevant_arguments: &[1],
            tags: &["sink", "crypto"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "unwrap",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "unwrap_or_else",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "combinator"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "unwrap_or_default",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::result::Result::map",
            kind: FlowModelKind::Passthrough,
            category: "result-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::result::Result::map_err",
            kind: FlowModelKind::Passthrough,
            category: "result-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::option::Option::map",
            kind: FlowModelKind::Passthrough,
            category: "option-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::option::Option::and_then",
            kind: FlowModelKind::Passthrough,
            category: "option-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::result::Result::and_then",
            kind: FlowModelKind::Passthrough,
            category: "result-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "to_string",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::string::String::from",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "string"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::string::String::into_bytes",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "string"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::string::String::as_bytes",
            kind: FlowModelKind::Passthrough,
            category: "borrow-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "string", "borrow"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::str::from_utf8",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "string", "conversion"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::str::from_utf8_unchecked",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "string", "conversion", "unsafe"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "to_owned",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "into_owned",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::convert::From::from",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "conversion"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::convert::Into::into",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "conversion"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "clone",
            kind: FlowModelKind::Passthrough,
            category: "value-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "as_ref",
            kind: FlowModelKind::Passthrough,
            category: "borrow-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "as_mut",
            kind: FlowModelKind::Passthrough,
            category: "borrow-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::ops::Deref::deref",
            kind: FlowModelKind::Passthrough,
            category: "borrow-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "projection"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::ops::DerefMut::deref_mut",
            kind: FlowModelKind::Passthrough,
            category: "borrow-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "projection"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::prelude::v1::Ok",
            kind: FlowModelKind::Passthrough,
            category: "result-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::prelude::v1::Some",
            kind: FlowModelKind::Passthrough,
            category: "option-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "container"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::boxed::Box::pin",
            kind: FlowModelKind::Passthrough,
            category: "pin-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "async-boundary"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::boxed::Box::new",
            kind: FlowModelKind::Passthrough,
            category: "smart-pointer",
            relevant_arguments: &[0],
            tags: &["passthrough", "smart-pointer"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::Arc::new",
            kind: FlowModelKind::Passthrough,
            category: "smart-pointer",
            relevant_arguments: &[0],
            tags: &["passthrough", "smart-pointer", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::rc::Rc::new",
            kind: FlowModelKind::Passthrough,
            category: "smart-pointer",
            relevant_arguments: &[0],
            tags: &["passthrough", "smart-pointer"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::cell::RefCell::new",
            kind: FlowModelKind::Passthrough,
            category: "smart-pointer",
            relevant_arguments: &[0],
            tags: &["passthrough", "interior-mutability"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::Mutex::new",
            kind: FlowModelKind::Passthrough,
            category: "sync-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::RwLock::new",
            kind: FlowModelKind::Passthrough,
            category: "sync-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::Mutex::lock",
            kind: FlowModelKind::Passthrough,
            category: "sync-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::RwLock::read",
            kind: FlowModelKind::Passthrough,
            category: "sync-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::sync::RwLock::write",
            kind: FlowModelKind::Passthrough,
            category: "sync-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "sync"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::ffi::CString::new",
            kind: FlowModelKind::Passthrough,
            category: "ffi-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "native-boundary"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "std::ffi::CStr::from_ptr",
            kind: FlowModelKind::NativeSource,
            category: "native-string",
            relevant_arguments: &[],
            tags: &["source", "native-boundary"],
            confidence: "exact",
        },
        FlowModel {
            symbol: "as_ptr",
            kind: FlowModelKind::Passthrough,
            category: "ffi-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "native-boundary"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::path::Path::join",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0, 1],
            tags: &["passthrough", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::PathBuf::from",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0],
            tags: &["passthrough", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::Path::new",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0],
            tags: &["passthrough", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::PathBuf::push",
            kind: FlowModelKind::Builder,
            category: "path-builder",
            relevant_arguments: &[0, 1],
            tags: &["builder", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::PathBuf::set_file_name",
            kind: FlowModelKind::Builder,
            category: "path-builder",
            relevant_arguments: &[0, 1],
            tags: &["builder", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::PathBuf::set_extension",
            kind: FlowModelKind::Builder,
            category: "path-builder",
            relevant_arguments: &[0, 1],
            tags: &["builder", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::Path::to_path_buf",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0],
            tags: &["passthrough", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::path::Path::parent",
            kind: FlowModelKind::Passthrough,
            category: "path-builder",
            relevant_arguments: &[0],
            tags: &["passthrough", "path"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::ffi::OsString::from",
            kind: FlowModelKind::Passthrough,
            category: "os-string-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "os-string"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::ffi::OsStr::to_os_string",
            kind: FlowModelKind::Passthrough,
            category: "os-string-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "os-string"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "Vec::push",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1],
            tags: &["builder", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "Vec::extend",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1],
            tags: &["builder", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::iter::Extend::extend",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1],
            tags: &["builder", "container"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "Vec::from",
            kind: FlowModelKind::Passthrough,
            category: "container",
            relevant_arguments: &[0],
            tags: &["passthrough", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "std::iter::Iterator::collect",
            kind: FlowModelKind::Passthrough,
            category: "iterator-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "iterator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::iter::Iterator::map",
            kind: FlowModelKind::Passthrough,
            category: "iterator-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "iterator", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::iter::Iterator::filter_map",
            kind: FlowModelKind::Passthrough,
            category: "iterator-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "iterator", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "std::iter::Iterator::flatten",
            kind: FlowModelKind::Passthrough,
            category: "iterator-wrapper",
            relevant_arguments: &[0],
            tags: &["passthrough", "iterator", "combinator"],
            confidence: "type-resolved",
        },
        FlowModel {
            symbol: "HashMap::insert",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1, 2],
            tags: &["builder", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "HashSet::insert",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1],
            tags: &["builder", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "BTreeMap::insert",
            kind: FlowModelKind::Builder,
            category: "container",
            relevant_arguments: &[0, 1, 2],
            tags: &["builder", "container"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "getenv",
            kind: FlowModelKind::NativeSource,
            category: "native-env",
            relevant_arguments: &[],
            tags: &["source", "native-boundary", "ffi"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "secure_getenv",
            kind: FlowModelKind::NativeSource,
            category: "native-env",
            relevant_arguments: &[],
            tags: &["source", "native-boundary", "ffi"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "read",
            kind: FlowModelKind::NativeSource,
            category: "native-read",
            relevant_arguments: &[],
            tags: &["source", "native-boundary", "ffi"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "recv",
            kind: FlowModelKind::NativeSource,
            category: "native-network",
            relevant_arguments: &[],
            tags: &["source", "native-boundary", "ffi"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "fgets",
            kind: FlowModelKind::NativeSource,
            category: "native-read",
            relevant_arguments: &[],
            tags: &["source", "native-boundary", "ffi"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "system",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "popen",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "execv",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[0, 1],
            tags: &["sink", "native-boundary", "ffi", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "execve",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[0, 1, 2],
            tags: &["sink", "native-boundary", "ffi", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "CreateProcessW",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[0, 1],
            tags: &["sink", "native-boundary", "windows", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "ShellExecuteW",
            kind: FlowModelKind::NativeSink,
            category: "native-process-exec",
            relevant_arguments: &[2, 3],
            tags: &["sink", "native-boundary", "windows", "process"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "puts",
            kind: FlowModelKind::NativeSink,
            category: "native-output",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "stdio"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "send",
            kind: FlowModelKind::NativeSink,
            category: "native-network",
            relevant_arguments: &[1],
            tags: &["sink", "native-boundary", "ffi", "network"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "connect",
            kind: FlowModelKind::NativeSink,
            category: "native-network",
            relevant_arguments: &[1],
            tags: &["sink", "native-boundary", "ffi", "network"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "open",
            kind: FlowModelKind::NativeSink,
            category: "native-filesystem-open",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "filesystem"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "fopen",
            kind: FlowModelKind::NativeSink,
            category: "native-filesystem-open",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "filesystem"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "unlink",
            kind: FlowModelKind::NativeSink,
            category: "native-filesystem-delete",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "filesystem"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "remove",
            kind: FlowModelKind::NativeSink,
            category: "native-filesystem-delete",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "filesystem"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "dlopen",
            kind: FlowModelKind::NativeSink,
            category: "native-dynamic-load",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "ffi", "loader"],
            confidence: "pattern",
        },
        FlowModel {
            symbol: "LoadLibraryW",
            kind: FlowModelKind::NativeSink,
            category: "native-dynamic-load",
            relevant_arguments: &[0],
            tags: &["sink", "native-boundary", "windows", "loader"],
            confidence: "pattern",
        },
    ]
}

fn matching_flow_models(symbol: &str) -> Vec<&'static FlowModel> {
    built_in_flow_models()
        .iter()
        .filter(|model| flow_model_matches(symbol, model))
        .collect()
}

fn flow_model_matches(symbol: &str, model: &FlowModel) -> bool {
    let normalized = canonical_call_symbol(symbol);
    let pattern = normalize_symbol(model.symbol);
    let normalized_erased = strip_generic_arguments(&normalized);
    let pattern_erased = strip_generic_arguments(&pattern);
    if matches!(
        model.kind,
        FlowModelKind::NativeSource | FlowModelKind::NativeSink
    ) && (normalized.starts_with("std::")
        || normalized.starts_with("core::")
        || normalized.starts_with("alloc::"))
    {
        return false;
    }
    if matches!(
        model.kind,
        FlowModelKind::NativeSource | FlowModelKind::NativeSink
    ) && !pattern.contains("::")
        && normalized.contains("::")
    {
        return false;
    }
    if let Some((trait_name, method_name)) = impl_trait_method_parts(symbol) {
        let trait_method = format!("{}::{}", normalize_symbol(&trait_name), method_name);
        if pattern == trait_method || pattern.ends_with(&format!("::{trait_method}")) {
            return true;
        }
    }
    if pattern.contains("::") {
        normalized == pattern
            || normalized.ends_with(&format!("::{pattern}"))
            || normalized_erased == pattern_erased
            || normalized_erased.ends_with(&format!("::{pattern_erased}"))
    } else {
        normalized == pattern
            || last_segment(&normalized) == pattern
            || normalized_erased == pattern_erased
            || last_segment(&normalized_erased) == pattern_erased
    }
}

fn add_model_properties(properties: &mut IndexMap<String, String>, symbol: &str) {
    let models = matching_flow_models(symbol);
    if models.is_empty() {
        return;
    }
    properties.insert(
        "dataflowModels".to_string(),
        models
            .iter()
            .map(|model| model.symbol)
            .collect::<Vec<_>>()
            .join(","),
    );
    properties.insert(
        "modelConfidence".to_string(),
        models
            .iter()
            .map(|model| model.confidence)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(","),
    );
    let tags = models
        .iter()
        .flat_map(|model| model.tags.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    if !tags.is_empty() {
        properties.insert("modelTags".to_string(), tags);
    }
    if models.iter().any(|model| {
        matches!(
            model.kind,
            FlowModelKind::NativeSource | FlowModelKind::NativeSink
        ) || model.tags.contains(&"native-boundary")
    }) {
        properties.insert("nativeBoundary".to_string(), "true".to_string());
    }
}

fn modeled_native_boundary(symbol: &str) -> bool {
    matching_flow_models(symbol).into_iter().any(|model| {
        matches!(
            model.kind,
            FlowModelKind::NativeSource | FlowModelKind::NativeSink
        ) || model.tags.contains(&"native-boundary")
    })
}

fn pattern(
    target: &str,
    symbol: &str,
    category: &str,
    relevant_arguments: Vec<usize>,
) -> DataFlowPattern {
    DataFlowPattern {
        target: target.to_string(),
        pattern: symbol.to_string(),
        category: category.to_string(),
        relevant_arguments,
        // The compiler backend matches on type-resolved symbols, so it never
        // needs the receiver-type restriction the stable backend uses to
        // disambiguate a bare method name.
        receiver_type: None,
    }
}

fn resolve_method_call(
    tcx: TyCtxt<'_>,
    receiver_ty: Ty<'_>,
    def_id: Option<DefId>,
    function_ids: &HashMap<LocalDefId, String>,
) -> Option<ResolvedCall> {
    let def_id = def_id?;
    let symbol = tcx.def_path_str(def_id);
    let receiver_ty = receiver_ty.peel_refs();
    let receiver_type = Some(normalize_type_name(receiver_ty.to_string()));
    let call_type = if matches!(receiver_ty.kind(), ty::Dynamic(..)) {
        "dyn-dispatch"
    } else if tcx.opt_associated_item(def_id).is_some_and(|assoc| {
        matches!(
            assoc.container,
            AssocContainer::Trait | AssocContainer::TraitImpl(_)
        )
    }) {
        "trait-static"
    } else {
        "static"
    };
    // Only a `ty::Dynamic` receiver dispatches through a vtable, and
    // `call_type` above is exactly that test. A `trait-static` call reaches a
    // trait's method too, but it is resolved statically and selects no vtable,
    // so it reports no dispatching trait.
    let DynCandidates {
        ids: target_ids,
        names: target_names,
        receivers: candidate_receivers,
        dispatch_trait,
    } = if call_type == "dyn-dispatch" {
        enumerate_dyn_candidates(tcx, receiver_ty, def_id, function_ids)
    } else {
        let (ids, names) = target_for_def_id(tcx, def_id, function_ids);
        DynCandidates {
            ids,
            names,
            receivers: receiver_type.clone().into_iter().collect(),
            dispatch_trait: None,
        }
    };
    let native_boundary = modeled_native_boundary(&symbol)
        || target_names
            .iter()
            .any(|target| modeled_native_boundary(target));
    let semantic_tags =
        semantic_tags_for_call(&symbol, &target_names, call_type, receiver_type.as_deref());
    let async_boundary = semantic_tags.iter().any(|tag| tag == "async-boundary");
    let task_boundary = semantic_tags.iter().any(|tag| tag == "task-boundary");
    let dispatch_confidence = dispatch_confidence_for(call_type, target_ids.len());
    let specialization_key =
        specialization_key_from_parts(receiver_type.as_deref(), &semantic_tags, &target_names);
    Some(ResolvedCall {
        callee_display: symbol,
        call_type: if native_boundary
            || matches!(
                tcx.def_kind(def_id),
                DefKind::ForeignMod | DefKind::ForeignTy
            ) {
            "native".to_string()
        } else {
            call_type.to_string()
        },
        dispatch_confidence,
        target_ids,
        target_names,
        candidate_receivers,
        receiver_type: receiver_type.clone(),
        dispatch_trait,
        specialization_key,
        semantic_tags,
        async_boundary,
        task_boundary,
    })
}

fn resolve_expr_call(
    tcx: TyCtxt<'_>,
    typeck: &ty::TypeckResults<'_>,
    func: &Expr<'_>,
    function_ids: &HashMap<LocalDefId, String>,
) -> Option<ResolvedCall> {
    match func.kind {
        ExprKind::Path(qpath) => {
            let res = typeck.qpath_res(&qpath, func.hir_id);
            let def_id = res.opt_def_id()?;
            let (target_ids, target_names) = target_for_def_id(tcx, def_id, function_ids);
            let symbol = tcx.def_path_str(def_id);
            let native_boundary = modeled_native_boundary(&symbol)
                || target_names
                    .iter()
                    .any(|target| modeled_native_boundary(target));
            let semantic_tags = semantic_tags_for_call(&symbol, &target_names, "static", None);
            Some(ResolvedCall {
                callee_display: symbol,
                call_type: if native_boundary {
                    "native".to_string()
                } else if matches!(typeck.expr_ty(func).kind(), ty::FnPtr(..)) {
                    "fn-pointer".to_string()
                } else {
                    "static".to_string()
                },
                dispatch_confidence: dispatch_confidence_for("static", target_ids.len()),
                target_ids,
                target_names,
                candidate_receivers: Vec::new(),
                receiver_type: None,
                dispatch_trait: None,
                specialization_key: specialization_key_from_parts(None, &semantic_tags, &[]),
                semantic_tags: semantic_tags.clone(),
                async_boundary: semantic_tags.iter().any(|tag| tag == "async-boundary"),
                task_boundary: semantic_tags.iter().any(|tag| tag == "task-boundary"),
            })
        }
        _ => match typeck.expr_ty(func).kind() {
            ty::Closure(def_id, _) | ty::Coroutine(def_id, _) | ty::CoroutineClosure(def_id, _) => {
                let def_id = *def_id;
                let (target_ids, target_names) = target_for_def_id(tcx, def_id, function_ids);
                let semantic_tags = semantic_tags_for_call(
                    &tcx.def_path_str(def_id),
                    &target_names,
                    "closure",
                    None,
                );
                Some(ResolvedCall {
                    callee_display: tcx.def_path_str(def_id),
                    call_type: "closure".to_string(),
                    dispatch_confidence: dispatch_confidence_for("closure", target_ids.len()),
                    target_ids,
                    target_names,
                    candidate_receivers: Vec::new(),
                    receiver_type: None,
                    dispatch_trait: None,
                    specialization_key: specialization_key_from_parts(None, &semantic_tags, &[]),
                    semantic_tags: semantic_tags.clone(),
                    async_boundary: semantic_tags.iter().any(|tag| tag == "async-boundary"),
                    task_boundary: semantic_tags.iter().any(|tag| tag == "task-boundary"),
                })
            }
            ty::FnDef(def_id, _) => {
                let def_id = *def_id;
                let (target_ids, target_names) = target_for_def_id(tcx, def_id, function_ids);
                let semantic_tags = semantic_tags_for_call(
                    &tcx.def_path_str(def_id),
                    &target_names,
                    "static",
                    None,
                );
                Some(ResolvedCall {
                    callee_display: tcx.def_path_str(def_id),
                    call_type: "static".to_string(),
                    dispatch_confidence: dispatch_confidence_for("static", target_ids.len()),
                    target_ids,
                    target_names,
                    candidate_receivers: Vec::new(),
                    receiver_type: None,
                    dispatch_trait: None,
                    specialization_key: specialization_key_from_parts(None, &semantic_tags, &[]),
                    semantic_tags: semantic_tags.clone(),
                    async_boundary: semantic_tags.iter().any(|tag| tag == "async-boundary"),
                    task_boundary: semantic_tags.iter().any(|tag| tag == "task-boundary"),
                })
            }
            ty::FnPtr(..) => Some(ResolvedCall {
                callee_display: "fn-pointer".to_string(),
                call_type: "fn-pointer".to_string(),
                dispatch_confidence: "low".to_string(),
                target_ids: Vec::new(),
                target_names: Vec::new(),
                candidate_receivers: Vec::new(),
                receiver_type: None,
                dispatch_trait: None,
                specialization_key: "fn-pointer".to_string(),
                semantic_tags: vec!["fn-pointer".to_string()],
                async_boundary: false,
                task_boundary: false,
            }),
            _ => None,
        },
    }
}

fn target_for_def_id(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    function_ids: &HashMap<LocalDefId, String>,
) -> (Vec<String>, Vec<String>) {
    let symbol = tcx.def_path_str(def_id);
    if def_id.is_local()
        && let Some(id) = function_ids.get(&def_id.expect_local())
    {
        return (vec![id.clone()], vec![symbol]);
    }
    (
        vec![stable_id("cg-node", &["external", &symbol])],
        vec![symbol],
    )
}

/// What a `dyn` receiver's method call resolved to.
///
/// `dispatch_trait` is `Some` only when the targets in `ids` were found by
/// walking a trait's impls: that trait owns the called method, so it is the
/// trait whose vtable dispatches the call. Every fallback path below resolves
/// the callee directly instead, and reports no trait, because none was used.
struct DynCandidates {
    ids: Vec<String>,
    names: Vec<String>,
    receivers: Vec<String>,
    dispatch_trait: Option<String>,
}

impl DynCandidates {
    /// The callee resolved without going through a trait's impls.
    fn without_trait(ids: Vec<String>, names: Vec<String>) -> Self {
        Self {
            ids,
            names,
            receivers: Vec::new(),
            dispatch_trait: None,
        }
    }
}

fn enumerate_dyn_candidates(
    tcx: TyCtxt<'_>,
    receiver_ty: Ty<'_>,
    method_def_id: DefId,
    function_ids: &HashMap<LocalDefId, String>,
) -> DynCandidates {
    let Some(assoc) = tcx.opt_associated_item(method_def_id) else {
        let (ids, names) = target_for_def_id(tcx, method_def_id, function_ids);
        return DynCandidates::without_trait(ids, names);
    };
    let trait_item = assoc.trait_item_def_id().unwrap_or(method_def_id);
    let Some(trait_def_id) = tcx
        .opt_associated_item(trait_item)
        .and_then(|item| item.trait_container(tcx))
    else {
        let (ids, names) = target_for_def_id(tcx, method_def_id, function_ids);
        return DynCandidates::without_trait(ids, names);
    };
    let method_name = tcx.associated_item(trait_item).name();
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut receivers = Vec::new();
    let receiver_hint = normalize_type_name(receiver_ty.to_string());
    if let Some(impls) = tcx.all_local_trait_impls(()).get(&trait_def_id) {
        for impl_def in impls {
            let impl_ty = normalize_type_name(impl_self_ty_name(tcx, impl_def.to_def_id()));
            if !receiver_hint.is_empty()
                && !receiver_hint.contains("dyn")
                && !receiver_matches_hint(&impl_ty, &receiver_hint)
            {
                continue;
            }
            for candidate in tcx
                .associated_items(impl_def.to_def_id())
                .in_definition_order()
            {
                if candidate.is_fn() && candidate.name() == method_name {
                    names.push(tcx.def_path_str(candidate.def_id));
                    receivers.push(impl_ty.clone());
                    if let Some(id) = candidate
                        .def_id
                        .as_local()
                        .and_then(|local| function_ids.get(&local))
                    {
                        ids.push(id.clone());
                    } else {
                        ids.push(stable_id("cg-node", &["external", names.last().unwrap()]));
                    }
                }
            }
        }
    }
    if ids.is_empty() {
        let (ids, names) = target_for_def_id(tcx, method_def_id, function_ids);
        DynCandidates::without_trait(ids, names)
    } else {
        DynCandidates {
            ids,
            names,
            receivers,
            // The bare trait name, matching what the stable backend emits, so
            // the field joins across backends rather than carrying a full path
            // in one and a short name in the other.
            dispatch_trait: Some(tcx.item_name(trait_def_id).to_string()),
        }
    }
}

fn receiver_matches_hint(candidate: &str, hint: &str) -> bool {
    candidate == hint
        || candidate.ends_with(hint)
        || hint.ends_with(candidate)
        || hint.contains(candidate)
        || candidate.contains(hint)
}

fn dispatch_confidence_for(call_type: &str, target_count: usize) -> String {
    match (call_type, target_count) {
        (_, 0) => "low".to_string(),
        ("static", 1) | ("closure", 1) | ("native", 1) => "high".to_string(),
        (_, 1) => "high".to_string(),
        (_, 2..=4) => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn edge_precision_for(call: &MirCall) -> String {
    match call.target_ids.len() {
        0 => "unknown".to_string(),
        1 => "exact".to_string(),
        _ => "bounded".to_string(),
    }
}

fn callgraph_call_type(call: &MirCall) -> String {
    if call.async_boundary || call.task_boundary {
        "async-logical".to_string()
    } else if call.target_ids.is_empty() {
        format!("{}-unknown", call.call_type)
    } else if call.target_ids.len() == 1 {
        format!("{}-exact", call.call_type)
    } else {
        format!("{}-bounded", call.call_type)
    }
}

fn normalize_type_name(value: String) -> String {
    normalize_symbol(&value)
}

fn semantic_tags_for_call(
    symbol: &str,
    target_names: &[String],
    call_type: &str,
    receiver_type: Option<&str>,
) -> Vec<String> {
    let mut tags = BTreeSet::new();
    let mut inspect = vec![symbol.to_string()];
    inspect.extend(target_names.iter().cloned());
    for candidate in inspect {
        let normalized = normalize_symbol(&candidate);
        let last = last_segment(&normalized);
        for model in matching_flow_models(&candidate) {
            for tag in model.tags {
                tags.insert((*tag).to_string());
            }
            tags.insert(format!("model-confidence:{}", model.confidence));
            if matches!(
                model.kind,
                FlowModelKind::NativeSource | FlowModelKind::NativeSink
            ) {
                tags.insert("native-boundary".to_string());
            }
        }
        if matches!(call_type, "dyn-dispatch" | "trait-static") {
            tags.insert("trait-dispatch".to_string());
        }
        if matches!(call_type, "closure" | "fn-pointer") {
            tags.insert(call_type.to_string());
        }
        if normalized.contains("poll")
            || normalized.contains("block_on")
            || normalized.contains("await")
        {
            tags.insert("async-boundary".to_string());
        }
        if normalized.contains("spawn") || normalized.contains("thread::spawn") {
            tags.insert("task-boundary".to_string());
        }
        if normalized.contains("mpsc::")
            || matches!(last, "send" | "recv" | "try_recv" | "recv_timeout")
        {
            tags.insert("channel".to_string());
        }
        if matches!(
            last,
            "map" | "map_err" | "and_then" | "then" | "or_else" | "inspect" | "unwrap_or_else"
        ) {
            tags.insert("combinator".to_string());
            tags.insert("passthrough".to_string());
        }
        if matches!(
            last,
            "clone"
                | "to_string"
                | "to_owned"
                | "into_owned"
                | "as_ref"
                | "as_mut"
                | "as_deref"
                | "as_deref_mut"
                | "borrow"
                | "borrow_mut"
                | "lock"
                | "take"
                | "get"
                | "get_mut"
                | "first"
                | "last"
                | "next"
                | "pop"
                | "recv"
                | "try_recv"
        ) {
            tags.insert("passthrough".to_string());
        }
        if matches!(last, "iter" | "iter_mut" | "into_iter" | "next") {
            tags.insert("iterator".to_string());
        }
        if matches!(last, "new" | "insert" | "push" | "arg" | "args") {
            tags.insert("builder".to_string());
        }
        if matches!(last, "call" | "call_mut" | "call_once") {
            tags.insert("callable".to_string());
        }
    }
    if receiver_type.is_some_and(|receiver| {
        receiver.contains("RefCell")
            || receiver.contains("Mutex")
            || receiver.contains("RwLock")
            || receiver.contains("MutexGuard")
            || receiver.contains("RwLockReadGuard")
            || receiver.contains("RwLockWriteGuard")
            || receiver.contains("Ref<")
            || receiver.contains("RefMut<")
    }) {
        tags.insert("interior-mutability".to_string());
    }
    tags.into_iter().collect()
}

fn hir_precision_index(hir_calls: &[HirCallRecord]) -> HashMap<(String, String), usize> {
    let mut precision = HashMap::<(String, String), usize>::new();
    for call in hir_calls {
        let rank = precision_rank_for_resolved(&call.resolved);
        for symbol in hir_symbols(&call.resolved) {
            let key = (call.source_id.clone(), symbol);
            precision
                .entry(key)
                .and_modify(|existing| *existing = (*existing).max(rank))
                .or_insert(rank);
        }
    }
    precision
}

fn hir_symbols(resolved: &ResolvedCall) -> Vec<String> {
    let mut symbols = Vec::new();
    symbols.push(canonical_call_symbol(&resolved.callee_display));
    for target in &resolved.target_names {
        let symbol = canonical_call_symbol(target);
        if !symbols.contains(&symbol) {
            symbols.push(symbol);
        }
    }
    symbols
}

fn precision_rank_for_resolved(resolved: &ResolvedCall) -> usize {
    if resolved.async_boundary || resolved.task_boundary {
        3
    } else {
        match resolved.target_ids.len() {
            0 => 0,
            1 => 2,
            _ => 1,
        }
    }
}

fn precision_rank_for_call(call: &MirCall) -> usize {
    if call.async_boundary || call.task_boundary {
        3
    } else {
        match call.target_ids.len() {
            0 => 0,
            1 => 2,
            _ => 1,
        }
    }
}

fn should_skip_mir_edge(
    source_id: &str,
    target_name: &str,
    call: &MirCall,
    hir_precision: &HashMap<(String, String), usize>,
) -> bool {
    let symbol = canonical_call_symbol(target_name);
    let current_rank = precision_rank_for_call(call);
    if hir_precision
        .get(&(source_id.to_string(), symbol.clone()))
        .is_some_and(|existing| *existing > current_rank)
    {
        return true;
    }
    let suffix = last_segment(&symbol).to_string();
    hir_precision
        .iter()
        .any(|((source, existing_symbol), rank)| {
            source == source_id && *rank > current_rank && last_segment(existing_symbol) == suffix
        })
}

fn canonical_call_symbol(value: &str) -> String {
    let normalized = normalize_symbol(value);
    if normalized.starts_with('<') && normalized.contains(" as ") && normalized.contains(">::") {
        return normalized
            .split(" as ")
            .nth(1)
            .unwrap_or(&normalized)
            .trim_start_matches('<')
            .replace(">::", "::")
            .trim_end_matches('>')
            .to_string();
    }
    normalized
}

fn specialization_key_from_parts(
    receiver_type: Option<&str>,
    semantic_tags: &[String],
    target_names: &[String],
) -> String {
    let mut parts = Vec::new();
    if let Some(receiver_type) = receiver_type {
        parts.push(receiver_type.to_string());
    }
    if !semantic_tags.is_empty() {
        parts.push(semantic_tags.join("+"));
    }
    if !target_names.is_empty() {
        parts.push(target_names.join("|"));
    }
    if parts.is_empty() {
        "default".to_string()
    } else {
        parts.join("::")
    }
}

fn function_kind(tcx: TyCtxt<'_>, owner: LocalDefId) -> String {
    match tcx.def_kind(owner) {
        DefKind::Fn => {
            if tcx
                .fn_sig(owner.to_def_id())
                .skip_binder()
                .safety()
                .is_unsafe()
            {
                "unsafe-function".to_string()
            } else {
                "function".to_string()
            }
        }
        DefKind::AssocFn => {
            if let Some(assoc) = tcx.opt_associated_item(owner.to_def_id()) {
                if matches!(
                    assoc.container,
                    AssocContainer::Trait | AssocContainer::TraitImpl(_)
                ) {
                    "trait-method".to_string()
                } else if tcx
                    .fn_sig(owner.to_def_id())
                    .skip_binder()
                    .safety()
                    .is_unsafe()
                {
                    "unsafe-method".to_string()
                } else {
                    "method".to_string()
                }
            } else {
                "method".to_string()
            }
        }
        DefKind::Closure | DefKind::SyntheticCoroutineBody => "closure".to_string(),
        _ if is_inline_const(tcx, owner.to_def_id()) => "closure".to_string(),
        _ => "function".to_string(),
    }
}

fn declaration_signature(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    match tcx.def_kind(def_id) {
        DefKind::Fn | DefKind::AssocFn => tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .to_string(),
        _ => tcx.def_path_str(def_id),
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

fn looks_like_async_boundary(symbol: &str) -> bool {
    let symbol = normalize_symbol(symbol);
    symbol.contains("tokio::spawn")
        || symbol.contains("std::thread::spawn")
        || symbol.contains("poll")
}

fn sort_crypto(crypto: &mut CryptoEvidence) {
    crypto.libraries.sort_by(|l, r| l.id.cmp(&r.id));
    crypto.components.sort_by(|l, r| l.id.cmp(&r.id));
    crypto.materials.sort_by(|l, r| l.id.cmp(&r.id));
    crypto.findings.sort_by(|l, r| l.id.cmp(&r.id));
}

fn file_path_from_span(tcx: TyCtxt<'_>, root: &Path, span: Span) -> String {
    match tcx
        .sess
        .source_map()
        .span_to_filename(span.source_callsite())
    {
        FileName::Real(real) => real
            .into_local_path()
            .map(|path| relative_display_path(root, &path))
            .unwrap_or_else(|| "<non-local>".to_string()),
        other => format!("{:?}", other),
    }
}

fn position_from_span(tcx: TyCtxt<'_>, root: &Path, span: Span) -> Position {
    let callsite = span.source_callsite();
    let location = tcx.sess.source_map().lookup_char_pos(callsite.lo());
    let filename = match &location.file.name {
        FileName::Real(real) => real
            .clone()
            .into_local_path()
            .map(|p| relative_display_path(root, &p))
            .unwrap_or_else(|| format!("{:?}", location.file.name)),
        _ => format!("{:?}", location.file.name),
    };
    Position {
        filename,
        line: location.line,
        column: location.col_display + 1,
    }
}

fn span_key(tcx: TyCtxt<'_>, span: Span) -> String {
    let callsite = span.source_callsite();
    let lo = tcx.sess.source_map().lookup_char_pos(callsite.lo());
    let hi = tcx.sess.source_map().lookup_char_pos(callsite.hi());
    format!(
        "{:?}:{}:{}:{}",
        lo.file.name,
        lo.line,
        lo.col_display + 1,
        hi.col_display + 1
    )
}

fn span_key_simple(span: Span) -> String {
    format!("{}:{}", span.lo().0, span.hi().0)
}

fn debug_log(enabled: bool, args: std::fmt::Arguments<'_>) {
    if enabled {
        eprintln!("rusi debug: {args}");
    }
}

fn data_flow_mode_collects_external_bodies(mode: &str) -> bool {
    matches!(mode, "security-deps" | "security-full")
}

fn local_crate_source_path(tcx: TyCtxt<'_>) -> Option<PathBuf> {
    tcx.sess
        .local_crate_source_file()
        .and_then(|path| path.into_local_path())
}

fn path_is_under_root(root: &Path, path: &Path) -> bool {
    let root = canonical_path(root);
    let path = canonical_path(path);
    path.starts_with(root)
}

fn prepare_emit_dir(analysis_root: &Path, emit_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let analysis_root = analysis_root.canonicalize().with_context(|| {
        format!(
            "failed to resolve analysis root {}",
            analysis_root.display()
        )
    })?;
    let relative = emit_dir.strip_prefix(&analysis_root).with_context(|| {
        format!(
            "refusing to write compiler artifacts outside analysis root {}; got {}",
            analysis_root.display(),
            emit_dir.display()
        )
    })?;
    let mut scoped_emit_dir = analysis_root.clone();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => scoped_emit_dir.push(part),
            _ => anyhow::bail!(
                "refusing to use non-normal compiler artifact path {}",
                emit_dir.display()
            ),
        }
        ensure_safe_directory_component(&scoped_emit_dir)?;
    }
    Ok((analysis_root, scoped_emit_dir))
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
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect compiler artifact path {}",
                    path.display()
                )
            });
        }
    }
    Ok(())
}

fn ensure_directory_within_root(root: &Path, path: &Path) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve analysis root {}", root.display()))?;
    let canonical_path = path.canonicalize().with_context(|| {
        format!(
            "failed to resolve compiler artifact directory {}",
            path.display()
        )
    })?;
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
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn last_segment(value: &str) -> &str {
    value.rsplit("::").next().unwrap_or(value)
}

fn inferred_package_path(value: &str) -> String {
    value.split("::").next().unwrap_or("").to_string()
}

fn normalize_symbol(value: &str) -> String {
    let mut normalized = strip_generic_arguments(&value.replace(' ', ""));
    while normalized.contains("::::") || normalized.contains(":::") {
        normalized = normalized.replace("::::", "::").replace(":::", "::");
    }
    normalized.trim_end_matches(':').to_string()
}

fn strip_generic_arguments(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut angle_depth = 0usize;
    for ch in value.chars() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            _ if angle_depth == 0 => result.push(ch),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(base: &str, projections: &[PlaceProjection]) -> PlacePath {
        PlacePath {
            base: base.to_string(),
            projections: projections.to_vec(),
        }
    }

    fn local(base: &str) -> PlacePath {
        place(base, &[])
    }

    fn field(name: &str) -> PlaceProjection {
        PlaceProjection::Field(name.to_string())
    }

    fn assign(dest: &str, sources: &[PlacePath]) -> MirOp {
        MirOp::Assign(AssignAction {
            dest: local(dest),
            sources: sources.to_vec(),
            alias: None,
            field_sources: Vec::new(),
        })
    }

    fn call(dest: &str, callee: &str, target_ids: &[&str], args: &[PlacePath]) -> MirOp {
        MirOp::Call(MirCall {
            dest: local(dest),
            dest_type: None,
            callee_display: callee.to_string(),
            call_type: if target_ids.is_empty() {
                "static".to_string()
            } else {
                "local".to_string()
            },
            dispatch_confidence: "high".to_string(),
            target_ids: target_ids.iter().map(|id| id.to_string()).collect(),
            target_names: Vec::new(),
            candidate_receivers: Vec::new(),
            receiver_type: None,
            dispatch_trait: None,
            specialization_key: String::new(),
            semantic_tags: Vec::new(),
            async_boundary: false,
            task_boundary: false,
            args: args
                .iter()
                .map(|arg| CallArg {
                    place: Some(arg.clone()),
                    type_name: None,
                })
                .collect(),
        })
    }

    fn block(label: usize, ops: Vec<MirOp>, successors: &[usize], returns: bool) -> MirBlock {
        MirBlock {
            label: format!("bb{label}"),
            ops,
            successors: successors.iter().map(|next| format!("bb{next}")).collect(),
            returns,
        }
    }

    fn function(name: &str, params: &[&str], blocks: Vec<MirBlock>) -> MirFunction {
        MirFunction {
            id: format!("fn-{name}"),
            name: last_segment(name).to_string(),
            qualified_name: name.to_string(),
            kind: "function".to_string(),
            package_path: "probe".to_string(),
            file_path: "src/main.rs".to_string(),
            position: Position::default(),
            param_names: params.iter().map(|param| param.to_string()).collect(),
            param_types: params
                .iter()
                .map(|_| "std::string::String".to_string())
                .collect(),
            return_type: "()".to_string(),
            blocks,
        }
    }

    fn summaries_of(functions: &[MirFunction]) -> (BTreeMap<String, FunctionSummary>, usize) {
        let patterns = built_in_patterns();
        let local_ids = functions
            .iter()
            .map(|f| f.id.clone())
            .collect::<HashSet<_>>();
        let function_map = functions
            .iter()
            .map(|f| (f.id.clone(), f))
            .collect::<HashMap<_, _>>();
        let ctx = FlowContext::new(functions, &patterns, &local_ids, &function_map);
        summary_fixpoint(functions, &ctx, false)
    }

    /// `f00(p)` calls `f01(p)` and so on down to a process spawn, written
    /// callers first: the old pass learned one level per round and stopped
    /// after eight.
    fn call_chain(depth: usize) -> Vec<MirFunction> {
        (0..depth)
            .map(|level| {
                let name = format!("probe::f{level:02}");
                let op = if level + 1 < depth {
                    let callee = format!("probe::f{:02}", level + 1);
                    let callee_id = format!("fn-{callee}");
                    call("_2", &callee, &[callee_id.as_str()], &[local("p")])
                } else {
                    call("_2", "std::process::Command::new", &[], &[local("p")])
                };
                function(&name, &["p"], vec![block(0, vec![op], &[], true)])
            })
            .collect()
    }

    #[test]
    fn a_call_chain_of_any_depth_settles_in_one_pass() {
        let functions = call_chain(30);
        let (summaries, evaluations) = summaries_of(&functions);
        assert_eq!(evaluations, functions.len(), "one evaluation per function");
        for function in &functions {
            assert_eq!(
                summaries[&function.id].param_to_sink.get("process-exec"),
                Some(&BTreeSet::from([0])),
                "{}",
                function.qualified_name
            );
        }
    }

    #[test]
    fn mutual_recursion_settles_without_a_round_limit() {
        // even(p) -> odd(p) -> even(p), and odd also spawns p.
        let even = function(
            "probe::even",
            &["p"],
            vec![block(
                0,
                vec![call("_2", "probe::odd", &["fn-probe::odd"], &[local("p")])],
                &[],
                true,
            )],
        );
        let odd = function(
            "probe::odd",
            &["p"],
            vec![block(
                0,
                vec![
                    call("_2", "probe::even", &["fn-probe::even"], &[local("p")]),
                    call("_3", "std::process::Command::new", &[], &[local("p")]),
                ],
                &[],
                true,
            )],
        );
        let (summaries, evaluations) = summaries_of(&[even, odd]);
        assert_eq!(
            summaries["fn-probe::even"]
                .param_to_sink
                .get("process-exec"),
            Some(&BTreeSet::from([0]))
        );
        assert!((2..=6).contains(&evaluations), "{evaluations}");
    }

    /// A function recursing on a field of its own parameter, returning a
    /// field: without widening, each round would add `n.next.val`,
    /// `n.next.next.val`, and so on forever.
    #[test]
    fn recursion_on_a_projection_of_a_parameter_terminates() {
        let next = place("n", &[PlaceProjection::Deref, field("next")]);
        let val = place("n", &[PlaceProjection::Deref, field("val")]);
        let walk = function(
            "probe::walk",
            &["n"],
            vec![
                block(0, vec![], &[1, 2], false),
                block(
                    1,
                    vec![
                        call(
                            "_3",
                            "probe::walk",
                            &["fn-probe::walk"],
                            std::slice::from_ref(&next),
                        ),
                        assign("_0", &[local("_3")]),
                    ],
                    &[3],
                    false,
                ),
                block(
                    2,
                    vec![assign("_0", std::slice::from_ref(&val))],
                    &[3],
                    false,
                ),
                block(3, vec![], &[], true),
            ],
        );
        let (summaries, _) = summaries_of(&[walk]);
        let summary = &summaries["fn-probe::walk"];
        assert!(summary.field_to_return.contains(&val));
        assert!(
            summary.field_to_return.contains(&next),
            "widened to the argument"
        );
        assert!(
            summary
                .field_to_return
                .iter()
                .all(|place| place.projections.len() <= 2),
            "{:?}",
            summary.field_to_return
        );
    }

    /// A loop body of seventy links, each copied from the next, with the
    /// source stored in the last: the source needs seventy trips to reach
    /// `x00`, past the 64 whole-function passes the old fixpoint allowed.
    fn seventy_step_loop() -> MirFunction {
        let links = 70;
        let head = 1;
        let first_body = 2;
        let last_body = first_body + links - 1;
        let exit = last_body + 1;
        // The head lists its exit first, the order under which reverse
        // postorder alone would rank the exit ahead of the body.
        let mut blocks = vec![
            block(0, vec![], &[head], false),
            block(head, vec![], &[exit, first_body], false),
        ];
        for link in 0..links {
            let label = first_body + link;
            let mut ops = vec![assign(
                &format!("x{link:02}"),
                &[local(&format!("x{:02}", link + 1))],
            )];
            let next = if label == last_body {
                ops.push(call(
                    &format!("x{links:02}"),
                    "std::env::var",
                    &[],
                    &[local("key")],
                ));
                head
            } else {
                label + 1
            };
            blocks.push(block(label, ops, &[next], false));
        }
        blocks.push(block(
            exit,
            vec![call(
                "_9",
                "std::process::Command::new",
                &[],
                &[local("x00")],
            )],
            &[],
            true,
        ));
        function("probe::seventy", &["key"], blocks)
    }

    #[test]
    fn a_loop_carried_chain_longer_than_the_old_pass_limit_settles() {
        let seventy = seventy_step_loop();
        let (summaries, _) = summaries_of(std::slice::from_ref(&seventy));
        assert_eq!(
            summaries[&seventy.id].source_to_sink.get("process-exec"),
            Some(&BTreeSet::from(["env".to_string()]))
        );

        let mut diagnostics = Vec::new();
        let evidence = build_data_flow(std::slice::from_ref(&seventy), &mut diagnostics, false);
        let slice = evidence
            .slices
            .iter()
            .find(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
            .expect("env reaches the spawn after seventy trips");
        // The witness walks every link: source, seventy copies, the spawn.
        assert_eq!(slice.path_length, 71);
    }

    /// A spawn in a loop body that sees the source only from the second trip
    /// on, next to a call nothing resolves. The fixpoint transfers the body
    /// more than once; emitting from the settled states reports each once.
    #[test]
    fn loop_bodies_emit_once_from_the_settled_state() {
        let carried = function(
            "probe::carried",
            &["key"],
            vec![
                block(0, vec![], &[1], false),
                block(1, vec![], &[3, 2], false),
                block(
                    2,
                    vec![
                        assign("x", &[local("y")]),
                        call("y", "std::env::var", &[], &[local("key")]),
                        call("_5", "probe::mystery", &[], &[local("x")]),
                        call("_6", "std::process::Command::new", &[], &[local("x")]),
                    ],
                    &[1],
                    false,
                ),
                block(3, vec![], &[], true),
            ],
        );
        let mut diagnostics = Vec::new();
        let evidence = build_data_flow(std::slice::from_ref(&carried), &mut diagnostics, false);
        let spawns: Vec<_> = evidence
            .slices
            .iter()
            .filter(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
            .collect();
        assert_eq!(spawns.len(), 1, "{spawns:#?}");
        // Source, the copy into `x`, the spawn.
        assert_eq!(spawns[0].path_length, 2);
        let unresolved = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.ends_with(": probe::mystery"))
            .count();
        assert_eq!(unresolved, 1, "{diagnostics:#?}");
    }

    #[test]
    fn loop_bodies_rank_before_their_exit_whatever_the_successor_order() {
        let seventy = seventy_step_loop();
        let graph = BlockGraph::new(&seventy);
        let position = |block: usize| graph.order.iter().position(|b| *b == block).unwrap();
        let exit = seventy.blocks.len() - 1;
        assert_eq!(graph.order.len(), seventy.blocks.len());
        for body in 2..exit {
            assert!(position(body) < position(exit), "bb{body} before the exit");
        }
    }

    #[test]
    fn alias_chains_resolve_fully_and_stop_at_cycles() {
        // a00 -> a01 -> ... -> a20: the old chase stopped after eight hops.
        let mut aliases = HashMap::new();
        for hop in 0..20 {
            aliases.insert(
                local(&format!("a{hop:02}")),
                local(&format!("a{:02}", hop + 1)),
            );
        }
        assert_eq!(resolve_aliases(&aliases, &local("a00")), local("a20"));
        // A projection rides along a prefix alias.
        let projected = place("a00", &[field("f")]);
        assert_eq!(
            resolve_aliases(&aliases, &projected),
            place("a20", &[field("f")])
        );

        let cycle = HashMap::from([(local("x"), local("y")), (local("y"), local("x"))]);
        let resolved = resolve_aliases(&cycle, &local("x"));
        assert!(resolved == local("x") || resolved == local("y"));
        // A cycle that grows the place each time around still ends.
        let growing = HashMap::from([(local("g"), place("g", &[field("next")]))]);
        assert_eq!(
            resolve_aliases(&growing, &local("g")),
            place("g", &[field("next")])
        );
    }

    #[test]
    fn rebasing_widens_only_inside_a_recursion_cycle() {
        let callee = function("probe::callee", &["q"], Vec::new());
        let args = [CallArg {
            place: Some(place("a", &[field("b")])),
            type_name: None,
        }];
        let field_place = place("q", &[field("c")]);
        assert_eq!(
            rebase_summary_place(&args, &callee, &field_place, None, false),
            Some(place("a", &[field("b"), field("c")]))
        );
        assert_eq!(
            rebase_summary_place(&args, &callee, &field_place, None, true),
            Some(place("a", &[field("b")]))
        );
    }

    #[test]
    fn impl_trait_method_parts_reads_the_top_level_as() {
        let parts = |symbol: &str| impl_trait_method_parts(symbol);
        let pair =
            |trait_name: &str, method: &str| Some((trait_name.to_string(), method.to_string()));
        assert_eq!(
            parts("<dispatch::Stage01 as dispatch::Stage>::apply"),
            pair("Stage", "apply")
        );
        assert_eq!(
            parts("<dyn dispatch::Stage as dispatch::Stage>::apply"),
            pair("Stage", "apply")
        );
        assert_eq!(parts("<Store as Database>::get"), pair("Database", "get"));
        assert_eq!(parts("<Database as Class>::load"), pair("Class", "load"));
        assert_eq!(
            parts("<Vec<Alias> as Handler<Base>>::call"),
            pair("Handler", "call")
        );
        assert_eq!(
            parts("<<T as Source>::Item as Sink>::put"),
            pair("Sink", "put")
        );
        assert_eq!(
            parts("<fn() -> Cast as Callable>::invoke"),
            pair("Callable", "invoke")
        );
        assert_eq!(parts("<X as Y>::method::<u8>"), pair("Y", "method"));
        assert_eq!(parts("probe::free_function"), None);
        assert_eq!(parts("<Inherent>::method"), None);
    }

    #[test]
    fn candidate_targets_reach_every_impl_of_the_trait_in_id_order() {
        let impls: Vec<MirFunction> = (0..40)
            .map(|index| {
                function(
                    &format!("<dispatch::Stage{index:02} as dispatch::Stage>::apply"),
                    &["self", "input"],
                    Vec::new(),
                )
            })
            .chain(std::iter::once(function(
                "<dispatch::Other as dispatch::Unrelated>::apply",
                &["self", "input"],
                Vec::new(),
            )))
            .collect();
        let patterns = built_in_patterns();
        let local_ids = impls.iter().map(|f| f.id.clone()).collect::<HashSet<_>>();
        let function_map = impls
            .iter()
            .map(|f| (f.id.clone(), f))
            .collect::<HashMap<_, _>>();
        let ctx = FlowContext::new(&impls, &patterns, &local_ids, &function_map);
        let MirOp::Call(mut dyn_call) = call(
            "_4",
            "<dyn dispatch::Stage as dispatch::Stage>::apply",
            &[],
            &[local("stage"), local("input")],
        ) else {
            unreachable!()
        };
        dyn_call.call_type = "dyn-dispatch".to_string();
        let targets = candidate_dataflow_targets(&dyn_call, &ctx);
        assert_eq!(targets.len(), 40, "every Stage impl, and only those");
        assert!(targets.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(!targets.iter().any(|id| id.contains("Unrelated")));
    }

    /// Rust resolves a call to an inherent method statically, so the call
    /// carries it as its own target, and a trait-object, trait or
    /// unresolved call can never land on one. The candidate indexes hold
    /// trait impl methods only, so no inherent method stands in for such a
    /// call, whatever it is called and whatever its type is called
    /// (`Database` contains the letters of " as ").
    #[test]
    fn inherent_methods_are_reached_only_through_their_own_targets() {
        let functions = vec![
            function("probe::Database::get", &["self", "key"], Vec::new()),
            function("<probe::Wrapper<T>>::get", &["self", "key"], Vec::new()),
            function(
                "<probe::Memory as probe::Store>::get",
                &["self", "key"],
                Vec::new(),
            ),
        ];
        let patterns = built_in_patterns();
        let local_ids = functions
            .iter()
            .map(|f| f.id.clone())
            .collect::<HashSet<_>>();
        let function_map = functions
            .iter()
            .map(|f| (f.id.clone(), f))
            .collect::<HashMap<_, _>>();
        let ctx = FlowContext::new(&functions, &patterns, &local_ids, &function_map);
        let targets = |callee: &str, call_type: &str, target_ids: &[&str]| {
            let MirOp::Call(mut call) =
                call("_3", callee, target_ids, &[local("store"), local("key")])
            else {
                unreachable!()
            };
            call.call_type = call_type.to_string();
            candidate_dataflow_targets(&call, &ctx)
        };
        let memory = vec!["fn-<probe::Memory as probe::Store>::get".to_string()];
        assert_eq!(
            targets(
                "<dyn probe::Store as probe::Store>::get",
                "dyn-dispatch",
                &[]
            ),
            memory
        );
        assert_eq!(targets("probe::Store::get", "trait-static", &[]), memory);
        assert_eq!(targets("get", "unresolved", &[]), memory);
        assert_eq!(
            targets(
                "probe::Database::get",
                "static",
                &["fn-probe::Database::get"]
            ),
            vec!["fn-probe::Database::get".to_string()]
        );
    }

    #[test]
    fn nested_bodies_are_indexed_under_every_enclosing_function() {
        let functions = vec![
            function("probe::outer", &[], Vec::new()),
            function("probe::outer::{closure#0}", &[], Vec::new()),
            function("probe::outer::{closure#0}::{closure#1}", &[], Vec::new()),
            function("probe::outer_twin::{closure#0}", &[], Vec::new()),
        ];
        let patterns = built_in_patterns();
        let local_ids = functions
            .iter()
            .map(|f| f.id.clone())
            .collect::<HashSet<_>>();
        let function_map = functions
            .iter()
            .map(|f| (f.id.clone(), f))
            .collect::<HashMap<_, _>>();
        let ctx = FlowContext::new(&functions, &patterns, &local_ids, &function_map);
        assert_eq!(
            ctx.nested_bodies["probe::outer"],
            vec![
                "fn-probe::outer::{closure#0}".to_string(),
                "fn-probe::outer::{closure#0}::{closure#1}".to_string()
            ]
        );
        assert_eq!(
            ctx.nested_bodies["probe::outer::{closure#0}"],
            vec!["fn-probe::outer::{closure#0}::{closure#1}".to_string()]
        );
    }

    #[test]
    fn summaries_join_by_union_and_report_growth() {
        let mut summary = FunctionSummary::default();
        let mut next = FunctionSummary::default();
        next.param_to_sink
            .insert("process-exec".to_string(), BTreeSet::from([0]));
        assert!(summary.join(next.clone()));
        assert!(!summary.join(next));
        let mut more = FunctionSummary::default();
        more.param_to_sink
            .insert("process-exec".to_string(), BTreeSet::from([1]));
        assert!(summary.join(more));
        assert_eq!(
            summary.param_to_sink["process-exec"],
            BTreeSet::from([0, 1])
        );
    }
}
