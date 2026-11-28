//! Crate-root-driven module discovery for the stable backend.
//!
//! The original discovery walked `src/**` and derived each module path from the
//! file path. That is wrong in three ways: files unreachable from any crate root
//! are analyzed anyway, `#[path = "..."]` modules get a bogus path, and targets
//! that are genuinely separate crates (`lib.rs`, `main.rs`, `bin/*.rs`) are
//! conflated into one module namespace.
//!
//! This module instead starts from the Cargo targets of a package and follows
//! `mod` declarations outward, exactly as `rustc` does: inline modules recurse
//! in place, out-of-line modules resolve to `dir/name.rs` or `dir/name/mod.rs`,
//! and `#[path]` overrides both. cfg-disabled `mod` declarations are not
//! followed at all.
//!
//! Files that no root reaches are still reported, flagged as orphans with the
//! old path-derived module path, so switching to this discovery cannot silently
//! lose evidence.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use cargo_metadata::Package;

use crate::PackageContext;
use crate::cfg::CfgEvaluator;
use crate::macro_expand::{self, MacroFilePrepass};

/// A crate root belonging to one Cargo target.
#[derive(Debug, Clone)]
pub(crate) struct CrateRoot {
    /// Target name as Cargo reports it (`my-lib`, `my-bin`, ...).
    pub(crate) target_name: String,
    /// Primary target kind (`lib`, `bin`, `test`, ...).
    pub(crate) target_kind: String,
    pub(crate) path: PathBuf,
}

/// One Rust file to analyze, with the module path it actually occupies.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredFile {
    pub(crate) path: PathBuf,
    /// Module path relative to the crate root, empty for the root itself.
    pub(crate) module_path: Vec<String>,
    /// Cargo target that reached this file; with `target_kind`, it decides the
    /// crate that roots the file's qualified names (see [`crate_path`]).
    pub(crate) target_name: String,
    pub(crate) target_kind: String,
    /// True when no crate root reached this file and the module path was
    /// derived from the file path as a fallback.
    #[allow(dead_code)]
    pub(crate) orphan: bool,
}

/// The outcome of discovery for one package.
///
/// Discovery reads each file once and parses it once: the parse that walks
/// the `mod` tree also feeds the macro pre-pass, and the text is kept for
/// the analysis pass so no file is read from disk twice. `prepasses` and
/// `sources` line up with `files` by index.
#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleTree {
    pub(crate) files: Vec<DiscoveredFile>,
    /// The macro pre-pass result of each file, extracted from the one parse
    /// discovery made. Every position carries a value; a file that could not
    /// be read or parsed carries an empty pre-pass.
    pub(crate) prepasses: Vec<MacroFilePrepass>,
    /// Each file's text, taken by the analysis pass so the file is not read
    /// again. `None` where the file could not be read here, which sends the
    /// analysis pass back to disk so the failure is reported there as before.
    pub(crate) sources: Vec<Option<String>>,
    /// Human-readable notes (unresolved `mod` declarations, orphan files) for
    /// the caller to turn into report diagnostics.
    pub(crate) notes: Vec<ModuleTreeNote>,
}

#[derive(Debug, Clone)]
pub(crate) struct ModuleTreeNote {
    pub(crate) message: String,
    /// Package-relative path of the file the note is about, when known.
    pub(crate) file_path: Option<PathBuf>,
}

/// Selects the Cargo targets that act as crate roots for analysis.
///
/// Test, bench, and example targets are only included with `include_tests`,
/// matching how the previous discovery treated the `tests/` directory.
pub(crate) fn crate_roots(
    package: &Package,
    include_tests: bool,
    library_only: bool,
) -> Vec<CrateRoot> {
    let mut roots = Vec::new();
    for target in &package.targets {
        let kind = target
            .kind
            .first()
            .map(|kind| kind.to_string())
            .unwrap_or_default();
        let selected = match kind.as_str() {
            "lib" | "rlib" | "dylib" | "staticlib" | "cdylib" | "proc-macro" => true,
            "bin" => !library_only,
            "test" | "bench" | "example" => include_tests && !library_only,
            // `custom-build` is build.rs: it never ships in the artifact under
            // analysis, so it is not a crate root here.
            _ => false,
        };
        if !selected {
            continue;
        }
        roots.push(CrateRoot {
            target_name: target.name.clone(),
            target_kind: kind,
            path: target.src_path.as_std_path().to_path_buf(),
        });
    }
    roots.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.target_name.cmp(&right.target_name))
    });
    roots
}

/// [`discover_with_pool`] on a pool of its own, for tests.
#[cfg(test)]
pub(crate) fn discover(
    package_ctx: &PackageContext,
    roots: &[CrateRoot],
    evaluator: &CfgEvaluator,
    include_tests: bool,
    analysis_root: &Path,
    edition_2021: bool,
) -> Result<ModuleTree> {
    let pool = DiscoveryPool::spawn(crate::analysis_worker_count());
    let tree = discover_with_pool(
        package_ctx,
        roots,
        evaluator,
        include_tests,
        analysis_root,
        edition_2021,
        &pool,
    );
    drop(pool);
    tree
}

/// Walks every crate root of the package, then sweeps for orphan files.
///
/// Each file is read and parsed once; the parse feeds both the `mod` walk
/// and the macro pre-pass, and the text is kept for the analysis pass.
/// `analysis_root` is the directory the report's file paths are relative to,
/// and `edition_2021` is the package's edition as the macro pre-pass reads
/// patterns.
///
/// The per-file half of the walk (read, parse, extract, resolve children)
/// runs on `pool`, which a planning phase shares across every package it
/// walks, so one huge crate does not serialize the front of the pipeline
/// behind it. Which file belongs to which root and module path, and the
/// notes, are decided afterwards on the caller's thread in depth-first
/// order (see [`walk_root`]), so the returned tree and notes do not depend
/// on the order the workers finished in.
pub(crate) fn discover_with_pool(
    package_ctx: &PackageContext,
    roots: &[CrateRoot],
    evaluator: &CfgEvaluator,
    include_tests: bool,
    analysis_root: &Path,
    edition_2021: bool,
    pool: &DiscoveryPool,
) -> Result<ModuleTree> {
    let mut tree = ModuleTree::default();
    // A file can legitimately be reached by several roots (a module shared by a
    // lib and a bin). We analyze it once, under the first root that claims it,
    // so evidence is not duplicated.
    let mut claimed: HashSet<PathBuf> = HashSet::new();
    // Every module file must resolve inside the package directory. A `#[path]`
    // attribute or a symlinked `src/` can otherwise point at code outside the
    // package under analysis, which the previous directory walk also refused to
    // follow.
    let allowed_root = crate::canonical_path(&package_ctx.root_dir);
    // What each walk task produced, keyed by path; replayed into the tree in
    // walk order once every root has drained.
    let mut walked: HashMap<PathBuf, WalkedFile> = HashMap::new();
    // The notes of each root's subtree, in walk order. The walk notes have to
    // wait here rather than go straight into the tree, because a root whose
    // root file is missing pushes its note before the next root's subtree
    // notes, exactly as the sequential walk did.
    let mut root_notes: Vec<Vec<ModuleTreeNote>> = Vec::new();

    for root in roots {
        if !root.path.is_file() {
            root_notes.push(vec![ModuleTreeNote {
                message: format!(
                    "crate root for target `{}` does not exist: {}",
                    root.target_name,
                    root.path.display()
                ),
                file_path: None,
            }]);
            continue;
        }
        let Some(root_path) = contained_file(&root.path, &allowed_root) else {
            root_notes.push(vec![ModuleTreeNote {
                message: format!(
                    "crate root for target `{}` resolves outside the package directory and was \
                     skipped: {}",
                    root.target_name,
                    root.path.display()
                ),
                file_path: None,
            }]);
            continue;
        };
        root_notes.push(walk_root(
            pool,
            root,
            &root_path,
            evaluator,
            edition_2021,
            analysis_root,
            &allowed_root,
            &mut claimed,
            &mut walked,
        ));
    }

    let orphans = collect_orphans(package_ctx, &claimed, include_tests)?;
    // An orphan's one read and parse also feed the macro pre-pass, exactly as
    // a reached file's do, and it runs on the pool like everything else: a
    // dependency closure usually sweeps up more files than its `mod` trees
    // reach, so the orphan sweep is most of the files of the run. A file that
    // cannot be read stays on the `None` slot so the analysis pass reads it
    // again and reports the failure there, as it does for a reached file.
    let (reply, replies) = std::sync::mpsc::channel::<WalkOutcome>();
    let evaluator = std::sync::Arc::new(evaluator.clone());
    let analysis_root = std::sync::Arc::new(analysis_root.to_path_buf());
    let allowed_root = std::sync::Arc::new(allowed_root.to_path_buf());
    let mut outstanding = 0usize;
    for path in &orphans {
        if !claimed.insert(path.clone()) {
            continue;
        }
        outstanding += 1;
        pool.send(WalkJob {
            path: path.clone(),
            module_path: crate::module_path_for_file(package_ctx, path),
            target_name: package_ctx.package_name.clone(),
            target_kind: "unknown".to_string(),
            orphan: true,
            evaluator: std::sync::Arc::clone(&evaluator),
            analysis_root: std::sync::Arc::clone(&analysis_root),
            allowed_root: std::sync::Arc::clone(&allowed_root),
            edition_2021,
            reply: reply.clone(),
        });
    }
    let mut orphan_notes = Vec::with_capacity(outstanding);
    while outstanding > 0 {
        match replies.recv() {
            Ok(WalkOutcome::Done(file)) => {
                outstanding -= 1;
                let file = *file;
                walked.insert(file.path.clone(), file);
            }
            // A worker that panicked on a file re-raises here, the way the
            // analysis pool's joins do.
            Ok(WalkOutcome::Panicked(panic)) => std::panic::resume_unwind(panic),
            Err(_) => break,
        }
    }
    for path in &orphans {
        orphan_notes.push(ModuleTreeNote {
            message: "file is not reachable from any crate root; module path derived from the \
                      file path"
                .to_string(),
            file_path: Some(path.clone()),
        });
    }
    root_notes.push(orphan_notes);

    // The tree is returned in path order, as before; the notes come out in
    // walk order, roots and orphans included.
    let mut files: Vec<WalkedFile> = walked.into_values().collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    for file in files {
        tree.files.push(DiscoveredFile {
            path: file.path,
            module_path: file.module_path,
            target_name: file.target_name,
            target_kind: file.target_kind,
            orphan: file.orphan,
        });
        tree.sources.push(file.source);
        tree.prepasses.push(file.prepass);
    }
    for notes in root_notes {
        tree.notes.extend(notes);
    }
    Ok(tree)
}

/// Walks one crate root to its end and returns its notes in the order the
/// sequential depth-first walk pushed them.
///
/// The pool reads and parses every file the root can reach, each once,
/// under the module path of whichever `mod` item reached it first in
/// completion order. Nothing is claimed while the pool runs: once it has
/// drained, [`replay_file`] walks the results depth first, claims each file
/// at the point the sequential walk claimed it, and keeps it under that
/// module path. A file shared with an earlier root is therefore left to that
/// root, and a file reachable along two paths belongs to the path the
/// depth-first order reaches first, whatever order the workers finished in.
#[allow(clippy::too_many_arguments)]
fn walk_root(
    pool: &DiscoveryPool,
    root: &CrateRoot,
    root_path: &Path,
    evaluator: &CfgEvaluator,
    edition_2021: bool,
    analysis_root: &Path,
    allowed_root: &Path,
    claimed: &mut HashSet<PathBuf>,
    walked: &mut HashMap<PathBuf, WalkedFile>,
) -> Vec<ModuleTreeNote> {
    let (reply, replies) = std::sync::mpsc::channel::<WalkOutcome>();
    let shared_evaluator = std::sync::Arc::new(evaluator.clone());
    let shared_analysis_root = std::sync::Arc::new(analysis_root.to_path_buf());
    let shared_allowed_root = std::sync::Arc::new(allowed_root.to_path_buf());
    let job = |path: PathBuf, module_path: Vec<String>| WalkJob {
        path,
        module_path,
        target_name: root.target_name.clone(),
        target_kind: root.target_kind.clone(),
        orphan: false,
        evaluator: std::sync::Arc::clone(&shared_evaluator),
        analysis_root: std::sync::Arc::clone(&shared_analysis_root),
        allowed_root: std::sync::Arc::clone(&shared_allowed_root),
        edition_2021,
        reply: reply.clone(),
    };

    // Each reachable file is parsed once, under the first module path the
    // coordinator saw for it. Files an earlier root claimed are not parsed
    // again: the replay stops at them.
    let mut parsed: HashMap<PathBuf, WalkedFile> = HashMap::new();
    let mut enqueued: HashSet<PathBuf> = HashSet::new();
    let mut outstanding = 0usize;
    if !claimed.contains(root_path) {
        enqueued.insert(root_path.to_path_buf());
        outstanding += 1;
        pool.send(job(root_path.to_path_buf(), Vec::new()));
    }
    while outstanding > 0 {
        match replies.recv() {
            Ok(WalkOutcome::Done(file)) => {
                outstanding -= 1;
                let file = *file;
                let mut to_visit: Vec<(Vec<String>, PathBuf)> = Vec::new();
                collect_file_children(&file.children, &file.module_path, &mut to_visit);
                for (module_path, path) in to_visit {
                    if !claimed.contains(&path) && enqueued.insert(path.clone()) {
                        outstanding += 1;
                        pool.send(job(path, module_path));
                    }
                }
                parsed.insert(file.path.clone(), file);
            }
            // A worker that panicked on a file re-raises here, the way the
            // analysis pool's joins do.
            Ok(WalkOutcome::Panicked(panic)) => std::panic::resume_unwind(panic),
            Err(_) => break,
        }
    }

    let mut replay = Replay {
        root,
        evaluator,
        edition_2021,
        analysis_root,
        allowed_root,
        claimed,
        parsed,
        walked,
        notes: Vec::new(),
    };
    replay.file(root_path, Vec::new());
    replay.notes
}

/// Collects the out-of-line children a walk would visit next, in walk
/// order, each with the module path it is visited under.
fn collect_file_children(
    children: &[WalkedChild],
    module_path: &[String],
    out: &mut Vec<(Vec<String>, PathBuf)>,
) {
    for child in children {
        match child {
            WalkedChild::Inline { name, nested } => {
                let mut nested_path = module_path.to_vec();
                nested_path.push(name.clone());
                collect_file_children(nested, &nested_path, out);
            }
            WalkedChild::File { name, path } => {
                let mut child_path = module_path.to_vec();
                child_path.push(name.clone());
                out.push((child_path, path.clone()));
            }
            WalkedChild::Unresolved { .. } => {}
        }
    }
}

/// The depth-first pass over one root's parsed files that decides which
/// files the root owns and under which module path, and records the notes
/// in the order the sequential walk pushed them.
struct Replay<'a> {
    root: &'a CrateRoot,
    evaluator: &'a CfgEvaluator,
    edition_2021: bool,
    analysis_root: &'a Path,
    allowed_root: &'a Path,
    claimed: &'a mut HashSet<PathBuf>,
    parsed: HashMap<PathBuf, WalkedFile>,
    walked: &'a mut HashMap<PathBuf, WalkedFile>,
    notes: Vec<ModuleTreeNote>,
}

impl Replay<'_> {
    /// Claims `path` under `module_path` unless an earlier walk claimed it,
    /// then records its read failure and descends into its `mod` items.
    fn file(&mut self, path: &Path, module_path: Vec<String>) {
        if !self.claimed.insert(path.to_path_buf()) {
            return;
        }
        let mut file = match self.parsed.remove(path) {
            Some(file) if file.module_path == module_path => file,
            // The pool parsed this file under another `mod` item that the
            // depth-first order reaches later. The pre-pass and the notes
            // depend on the module path, so the file is walked again here
            // under the path it keeps. This second parse is left out of the
            // file work counters, which would otherwise depend on the order
            // the workers finished in.
            _ => {
                let (source, prepass, children, read_error) = walk_one_file(
                    path,
                    &module_path,
                    self.evaluator,
                    self.analysis_root,
                    self.allowed_root,
                    self.edition_2021,
                    false,
                );
                WalkedFile {
                    path: path.to_path_buf(),
                    module_path,
                    target_name: self.root.target_name.clone(),
                    target_kind: self.root.target_kind.clone(),
                    orphan: false,
                    source,
                    prepass,
                    children,
                    read_error,
                }
            }
        };
        if let Some(error) = &file.read_error {
            self.notes.push(ModuleTreeNote {
                message: format!("could not read module file: {error}"),
                file_path: Some(file.path.clone()),
            });
        }
        let children = std::mem::take(&mut file.children);
        let module_path = file.module_path.clone();
        self.walked.insert(path.to_path_buf(), file);
        self.children(path, &children, &module_path);
    }

    fn children(&mut self, owner: &Path, children: &[WalkedChild], module_path: &[String]) {
        for child in children {
            match child {
                WalkedChild::Inline { name, nested } => {
                    let mut nested_path = module_path.to_vec();
                    nested_path.push(name.clone());
                    self.children(owner, nested, &nested_path);
                }
                WalkedChild::Unresolved { name, declared_in } => self.notes.push(ModuleTreeNote {
                    message: format!(
                        "could not resolve `mod {name};` declared in module path `{}`",
                        if declared_in.is_empty() {
                            "<crate root>".to_string()
                        } else {
                            declared_in.join("::")
                        }
                    ),
                    file_path: Some(owner.to_path_buf()),
                }),
                WalkedChild::File { name, path } => {
                    let mut child_path = module_path.to_vec();
                    child_path.push(name.clone());
                    self.file(path, child_path);
                }
            }
        }
    }
}

/// One `mod` item a walk task saw, in declaration order, with what the walk
/// would have done about it.
enum WalkedChild {
    /// An inline module: its `mod` items live in the same file.
    Inline {
        name: String,
        nested: Vec<WalkedChild>,
    },
    /// An out-of-line module resolved to a file.
    File { name: String, path: PathBuf },
    /// An out-of-line module that resolved to no file.
    Unresolved {
        name: String,
        declared_in: Vec<String>,
    },
}

/// What one walk task produced for its file.
struct WalkedFile {
    path: PathBuf,
    module_path: Vec<String>,
    target_name: String,
    target_kind: String,
    orphan: bool,
    /// The file's text, `None` where it could not be read, so the analysis
    /// pass reads it again and reports the failure there.
    source: Option<String>,
    prepass: MacroFilePrepass,
    /// The file's `mod` items in declaration order.
    children: Vec<WalkedChild>,
    /// The read error, when the file could not be read.
    read_error: Option<String>,
}

/// A read, parse, and pre-pass of one discovered file.
struct WalkJob {
    path: PathBuf,
    module_path: Vec<String>,
    target_name: String,
    target_kind: String,
    /// True for a file the orphan sweep picked up, which no crate root
    /// reached and whose module path is derived from its location.
    orphan: bool,
    evaluator: std::sync::Arc<CfgEvaluator>,
    analysis_root: std::sync::Arc<PathBuf>,
    allowed_root: std::sync::Arc<PathBuf>,
    edition_2021: bool,
    reply: std::sync::mpsc::Sender<WalkOutcome>,
}

/// What a worker sends back for one [`WalkJob`]. The result is boxed so the
/// rare panic variant does not carry the size of a whole file's walk.
enum WalkOutcome {
    Done(Box<WalkedFile>),
    /// The worker panicked on this file. The coordinator re-raises the way
    /// the analysis pool's joins do.
    Panicked(Box<dyn std::any::Any + Send>),
}

impl WalkJob {
    fn run(self) {
        let WalkJob {
            path,
            module_path,
            target_name,
            target_kind,
            orphan,
            evaluator,
            analysis_root,
            allowed_root,
            edition_2021,
            reply,
        } = self;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            walk_one_file(
                &path,
                &module_path,
                &evaluator,
                &analysis_root,
                &allowed_root,
                edition_2021,
                true,
            )
        }));
        let outcome = match outcome {
            Ok((source, prepass, children, read_error)) => {
                WalkOutcome::Done(Box::new(WalkedFile {
                    path,
                    module_path,
                    target_name,
                    target_kind,
                    orphan,
                    source,
                    prepass,
                    children,
                    read_error,
                }))
            }
            Err(panic) => WalkOutcome::Panicked(panic),
        };
        let _ = reply.send(outcome);
    }
}

/// Reads one module file, parses it once for both the `mod` structure and
/// the macro pre-pass, and records what the walk would do about each `mod`
/// item. The text is kept for the analysis pass, which parses the file a
/// second time from it: holding the text (a few tens of megabytes for a
/// whole dependency closure) is far cheaper than holding parsed trees,
/// which `syn` spans could not hand across threads anyway.
#[allow(clippy::type_complexity)]
fn walk_one_file(
    path: &Path,
    module_path: &[String],
    evaluator: &CfgEvaluator,
    analysis_root: &Path,
    allowed_root: &Path,
    edition_2021: bool,
    count: bool,
) -> (
    Option<String>,
    MacroFilePrepass,
    Vec<WalkedChild>,
    Option<String>,
) {
    // An unreadable or non-UTF-8 file must not abort the whole run: the file
    // itself is recorded, discovery just cannot descend through it, exactly
    // as for a parse failure below.
    let source = match fs::read_to_string(path) {
        Ok(source) => {
            if count {
                crate::stats::FileWorkPhase::Discovery.count_read();
            }
            source
        }
        Err(error) => {
            return (
                None,
                MacroFilePrepass::default(),
                Vec::new(),
                Some(error.to_string()),
            );
        }
    };
    // A parse failure here is reported by the analysis pass, which parses
    // the same file; discovery just cannot descend any further.
    let syntax = match syn::parse_file(&source) {
        Ok(syntax) => {
            if count {
                crate::stats::FileWorkPhase::Discovery.count_parsed();
            }
            syntax
        }
        Err(_) => return (Some(source), MacroFilePrepass::default(), Vec::new(), None),
    };
    let relative = crate::relative_display_path(analysis_root, path);
    let prepass =
        macro_expand::prepass_from_parsed(&syntax, module_path, &relative, evaluator, edition_2021);
    // Only `walk_root` starts with an empty module path, so this is exactly
    // the crate-root test, and rustc's rule is positional, not by filename:
    // a crate root owns its own directory whatever it is called.
    let child_dir = child_module_dir(path, module_path.is_empty());
    // `#[path]` on a module *not* inside an inline block is relative to the
    // directory the declaring file sits in, which is not the directory its
    // pathless children live in: for `src/foo.rs` those are `src/foo/` but a
    // `#[path = "explicit.rs"]` there means `src/explicit.rs`. The two
    // coincide for crate roots and `mod.rs`, which is why the distinction
    // stayed invisible.
    let attr_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let children = collect_children(
        &syntax.items,
        &child_dir,
        &attr_dir,
        module_path,
        allowed_root,
        evaluator,
    );
    (Some(source), prepass, children, None)
}

/// Records what the walk would do about each `mod` item, in declaration
/// order, resolving out-of-line modules the way the walk resolves them.
fn collect_children(
    items: &[syn::Item],
    child_dir: &Path,
    attr_dir: &Path,
    module_path: &[String],
    allowed_root: &Path,
    evaluator: &CfgEvaluator,
) -> Vec<WalkedChild> {
    let mut children = Vec::new();
    for item in items {
        let syn::Item::Mod(item_mod) = item else {
            continue;
        };
        if !evaluator.attrs_enabled(&item_mod.attrs) {
            continue;
        }
        let name = item_mod.ident.to_string();
        let mut nested_path = module_path.to_vec();
        nested_path.push(name.clone());

        match &item_mod.content {
            // An inline module's own out-of-line children live in a
            // directory named after it.
            // Inside an inline block both bases are the same directory: the
            // inline module's name becomes a path component for its
            // out-of-line children and for a `#[path]` alike.
            Some((_, nested_items)) => {
                let nested_dir = child_dir.join(&name);
                children.push(WalkedChild::Inline {
                    name,
                    nested: collect_children(
                        nested_items,
                        &nested_dir,
                        &nested_dir,
                        &nested_path,
                        allowed_root,
                        evaluator,
                    ),
                });
            }
            None => match resolve_module_file(item_mod, child_dir, attr_dir, &name, allowed_root) {
                Some(path) => children.push(WalkedChild::File { name, path }),
                None => children.push(WalkedChild::Unresolved {
                    name,
                    declared_in: module_path.to_vec(),
                }),
            },
        }
    }
    children
}

/// Canonicalizes a candidate module file and accepts it only when it is a
/// real (non-symlink) file inside the package directory.
fn contained_file(path: &Path, allowed_root: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    canonical.starts_with(allowed_root).then_some(canonical)
}

/// `#[path = "..."]` wins, resolved against `attr_dir`; otherwise
/// `child_dir/name.rs` then `child_dir/name/mod.rs`.
fn resolve_module_file(
    item_mod: &syn::ItemMod,
    child_dir: &Path,
    attr_dir: &Path,
    name: &str,
    allowed_root: &Path,
) -> Option<PathBuf> {
    if let Some(path_attr) = module_path_attr(item_mod) {
        return contained_file(&attr_dir.join(path_attr), allowed_root);
    }
    if let Some(flat) = contained_file(&child_dir.join(format!("{name}.rs")), allowed_root) {
        return Some(flat);
    }
    contained_file(&child_dir.join(name).join("mod.rs"), allowed_root)
}

/// Workers that read, parse, and pre-pass one discovered file per task.
///
/// One pool is shared by every package of a planning phase, so a package
/// with a single huge crate no longer serializes the front of the pipeline
/// behind it. The workers own no state: each task carries everything it
/// needs and sends its result to the coordinator that enqueued it.
pub(crate) struct DiscoveryPool {
    tx: Option<std::sync::mpsc::Sender<WalkJob>>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl DiscoveryPool {
    /// Spawns `workers` walk workers.
    pub(crate) fn spawn(workers: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<WalkJob>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        let workers = (0..workers.max(1))
            .map(|_| {
                let rx = std::sync::Arc::clone(&rx);
                std::thread::Builder::new()
                    .name("rusi-discovery".to_string())
                    .stack_size(crate::analysis_stack_size())
                    .spawn(move || {
                        loop {
                            let received = match rx.lock() {
                                Ok(received) => received,
                                // The queue mutex is only poisoned by another
                                // worker dying while holding it; this worker
                                // exits and the pool's drop reports the panic.
                                Err(_) => return,
                            };
                            let job = match received.recv() {
                                Ok(job) => job,
                                Err(_) => return,
                            };
                            drop(received);
                            job.run();
                        }
                    })
                    .expect("failed to spawn a discovery worker")
            })
            .collect();
        Self {
            tx: Some(tx),
            workers,
        }
    }

    /// Hands one file task to a worker. A worker that died mid-run closes
    /// the queue and the send returns the job, which then runs on the
    /// caller's thread so discovery still completes; the pool's drop
    /// reports the panic that closed the queue.
    fn send(&self, job: WalkJob) {
        if let Some(tx) = &self.tx
            && let Err(failed) = tx.send(job)
        {
            failed.0.run();
        }
    }
}

impl Drop for DiscoveryPool {
    fn drop(&mut self) {
        // Closing the queue lets the workers finish and exit; the joins
        // surface a worker panic the way the analysis pool does.
        self.tx = None;
        for worker in self.workers.drain(..) {
            if let Err(panic) = worker.join() {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

/// The directory that holds a module file's out-of-line children. A crate root
/// and `mod.rs` own their own directory; `foo.rs` owns `foo/`.
///
/// Crate-root status is positional, not a matter of filename: `src/bin/tool.rs`
/// and a `[lib] path = "src/custom.rs"` are roots that own their directory just
/// as `lib.rs` does, so `mod shared;` in either resolves next to the root.
fn child_module_dir(path: &Path, is_crate_root: bool) -> PathBuf {
    let parent = path.parent().unwrap_or(Path::new("."));
    if is_crate_root {
        return parent.to_path_buf();
    }
    match path.file_name().and_then(|name| name.to_str()) {
        Some("mod.rs") => parent.to_path_buf(),
        _ => match path.file_stem().and_then(|stem| stem.to_str()) {
            Some(stem) => parent.join(stem),
            None => parent.to_path_buf(),
        },
    }
}

/// Reads the literal form of `#[path = "..."]`.
fn module_path_attr(item_mod: &syn::ItemMod) -> Option<String> {
    for attr in &item_mod.attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        if let syn::Meta::NameValue(name_value) = &attr.meta
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) = &name_value.value
        {
            return Some(value.value());
        }
    }
    None
}

/// Sweeps the package for `.rs` files no crate root reached.
fn collect_orphans(
    package_ctx: &PackageContext,
    claimed: &HashSet<PathBuf>,
    include_tests: bool,
) -> Result<Vec<PathBuf>> {
    let mut orphans = Vec::new();
    for path in crate::discover_rust_files(package_ctx, include_tests)? {
        if !claimed.contains(&path) {
            orphans.push(path);
        }
    }
    orphans.sort();
    Ok(orphans)
}

/// The crate name that roots every qualified name in `file`.
///
/// A library target is the package's own crate; every `bin`, `example`, or
/// `test` target is a separate crate that happens to live in the same package,
/// so it must root its qualified names at its own name. Otherwise two
/// `src/bin/*.rs` files both define a crate-root `main` under the package name
/// and collide on declaration ids.
pub(crate) fn crate_path(package_ctx: &PackageContext, file: &DiscoveredFile) -> String {
    match file.target_kind.as_str() {
        "bin" | "example" | "test" | "bench" => file.target_name.replace('-', "_"),
        // Library kinds, and orphan files we could not attribute to a target,
        // belong to the package crate.
        _ => package_ctx.crate_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusi_schema::ModuleRef;
    use std::io::Write;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("rusi-module-tree-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).expect("fixture dirs");
            Self { root }
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent");
            }
            let mut file = fs::File::create(&path).expect("fixture file");
            file.write_all(contents.as_bytes()).expect("fixture write");
            crate::canonical_path(&path)
        }

        fn package_ctx(&self) -> PackageContext {
            let manifest_path = self.root.join("Cargo.toml");
            PackageContext {
                workspace_member: true,
                package_name: "fixture".to_string(),
                crate_name: "fixture".to_string(),
                manifest_path: manifest_path.clone(),
                root_dir: crate::canonical_path(&self.root),
                src_dir: self.root.join("src"),
                module_ref: ModuleRef {
                    name: "fixture".to_string(),
                    version: "0.0.0".to_string(),
                    manifest_path: manifest_path.display().to_string(),
                    workspace_member: true,
                },
            }
        }

        fn lib_root(&self) -> CrateRoot {
            CrateRoot {
                target_name: "fixture".to_string(),
                target_kind: "lib".to_string(),
                path: self.root.join("src").join("lib.rs"),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn module_path_of(tree: &ModuleTree, path: &Path) -> Option<Vec<String>> {
        tree.files
            .iter()
            .find(|file| file.path == path)
            .map(|file| file.module_path.clone())
    }

    #[test]
    fn follows_mod_declarations_and_nested_dirs() {
        let fixture = Fixture::new("nested");
        fixture.write("src/lib.rs", "mod flat;\nmod nested;\n");
        let flat = fixture.write("src/flat.rs", "pub fn flat() {}\n");
        fixture.write("src/nested/mod.rs", "mod leaf;\n");
        let leaf = fixture.write("src/nested/leaf.rs", "pub fn leaf() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(module_path_of(&tree, &flat), Some(vec!["flat".to_string()]));
        assert_eq!(
            module_path_of(&tree, &leaf),
            Some(vec!["nested".to_string(), "leaf".to_string()])
        );
        assert!(tree.files.iter().all(|file| !file.orphan));
    }

    #[test]
    fn path_attribute_overrides_the_file_layout() {
        let fixture = Fixture::new("path-attr");
        fixture.write(
            "src/lib.rs",
            "#[path = \"generated/impl_v2.rs\"]\nmod api;\n",
        );
        let target = fixture.write("src/generated/impl_v2.rs", "pub fn call() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        // The old path-derived scheme would have called this
        // `generated::impl_v2`.
        assert_eq!(
            module_path_of(&tree, &target),
            Some(vec!["api".to_string()])
        );
    }

    #[test]
    fn inline_modules_own_a_directory_of_children() {
        let fixture = Fixture::new("inline");
        fixture.write("src/lib.rs", "mod outer { mod inner; }\n");
        let inner = fixture.write("src/outer/inner.rs", "pub fn inner() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &inner),
            Some(vec!["outer".to_string(), "inner".to_string()])
        );
    }

    #[test]
    fn cfg_disabled_module_declarations_are_not_followed() {
        let fixture = Fixture::new("cfg-mod");
        fixture.write("src/lib.rs", "#[cfg(windows)] mod win;\nmod portable;\n");
        let win = fixture.write("src/win.rs", "pub fn win() {}\n");
        let portable = fixture.write("src/portable.rs", "pub fn portable() {}\n");

        let mut options = crate::cfg::CfgOptions::default();
        options.insert_atom("unix");
        let evaluator = CfgEvaluator::new(options, false);

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &evaluator,
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &portable),
            Some(vec!["portable".to_string()])
        );
        // Still reported, but as an orphan, so the platform-specific code is
        // visible without being attributed to an active module path.
        let win_entry = tree
            .files
            .iter()
            .find(|file| file.path == win)
            .expect("disabled module file is still swept up");
        assert!(win_entry.orphan);
    }

    #[test]
    fn unreachable_files_are_flagged_as_orphans() {
        let fixture = Fixture::new("orphan");
        fixture.write("src/lib.rs", "mod used;\n");
        fixture.write("src/used.rs", "pub fn used() {}\n");
        let stray = fixture.write("src/stray.rs", "pub fn stray() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        let stray_entry = tree
            .files
            .iter()
            .find(|file| file.path == stray)
            .expect("stray file is reported");
        assert!(stray_entry.orphan);
        assert!(
            tree.notes
                .iter()
                .any(|note| note.file_path.as_deref().is_some_and(|path| path == stray))
        );
    }

    #[test]
    fn unresolved_module_declarations_are_reported() {
        let fixture = Fixture::new("unresolved");
        let lib = fixture.write("src/lib.rs", "mod missing;\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert!(tree.notes.iter().any(|note| {
            note.message.contains("mod missing;") && note.file_path.as_deref() == Some(&lib)
        }));
    }

    #[test]
    fn a_bin_crate_root_owns_its_own_directory() {
        let fixture = Fixture::new("bin-root");
        fixture.write("src/bin/tool.rs", "mod shared;\n");
        let shared = fixture.write("src/bin/shared.rs", "pub fn helper() {}\n");

        let ctx = fixture.package_ctx();
        let root = CrateRoot {
            target_name: "tool".to_string(),
            target_kind: "bin".to_string(),
            path: fixture.root.join("src").join("bin").join("tool.rs"),
        };
        let tree = discover(
            &ctx,
            &[root],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        // Crate-root status is positional: `tool.rs` is a root, so its children
        // sit beside it, not in `src/bin/tool/`.
        assert_eq!(
            module_path_of(&tree, &shared),
            Some(vec!["shared".to_string()])
        );
    }

    #[test]
    fn an_unreadable_module_file_is_reported_rather_than_fatal() {
        let fixture = Fixture::new("unreadable");
        fixture.write("src/lib.rs", "mod raw;\nmod good;\n");
        let good = fixture.write("src/good.rs", "pub fn good() {}\n");
        // Invalid UTF-8, so `read_to_string` fails on a file that exists.
        let raw = fixture.root.join("src").join("raw.rs");
        fs::write(&raw, [0x66u8, 0x6e, 0x20, 0xff, 0xfe]).expect("fixture write");
        let raw = crate::canonical_path(&raw);

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds despite the unreadable file");

        assert!(
            tree.notes
                .iter()
                .any(|note| note.file_path.as_deref() == Some(&raw)
                    && note.message.contains("could not read"))
        );
        // The rest of the tree is still discovered.
        assert_eq!(module_path_of(&tree, &good), Some(vec!["good".to_string()]));
    }

    #[test]
    fn path_attribute_in_a_non_root_file_resolves_beside_that_file() {
        let fixture = Fixture::new("path-attr-nested");
        fixture.write("src/lib.rs", "mod foo;\n");
        fixture.write("src/foo.rs", "#[path = \"explicit.rs\"] mod n;\n");
        // Both candidates exist, so this discriminates between the two bases
        // rather than just detecting a miss. rustc resolves a `#[path]` outside
        // an inline block against the declaring file's own directory, so
        // `src/explicit.rs` wins and `src/foo/explicit.rs` is untouched.
        let beside = fixture.write("src/explicit.rs", "pub fn from_top() {}\n");
        let below = fixture.write("src/foo/explicit.rs", "pub fn from_subdir() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &beside),
            Some(vec!["foo".to_string(), "n".to_string()])
        );
        // The unreached file is still reported, as an orphan.
        assert!(
            tree.files
                .iter()
                .find(|file| file.path == below)
                .is_some_and(|file| file.orphan)
        );
    }

    #[test]
    fn path_attribute_inside_an_inline_module_resolves_below_it() {
        let fixture = Fixture::new("path-attr-inline");
        fixture.write("src/lib.rs", "mod foo;\n");
        fixture.write(
            "src/foo.rs",
            "pub mod a { #[path = \"b.rs\"] pub mod b; }\n",
        );
        // Inside an inline block the inline module's name is part of the base,
        // so this is `src/foo/a/b.rs` — not `src/b.rs`.
        let nested = fixture.write("src/foo/a/b.rs", "pub fn deep() {}\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &nested),
            Some(vec!["foo".to_string(), "a".to_string(), "b".to_string()])
        );
    }

    /// The one parse discovery makes feeds both the `mod` walk and the macro
    /// pre-pass. This pins what the merge promises: every discovered file
    /// carries its pre-pass and its text in the same order, definitions come
    /// out of files reached through `#[path]` modules, a cfg-disabled module
    /// contributes no definitions, and an orphan file still has both, so the
    /// scope table sees exactly what the separate pre-pass used to collect.
    #[test]
    fn prepass_items_and_sources_travel_with_the_discovered_files() {
        let fixture = Fixture::new("prepass-alignment");
        fixture.write(
            "src/lib.rs",
            "#[macro_use]\nmod macros;\n#[path = \"extras/renamed.rs\"]\nmod renamed;\n\
             #[cfg(windows)]\nmod disabled;\n",
        );
        let macros_rs = fixture.write("src/macros.rs", "macro_rules! shout { () => {} }\n");
        let renamed_rs =
            fixture.write("src/extras/renamed.rs", "macro_rules! quiet { () => {} }\n");
        let disabled_rs = fixture.write("src/disabled.rs", "macro_rules! gone { () => {} }\n");
        let stray = fixture.write("src/stray.rs", "macro_rules! stray { () => {} }\n");

        // A gate the evaluator can definitively false, as the cfg test below
        // does, so the disabled module is really skipped.
        let mut options = crate::cfg::CfgOptions::default();
        options.insert_atom("unix");
        let evaluator = CfgEvaluator::new(options, false);

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &evaluator,
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            tree.files.len(),
            tree.prepasses.len(),
            "one pre-pass result per discovered file"
        );
        assert_eq!(
            tree.files.len(),
            tree.sources.len(),
            "one text slot per discovered file"
        );

        let index_of = |path: &Path| -> usize {
            tree.files
                .iter()
                .position(|file| file.path == path)
                .expect("the file was discovered")
        };
        let definitions_of = |path: &Path| -> Vec<String> {
            tree.prepasses[index_of(path)]
                .definitions
                .iter()
                .map(|definition| definition.name.clone())
                .collect()
        };

        assert_eq!(definitions_of(&macros_rs), vec!["shout".to_string()]);
        assert_eq!(
            definitions_of(&renamed_rs),
            vec!["quiet".to_string()],
            "definitions are collected from a file reached through `#[path]`"
        );

        // The cfg-disabled module is not followed, so its file is an orphan;
        // its macro is not in scope anywhere, but the file itself still
        // carries its pre-pass and its text like every other file.
        assert_eq!(definitions_of(&disabled_rs), vec!["gone".to_string()]);
        let disabled_entry = &tree.files[index_of(&disabled_rs)];
        assert!(disabled_entry.orphan);

        let stray_index = index_of(&stray);
        assert_eq!(
            tree.prepasses[stray_index].definitions[0].name, "stray",
            "an orphan's definitions are collected from the same read"
        );
        assert!(tree.sources[stray_index].is_some());

        // Every discovered, readable file left its text for the analysis pass.
        for (file, source) in tree.files.iter().zip(&tree.sources) {
            assert!(source.is_some(), "no text kept for {}", file.path.display());
        }
    }

    /// `#[macro_use]` on a `mod` extends the child's macros past the item, so
    /// the definitions, the declaring `mod` item and its attribute must all
    /// come out of the same merged walk for the scope table to see them.
    #[test]
    fn macro_use_mod_items_reach_the_prepass_from_the_merged_walk() {
        let fixture = Fixture::new("macro-use-prepass");
        let lib_rs = fixture.write(
            "src/lib.rs",
            "#[macro_use]\nmod macros;\nfn run() { shout!(); }\n",
        );
        let macros_rs = fixture.write("src/macros.rs", "macro_rules! shout { () => {} }\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        let lib_index = tree
            .files
            .iter()
            .position(|file| file.path == lib_rs)
            .expect("the crate root was discovered");
        let prepass = &tree.prepasses[lib_index];
        let declaration = prepass
            .mods
            .iter()
            .find(|declaration| declaration.name == "macros")
            .expect("the `mod` declaration was collected");
        assert!(
            declaration.macro_use,
            "the `#[macro_use]` attribute of the `mod` item is kept"
        );
        let macros_index = tree
            .files
            .iter()
            .position(|file| file.path == macros_rs)
            .expect("the child module was discovered");
        assert!(
            tree.prepasses[macros_index]
                .definitions
                .iter()
                .any(|definition| definition.name == "shout"),
            "the child module's definitions were collected in the same walk"
        );
    }

    /// A file reachable along two `mod` paths belongs to the one the
    /// depth-first walk reaches first, whatever order the pool finishes in:
    /// `a` and everything below it come before the root's next item `b`.
    #[test]
    fn a_file_reached_twice_keeps_the_depth_first_module_path() {
        let fixture = Fixture::new("reached-twice");
        fixture.write("src/lib.rs", "mod a;\n#[path = \"shared.rs\"]\nmod b;\n");
        fixture.write("src/a.rs", "#[path = \"shared.rs\"]\nmod inner;\n");
        let shared = fixture.write("src/shared.rs", "mod missing;\n");

        let ctx = fixture.package_ctx();
        let tree = discover(
            &ctx,
            &[fixture.lib_root()],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &shared),
            Some(vec!["a".to_string(), "inner".to_string()])
        );
        let unresolved: Vec<&ModuleTreeNote> = tree
            .notes
            .iter()
            .filter(|note| note.message.contains("mod missing;"))
            .collect();
        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        assert!(unresolved[0].message.contains("`a::inner`"));
    }

    /// A module shared by two crate roots is recorded once, under the first
    /// root, and the second root's walk stops at it without repeating its
    /// notes.
    #[test]
    fn a_module_shared_by_two_roots_is_walked_once() {
        let fixture = Fixture::new("shared-by-roots");
        fixture.write("src/lib.rs", "mod common;\n");
        fixture.write("src/main.rs", "mod common;\n");
        let common = fixture.write("src/common.rs", "mod missing;\n");

        let ctx = fixture.package_ctx();
        let bin_root = CrateRoot {
            target_name: "tool".to_string(),
            target_kind: "bin".to_string(),
            path: fixture.root.join("src").join("main.rs"),
        };
        let tree = discover(
            &ctx,
            &[fixture.lib_root(), bin_root],
            &CfgEvaluator::permissive(),
            false,
            &fixture.root,
            true,
        )
        .expect("discovery succeeds");

        let entry = tree
            .files
            .iter()
            .find(|file| file.path == common)
            .expect("the shared module was discovered");
        assert_eq!(entry.target_kind, "lib");
        let unresolved = tree
            .notes
            .iter()
            .filter(|note| note.message.contains("mod missing;"))
            .count();
        assert_eq!(unresolved, 1);
    }
}
