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

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use cargo_metadata::Package;

use crate::PackageContext;
use crate::cfg::CfgEvaluator;

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
#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleTree {
    pub(crate) files: Vec<DiscoveredFile>,
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

/// Walks every crate root of the package, then sweeps for orphan files.
pub(crate) fn discover(
    package_ctx: &PackageContext,
    roots: &[CrateRoot],
    evaluator: &CfgEvaluator,
    include_tests: bool,
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

    for root in roots {
        if !root.path.is_file() {
            tree.notes.push(ModuleTreeNote {
                message: format!(
                    "crate root for target `{}` does not exist: {}",
                    root.target_name,
                    root.path.display()
                ),
                file_path: None,
            });
            continue;
        }
        let mut walker = ModuleWalker {
            root,
            allowed_root: &allowed_root,
            evaluator,
            claimed: &mut claimed,
            files: &mut tree.files,
            notes: &mut tree.notes,
        };
        walker.walk_root()?;
    }

    let orphans = collect_orphans(package_ctx, &claimed, include_tests)?;
    for path in orphans {
        tree.notes.push(ModuleTreeNote {
            message: "file is not reachable from any crate root; module path derived from the \
                      file path"
                .to_string(),
            file_path: Some(path.clone()),
        });
        let module_path = crate::module_path_for_file(package_ctx, &path);
        tree.files.push(DiscoveredFile {
            path,
            module_path,
            target_name: package_ctx.package_name.clone(),
            target_kind: "unknown".to_string(),
            orphan: true,
        });
    }

    tree.files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(tree)
}

struct ModuleWalker<'a> {
    root: &'a CrateRoot,
    allowed_root: &'a Path,
    evaluator: &'a CfgEvaluator,
    claimed: &'a mut HashSet<PathBuf>,
    files: &'a mut Vec<DiscoveredFile>,
    notes: &'a mut Vec<ModuleTreeNote>,
}

impl ModuleWalker<'_> {
    fn walk_root(&mut self) -> Result<()> {
        let Some(path) = self.contained_file(&self.root.path) else {
            self.notes.push(ModuleTreeNote {
                message: format!(
                    "crate root for target `{}` resolves outside the package directory and was \
                     skipped: {}",
                    self.root.target_name,
                    self.root.path.display()
                ),
                file_path: None,
            });
            return Ok(());
        };
        self.walk_file(path, Vec::new())
    }

    /// Canonicalizes a candidate module file and accepts it only when it is a
    /// real (non-symlink) file inside the package directory.
    fn contained_file(&self, path: &Path) -> Option<PathBuf> {
        let metadata = fs::symlink_metadata(path).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        let canonical = fs::canonicalize(path).ok()?;
        canonical
            .starts_with(self.allowed_root)
            .then_some(canonical)
    }

    /// Parses one module file, records it, and follows the `mod` declarations
    /// it contains.
    ///
    /// The file is parsed here and again during full analysis. Extracting only
    /// the module structure now and re-parsing later keeps peak memory flat on
    /// large workspaces, at the cost of one extra `syn` parse per file; the
    /// analysis pass itself is far more expensive than the parse.
    fn walk_file(&mut self, path: PathBuf, module_path: Vec<String>) -> Result<()> {
        if !self.claimed.insert(path.clone()) {
            return Ok(());
        }
        self.files.push(DiscoveredFile {
            path: path.clone(),
            module_path: module_path.clone(),
            target_name: self.root.target_name.clone(),
            target_kind: self.root.target_kind.clone(),
            orphan: false,
        });

        // An unreadable or non-UTF-8 file must not abort the whole run: the file
        // itself is already recorded, discovery just cannot descend through it,
        // exactly as for a parse failure below.
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                self.notes.push(ModuleTreeNote {
                    message: format!("could not read module file: {error}"),
                    file_path: Some(path),
                });
                return Ok(());
            }
        };
        // A parse failure here is reported by the analysis pass, which parses
        // the same file; discovery just cannot descend any further.
        let Ok(syntax) = syn::parse_file(&source) else {
            return Ok(());
        };

        // Only `walk_root` starts with an empty module path, so this is exactly
        // the crate-root test — and rustc's rule is positional, not by filename:
        // a crate root owns its own directory whatever it is called.
        let child_dir = child_module_dir(&path, module_path.is_empty());
        // `#[path]` on a module *not* inside an inline block is relative to the
        // directory the declaring file sits in, which is not the directory its
        // pathless children live in: for `src/foo.rs` those are `src/foo/` but a
        // `#[path = "explicit.rs"]` there means `src/explicit.rs`. The two
        // coincide for crate roots and `mod.rs`, which is why the distinction
        // stayed invisible.
        let attr_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        self.walk_items(&syntax.items, &child_dir, &attr_dir, &module_path, &path)
    }

    fn walk_items(
        &mut self,
        items: &[syn::Item],
        child_dir: &Path,
        attr_dir: &Path,
        module_path: &[String],
        owner: &Path,
    ) -> Result<()> {
        for item in items {
            let syn::Item::Mod(item_mod) = item else {
                continue;
            };
            if !self.evaluator.attrs_enabled(&item_mod.attrs) {
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
                    self.walk_items(nested_items, &nested_dir, &nested_dir, &nested_path, owner)?;
                }
                None => match self.resolve_module_file(item_mod, child_dir, attr_dir, &name) {
                    Some(file) => self.walk_file(file, nested_path)?,
                    None => self.notes.push(ModuleTreeNote {
                        message: format!(
                            "could not resolve `mod {name};` declared in module path `{}`",
                            if module_path.is_empty() {
                                "<crate root>".to_string()
                            } else {
                                module_path.join("::")
                            }
                        ),
                        file_path: Some(owner.to_path_buf()),
                    }),
                },
            }
        }
        Ok(())
    }

    /// `#[path = "..."]` wins, resolved against `attr_dir`; otherwise
    /// `child_dir/name.rs` then `child_dir/name/mod.rs`.
    fn resolve_module_file(
        &self,
        item_mod: &syn::ItemMod,
        child_dir: &Path,
        attr_dir: &Path,
        name: &str,
    ) -> Option<PathBuf> {
        if let Some(path_attr) = module_path_attr(item_mod) {
            return self.contained_file(&attr_dir.join(path_attr));
        }
        if let Some(flat) = self.contained_file(&child_dir.join(format!("{name}.rs"))) {
            return Some(flat);
        }
        self.contained_file(&child_dir.join(name).join("mod.rs"))
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
        let tree =
            discover(&ctx, &[fixture.lib_root()], &evaluator, false).expect("discovery succeeds");

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
        let tree = discover(&ctx, &[root], &CfgEvaluator::permissive(), false)
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
        )
        .expect("discovery succeeds");

        assert_eq!(
            module_path_of(&tree, &nested),
            Some(vec!["foo".to_string(), "a".to_string(), "b".to_string()])
        );
    }
}
