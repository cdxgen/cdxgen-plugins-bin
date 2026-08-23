//! Import resolution: globs, re-exports, and relative path prefixes.
//!
//! The collector records imports as flat strings, so `use foo::*` used to reach
//! the report as the literal path `"foo::*"` and `pub use` re-exports were not
//! modeled at all. Anything called through a glob import or through a crate's
//! own facade module therefore stayed unresolved in the call graph.
//!
//! This module builds, per package:
//!
//! 1. an item table (module path -> declared item names) from the collected
//!    declarations,
//! 2. an alias table mapping `(module, local name) -> canonical path`, seeded
//!    from every `use` in the package,
//! 3. glob expansions, for globs whose target module is locally known,
//! 4. a fixed point over `pub use` chains, so a name re-exported through
//!    several facade modules resolves to the module that actually declares it.
//!
//! Call targets are then rewritten through the table before the call graph is
//! built. Paths whose first segment resolves to nothing are left exactly as
//! written: unresolved evidence is still evidence.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusi_schema::Declaration;

/// One `use` declaration, flattened to a single imported name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UseRecord {
    /// Module path (relative to the crate root) containing the `use`.
    pub(crate) module_path: Vec<String>,
    /// Path as written, minus any trailing `*`.
    pub(crate) path: String,
    pub(crate) alias: Option<String>,
    pub(crate) is_glob: bool,
    /// `pub use` (or `pub(crate) use`), i.e. a re-export.
    pub(crate) is_public: bool,
}

/// Flattens a `use` tree into one record per imported name.
pub(crate) fn collect_use_records(
    item_use: &syn::ItemUse,
    module_path: &[String],
    records: &mut Vec<UseRecord>,
) {
    let is_public = !matches!(item_use.vis, syn::Visibility::Inherited);
    flatten(
        &item_use.tree,
        String::new(),
        module_path,
        is_public,
        records,
    );
}

fn flatten(
    tree: &syn::UseTree,
    prefix: String,
    module_path: &[String],
    is_public: bool,
    records: &mut Vec<UseRecord>,
) {
    let join = |prefix: &str, segment: &str| {
        if prefix.is_empty() {
            segment.to_string()
        } else {
            format!("{prefix}::{segment}")
        }
    };
    match tree {
        syn::UseTree::Path(path) => flatten(
            &path.tree,
            join(&prefix, &path.ident.to_string()),
            module_path,
            is_public,
            records,
        ),
        // `use a::b::{self}` imports the module `a::b` itself under the name
        // `b`, and `{self as c}` under the name `c`. The `self` segment is not
        // part of the path: appending it would give `a::b::self`, which matches
        // no declaration.
        syn::UseTree::Name(name) => {
            if let Some(path) = leaf_path(&prefix, &name.ident.to_string()) {
                records.push(UseRecord {
                    module_path: module_path.to_vec(),
                    path,
                    alias: None,
                    is_glob: false,
                    is_public,
                });
            }
        }
        syn::UseTree::Rename(rename) => {
            if let Some(path) = leaf_path(&prefix, &rename.ident.to_string()) {
                records.push(UseRecord {
                    module_path: module_path.to_vec(),
                    path,
                    alias: Some(rename.rename.to_string()),
                    is_glob: false,
                    is_public,
                });
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten(item, prefix.clone(), module_path, is_public, records);
            }
        }
        syn::UseTree::Glob(_) => records.push(UseRecord {
            module_path: module_path.to_vec(),
            path: prefix,
            alias: None,
            is_glob: true,
            is_public,
        }),
    }
}

/// Full path of a leaf `use` item, resolving a `self` leaf to the prefix it
/// stands for. Returns `None` for a bare `self` leaf with no prefix, which is
/// not valid Rust.
fn leaf_path(prefix: &str, ident: &str) -> Option<String> {
    if ident == "self" {
        return (!prefix.is_empty()).then(|| prefix.to_string());
    }
    if prefix.is_empty() {
        Some(ident.to_string())
    } else {
        Some(format!("{prefix}::{ident}"))
    }
}

/// Module path -> names declared directly in that module.
#[derive(Debug, Clone, Default)]
pub(crate) struct ItemTable {
    modules: HashMap<String, BTreeSet<String>>,
}

impl ItemTable {
    /// Builds the table from collected declarations. A declaration's
    /// `qualified_name` is `<crate>::<module...>::<name>`, so the owning module
    /// is everything but the last segment.
    pub(crate) fn from_declarations(declarations: &[Declaration]) -> Self {
        let mut modules: HashMap<String, BTreeSet<String>> = HashMap::new();
        for declaration in declarations {
            let Some((module, name)) = declaration.qualified_name.rsplit_once("::") else {
                continue;
            };
            modules
                .entry(module.to_string())
                .or_default()
                .insert(name.to_string());
        }
        Self { modules }
    }

    fn names(&self, module: &str) -> Option<&BTreeSet<String>> {
        self.modules.get(module)
    }

    fn contains(&self, module: &str, name: &str) -> bool {
        self.names(module).is_some_and(|names| names.contains(name))
    }
}

/// Resolved import table for one package.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImportResolution {
    crate_name: String,
    /// `(module path, local name) -> canonical path`.
    aliases: HashMap<(String, String), String>,
    /// Globs we could not expand, kept so callers can report them.
    unexpanded_globs: BTreeSet<String>,
    /// Module paths declared in this package, so a call written against a
    /// sibling module (`service::entry`, needing no `use`) resolves too.
    known_modules: BTreeSet<String>,
}

impl ImportResolution {
    pub(crate) fn build(crate_name: &str, items: &ItemTable, records: &[UseRecord]) -> Self {
        let mut resolution = Self {
            crate_name: crate_name.to_string(),
            ..Self::default()
        };

        // Named imports first: a glob must never shadow an explicit import.
        for record in records.iter().filter(|record| !record.is_glob) {
            let module_key = resolution.module_key(&record.module_path);
            let Some(canonical) = resolution.normalize(&module_key, &record.path) else {
                continue;
            };
            let local_name = match &record.alias {
                Some(alias) => alias.clone(),
                None => last_segment(&record.path).to_string(),
            };
            resolution
                .aliases
                .insert((module_key, local_name), canonical);
        }

        for record in records.iter().filter(|record| record.is_glob) {
            let module_key = resolution.module_key(&record.module_path);
            let Some(target) = resolution.normalize(&module_key, &record.path) else {
                resolution.unexpanded_globs.insert(record.path.clone());
                continue;
            };
            match items.names(&target) {
                Some(names) => {
                    for name in names {
                        // An item declared in the importing module shadows the
                        // glob, so `fn run` here beats `use sinks::*` bringing
                        // in another `run`.
                        if items.contains(&module_key, name) {
                            continue;
                        }
                        resolution
                            .aliases
                            .entry((module_key.clone(), name.clone()))
                            .or_insert_with(|| format!("{target}::{name}"));
                    }
                }
                // An external crate's glob (`use anyhow::*`): we know the target
                // module but not its contents.
                None => {
                    resolution.unexpanded_globs.insert(format!("{target}::*"));
                }
            }
        }

        resolution.known_modules = items.modules.keys().cloned().collect();
        resolution.collapse_reexports(items);
        resolution
    }

    /// Follows `pub use` chains to a fixed point: if a canonical path names
    /// something that is itself an alias in its own module, keep going until we
    /// reach a module that actually declares the item.
    fn collapse_reexports(&mut self, items: &ItemTable) {
        let keys: Vec<(String, String)> = self.aliases.keys().cloned().collect();
        for key in keys {
            let mut current = self.aliases[&key].clone();
            let mut seen = HashSet::new();
            while let Some((module, name)) = current.rsplit_once("::") {
                if items.contains(module, name) {
                    // The declaring module: stop here.
                    break;
                }
                let Some(next) = self.aliases.get(&(module.to_string(), name.to_string())) else {
                    break;
                };
                if next == &current || !seen.insert(current.clone()) {
                    // Cyclic re-exports resolve to wherever we already are.
                    break;
                }
                current = next.clone();
            }
            self.aliases.insert(key, current);
        }
    }

    /// Turns a path as written into an absolute one. `crate::`/`self::`/
    /// `super::` are rewritten against the containing module; a leading segment
    /// matching the crate name is kept; anything else is an external crate path
    /// and is returned unchanged.
    fn normalize(&self, module_key: &str, path: &str) -> Option<String> {
        let mut segments: Vec<&str> = path.split("::").filter(|part| !part.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }
        let mut base: Vec<String> = Vec::new();
        match segments[0] {
            "crate" => {
                base.push(self.crate_name.clone());
                segments.remove(0);
            }
            "self" => {
                base.extend(module_key.split("::").map(str::to_string));
                segments.remove(0);
            }
            "super" => {
                base.extend(module_key.split("::").map(str::to_string));
                while segments.first() == Some(&"super") {
                    // Never pop past the crate root.
                    if base.len() <= 1 {
                        return None;
                    }
                    base.pop();
                    segments.remove(0);
                }
            }
            // `::foo` and plain external paths stay as written.
            _ => {}
        }
        base.extend(segments.iter().map(|segment| segment.to_string()));
        if base.is_empty() {
            return None;
        }
        Some(base.join("::"))
    }

    fn module_key(&self, module_path: &[String]) -> String {
        let mut segments = vec![self.crate_name.clone()];
        segments.extend(module_path.iter().cloned());
        segments.join("::")
    }

    /// Rewrites a path written inside `module_path` to its canonical form.
    /// Returns `None` when nothing is known about the leading segment.
    pub(crate) fn resolve_path(&self, module_path: &[String], path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }
        let module_key = self.module_key(module_path);
        let (first, rest) = match path.split_once("::") {
            Some((first, rest)) => (first, Some(rest)),
            None => (path, None),
        };

        // Relative prefixes are absolute facts about the path, independent of
        // any `use`, so they are resolved even with no matching alias.
        if matches!(first, "crate" | "self" | "super") {
            return self.normalize(&module_key, path);
        }

        let canonical = match self.aliases.get(&(module_key.clone(), first.to_string())) {
            Some(canonical) => canonical.clone(),
            // Not imported, but a module in scope needs no `use`: a path
            // starting at a child of the current module is already absolute
            // once the module prefix is restored.
            None => {
                let candidate = format!("{module_key}::{first}");
                if !self.known_modules.contains(&candidate) {
                    return None;
                }
                candidate
            }
        };
        Some(match rest {
            Some(rest) => format!("{canonical}::{rest}"),
            None => canonical,
        })
    }

    pub(crate) fn unexpanded_globs(&self) -> impl Iterator<Item = &str> {
        self.unexpanded_globs.iter().map(String::as_str)
    }
}

fn last_segment(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(qualified_name: &str) -> Declaration {
        Declaration {
            qualified_name: qualified_name.to_string(),
            ..Declaration::default()
        }
    }

    fn use_records(module_path: &[&str], source: &str) -> Vec<UseRecord> {
        let item_use: syn::ItemUse = syn::parse_str(source).expect("fixture parses");
        let module_path: Vec<String> = module_path.iter().map(|part| part.to_string()).collect();
        let mut records = Vec::new();
        collect_use_records(&item_use, &module_path, &mut records);
        records
    }

    #[test]
    fn named_imports_resolve_through_the_alias_table() {
        let items = ItemTable::from_declarations(&[declaration("app::api::client::Client")]);
        let records = use_records(&[], "use crate::api::client::Client;");
        let resolution = ImportResolution::build("app", &items, &records);

        assert_eq!(
            resolution.resolve_path(&[], "Client::connect").as_deref(),
            Some("app::api::client::Client::connect")
        );
    }

    #[test]
    fn renamed_imports_resolve_under_their_alias() {
        let items = ItemTable::from_declarations(&[declaration("app::api::Client")]);
        let records = use_records(&[], "use crate::api::Client as Api;");
        let resolution = ImportResolution::build("app", &items, &records);

        assert_eq!(
            resolution.resolve_path(&[], "Api::connect").as_deref(),
            Some("app::api::Client::connect")
        );
    }

    #[test]
    fn glob_imports_expand_against_the_local_item_table() {
        let items = ItemTable::from_declarations(&[
            declaration("app::sinks::run_query"),
            declaration("app::sinks::run_command"),
        ]);
        let records = use_records(&["handlers"], "use crate::sinks::*;");
        let resolution = ImportResolution::build("app", &items, &records);

        // Previously recorded as the literal path "crate::sinks::*" and never
        // connected to the callee.
        assert_eq!(
            resolution
                .resolve_path(&["handlers".to_string()], "run_query")
                .as_deref(),
            Some("app::sinks::run_query")
        );
        assert_eq!(
            resolution
                .resolve_path(&["handlers".to_string()], "run_command")
                .as_deref(),
            Some("app::sinks::run_command")
        );
    }

    #[test]
    fn external_globs_are_reported_rather_than_guessed() {
        let items = ItemTable::default();
        let records = use_records(&[], "use anyhow::*;");
        let resolution = ImportResolution::build("app", &items, &records);

        assert!(resolution.resolve_path(&[], "Context").is_none());
        assert_eq!(
            resolution.unexpanded_globs().collect::<Vec<_>>(),
            vec!["anyhow::*"]
        );
    }

    #[test]
    fn named_imports_win_over_globs() {
        let items = ItemTable::from_declarations(&[
            declaration("app::wide::run"),
            declaration("app::narrow::run"),
        ]);
        let mut records = use_records(&[], "use crate::narrow::run;");
        records.extend(use_records(&[], "use crate::wide::*;"));
        let resolution = ImportResolution::build("app", &items, &records);

        assert_eq!(
            resolution.resolve_path(&[], "run").as_deref(),
            Some("app::narrow::run")
        );
    }

    #[test]
    fn reexport_chains_collapse_to_the_declaring_module() {
        // `app::inner::execute` re-exported by `app::mid`, then by `app::facade`.
        let items = ItemTable::from_declarations(&[declaration("app::inner::execute")]);
        let mut records = use_records(&["mid"], "pub use crate::inner::execute;");
        records.extend(use_records(&["facade"], "pub use crate::mid::execute;"));
        records.extend(use_records(&[], "use crate::facade::execute;"));
        let resolution = ImportResolution::build("app", &items, &records);

        assert_eq!(
            resolution.resolve_path(&[], "execute").as_deref(),
            Some("app::inner::execute")
        );
    }

    #[test]
    fn cyclic_reexports_terminate() {
        let items = ItemTable::default();
        let mut records = use_records(&["left"], "pub use crate::right::thing;");
        records.extend(use_records(&["right"], "pub use crate::left::thing;"));
        let resolution = ImportResolution::build("app", &items, &records);

        assert!(
            resolution
                .resolve_path(&["left".to_string()], "thing")
                .is_some()
        );
    }

    #[test]
    fn relative_prefixes_resolve_without_an_import() {
        let items = ItemTable::default();
        let resolution = ImportResolution::build("app", &items, &[]);

        assert_eq!(
            resolution
                .resolve_path(&["api".to_string(), "v1".to_string()], "self::run")
                .as_deref(),
            Some("app::api::v1::run")
        );
        assert_eq!(
            resolution
                .resolve_path(&["api".to_string(), "v1".to_string()], "super::run")
                .as_deref(),
            Some("app::api::run")
        );
        assert_eq!(
            resolution.resolve_path(&[], "crate::api::run").as_deref(),
            Some("app::api::run")
        );
    }

    #[test]
    fn super_never_escapes_the_crate_root() {
        let items = ItemTable::default();
        let resolution = ImportResolution::build("app", &items, &[]);

        assert!(resolution.resolve_path(&[], "super::run").is_none());
    }

    #[test]
    fn sibling_modules_resolve_without_an_import() {
        let items = ItemTable::from_declarations(&[declaration("app::service::entry")]);
        let resolution = ImportResolution::build("app", &items, &[]);

        assert_eq!(
            resolution.resolve_path(&[], "service::entry").as_deref(),
            Some("app::service::entry")
        );
    }

    #[test]
    fn unknown_leading_segments_stay_unresolved() {
        let items = ItemTable::default();
        let resolution = ImportResolution::build("app", &items, &[]);

        assert!(resolution.resolve_path(&[], "mystery::call").is_none());
    }

    #[test]
    fn grouped_and_nested_use_trees_flatten() {
        let records = use_records(&[], "use crate::{api::Client, sinks::{run, exec as go}};");
        let paths: Vec<(String, Option<String>)> = records
            .iter()
            .map(|record| (record.path.clone(), record.alias.clone()))
            .collect();

        assert_eq!(
            paths,
            vec![
                ("crate::api::Client".to_string(), None),
                ("crate::sinks::run".to_string(), None),
                ("crate::sinks::exec".to_string(), Some("go".to_string())),
            ]
        );
    }

    #[test]
    fn visibility_marks_reexports() {
        assert!(!use_records(&[], "use crate::api::Client;")[0].is_public);
        assert!(use_records(&[], "pub use crate::api::Client;")[0].is_public);
        assert!(use_records(&[], "pub(crate) use crate::api::Client;")[0].is_public);
    }

    #[test]
    fn self_in_a_group_imports_the_module_itself() {
        let items = ItemTable::from_declarations(&[declaration("app::api::handler")]);
        let records = use_records(&[], "use crate::api::{self, handler};");
        let resolution = ImportResolution::build("app", &items, &records);

        // The `self` leaf used to be dropped, so `api::handler()` resolved
        // against nothing.
        assert_eq!(
            resolution.resolve_path(&[], "api::handler").as_deref(),
            Some("app::api::handler")
        );
    }

    #[test]
    fn renamed_self_imports_the_module_under_its_alias() {
        let items = ItemTable::from_declarations(&[declaration("app::api::handler")]);
        let records = use_records(&[], "use crate::api::{self as gateway};");
        let resolution = ImportResolution::build("app", &items, &records);

        assert_eq!(
            resolution.resolve_path(&[], "gateway::handler").as_deref(),
            Some("app::api::handler")
        );
    }

    #[test]
    fn a_local_item_shadows_a_glob_import() {
        let items = ItemTable::from_declarations(&[
            declaration("app::handlers::run"),
            declaration("app::sinks::run"),
        ]);
        let records = use_records(&["handlers"], "use crate::sinks::*;");
        let resolution = ImportResolution::build("app", &items, &records);

        // `handlers::run` is declared right here, so the glob's `run` is not in
        // scope and the call must not be rewritten to the sink.
        assert!(
            resolution
                .resolve_path(&["handlers".to_string()], "run")
                .is_none()
        );
    }
}
