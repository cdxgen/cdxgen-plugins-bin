//! `macro_rules!` definitions and how each is in scope.
//!
//! A pre-pass collects every definition in the analysed crates with its
//! position, and the module declarations and imports that decide where it is
//! visible. The scope table answers one question: what does the macro path
//! written at this position mean? The rules are those of the Rust Reference
//! chapter "Macros By Example":
//!
//! * textual scope runs from a definition to the end of its module, into
//!   child modules declared after it, and no further than the block that
//!   holds it; a later definition of the same name shadows an earlier one
//!   from its position on;
//! * `#[macro_use]` on a `mod` item extends the scope of the macros defined
//!   in it past the end of the item, through every level that carries the
//!   attribute;
//! * path-based scope comes from `#[macro_export]` (the crate root) and from
//!   `use` items, which make a macro an item of the importing module;
//! * `#[macro_use] extern crate c;` brings the exported macros of `c` into
//!   scope everywhere in the crate.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use super::{MAX_NESTING, MacroDefinition, MacroRule};
use crate::cfg::{CfgEvaluator, CfgExpr};
use crate::import_resolution::{UseRecord, collect_use_records};

/// A `(line, column)` position within one file.
pub(crate) type Pos = (usize, usize);

/// A `use` item with the position it appears at.
#[derive(Debug, Clone)]
pub(crate) struct PositionedUse {
    pub(crate) record: UseRecord,
    pub(crate) position: Pos,
}

/// A `mod` item.
#[derive(Debug, Clone)]
pub(crate) struct ModDecl {
    /// Module path of the module that declares it.
    pub(crate) parent: Vec<String>,
    pub(crate) name: String,
    pub(crate) macro_use: bool,
    pub(crate) start: Pos,
    pub(crate) end: Pos,
}

/// What the pre-pass collected from one file.
#[derive(Debug, Default, Clone)]
pub(crate) struct MacroFilePrepass {
    pub(crate) definitions: Vec<MacroDefinition>,
    pub(crate) uses: Vec<PositionedUse>,
    pub(crate) mods: Vec<ModDecl>,
    /// Crate names of every `#[macro_use] extern crate`.
    pub(crate) macro_use_extern_crates: Vec<String>,
    /// `extern crate original as alias;`, as `(alias, original)`.
    pub(crate) extern_aliases: Vec<(String, String)>,
}

/// Reads one file's macro-relevant items. `module_path` is the module the
/// file occupies, exactly as the analysis pass will see it.
pub(crate) fn prepass_file(
    source: &str,
    module_path: &[String],
    file_path: &str,
    evaluator: &CfgEvaluator,
    edition_2021: bool,
) -> MacroFilePrepass {
    let Ok(syntax) = syn::parse_file(source) else {
        // A file that does not parse is reported by the main analysis pass.
        return MacroFilePrepass::default();
    };
    let mut visitor = PrepassVisitor {
        module_path: module_path.to_vec(),
        file_path: file_path.to_string(),
        evaluator,
        edition_2021,
        blocks: Vec::new(),
        out: MacroFilePrepass::default(),
    };
    visitor.visit_file(&syntax);
    visitor.out
}

struct PrepassVisitor<'a> {
    module_path: Vec<String>,
    file_path: String,
    evaluator: &'a CfgEvaluator,
    edition_2021: bool,
    /// The blocks the visit is inside, innermost last.
    blocks: Vec<(Pos, Pos)>,
    out: MacroFilePrepass,
}

fn start_of(span: proc_macro2::Span) -> Pos {
    let start = span.start();
    (start.line.max(1), start.column)
}

fn end_of(span: proc_macro2::Span) -> Pos {
    let end = span.end();
    (end.line.max(1), end.column)
}

impl PrepassVisitor<'_> {
    fn gate_allows(&self, attrs: &[syn::Attribute]) -> bool {
        self.evaluator.is_enabled(&CfgExpr::from_attrs(attrs))
    }
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

impl<'ast> Visit<'ast> for PrepassVisitor<'_> {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !self.gate_allows(crate::item_attrs(node)) {
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        let range = (
            start_of(node.brace_token.span.open()),
            end_of(node.brace_token.span.close()),
        );
        self.blocks.push(range);
        syn::visit::visit_block(self, node);
        self.blocks.pop();
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if self.gate_allows(&node.attrs)
            && node.mac.path.is_ident("macro_rules")
            && let Some(name) = node.ident.as_ref()
            && let Some(rules) = parse_rules(&node.mac.tokens)
        {
            let (line, column) = start_of(name.span());
            self.out.definitions.push(MacroDefinition {
                name: name.to_string(),
                module_path: self.module_path.clone(),
                file_path: self.file_path.clone(),
                line,
                column,
                exported: has_attr(&node.attrs, "macro_export"),
                edition_2021: self.edition_2021,
                block: self.blocks.last().copied(),
                rules,
            });
        }
        syn::visit::visit_item_macro(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if self.blocks.is_empty() {
            let mut records = Vec::new();
            collect_use_records(node, &self.module_path, &mut records);
            let position = start_of(node.use_token.span);
            self.out.uses.extend(
                records
                    .into_iter()
                    .map(|record| PositionedUse { record, position }),
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !self.gate_allows(&node.attrs) {
            return;
        }
        let start = start_of(node.mod_token.span);
        let end = match (&node.content, &node.semi) {
            (Some((brace, _)), _) => end_of(brace.span.close()),
            (None, Some(semi)) => end_of(semi.span),
            (None, None) => start,
        };
        self.out.mods.push(ModDecl {
            parent: self.module_path.clone(),
            name: node.ident.to_string(),
            macro_use: has_attr(&node.attrs, "macro_use"),
            start,
            end,
        });
        if node.content.is_some() {
            self.module_path.push(node.ident.to_string());
            syn::visit::visit_item_mod(self, node);
            self.module_path.pop();
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        let original = node.ident.to_string().replace('-', "_");
        if let Some((_, alias)) = &node.rename {
            self.out
                .extern_aliases
                .push((alias.to_string(), original.clone()));
        }
        if has_attr(&node.attrs, "macro_use") {
            self.out.macro_use_extern_crates.push(original);
        }
    }
}

/// The deepest nesting of groups in `stream`, found without recursion.
fn nesting_depth(stream: &TokenStream) -> usize {
    let mut deepest = 0usize;
    let mut stack = vec![(stream.clone().into_iter(), 1usize)];
    while let Some((mut iter, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        if deepest > MAX_NESTING {
            return deepest;
        }
        while let Some(tree) = iter.next() {
            if let TokenTree::Group(group) = tree {
                stack.push((iter, depth));
                stack.push((group.stream().into_iter(), depth + 1));
                break;
            }
        }
    }
    deepest
}

/// Splits a `macro_rules!` body into `matcher => transcriber` rules. Returns
/// `None` when the body is not a list of rules, or nests deeper than the
/// module reads.
pub(super) fn parse_rules(tokens: &TokenStream) -> Option<Vec<MacroRule>> {
    if nesting_depth(tokens) > MAX_NESTING {
        return None;
    }
    let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let mut rules = Vec::new();
    let mut i = 0usize;
    while i < trees.len() {
        let TokenTree::Group(matcher) = &trees[i] else {
            return None;
        };
        // `=>` arrives as two punctuation tokens.
        let arrow = matches!(
            (trees.get(i + 1), trees.get(i + 2)),
            (Some(TokenTree::Punct(equals)), Some(TokenTree::Punct(greater)))
                if equals.as_char() == '=' && greater.as_char() == '>'
        );
        let Some(TokenTree::Group(transcriber)) = trees.get(i + 3) else {
            return None;
        };
        if !arrow {
            return None;
        }
        rules.push(MacroRule {
            matcher: matcher.stream().to_string(),
            transcriber: transcriber.stream().to_string(),
        });
        i += 4;
        if matches!(trees.get(i), Some(TokenTree::Punct(semi)) if semi.as_char() == ';') {
            i += 1;
        }
    }
    (!rules.is_empty()).then_some(rules)
}

// ---------------------------------------------------------------------------
// Scope table
// ---------------------------------------------------------------------------

/// A reference to one definition, unique across crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacroRef {
    pub(crate) crate_path: String,
    index: usize,
}

/// Where an invocation's path resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvocationTarget {
    /// A workspace `macro_rules!` definition.
    Workspace {
        reference: MacroRef,
    },
    /// A dependency crate macro; `path` is the resolved path without the
    /// trailing bang (`serde_json::json`).
    Dependency {
        crate_name: String,
        path: String,
    },
    /// A bare name more than one `#[macro_use] extern crate` could supply.
    Ambiguous {
        candidates: Vec<String>,
    },
    /// A std, core or alloc macro, which is not recorded.
    Std,
    Unresolved,
}

/// Macros of the standard library that are in scope without a path, or that
/// are exported from `std` and `core` under a single name. They are not
/// dependency evidence, so they are recognised before a crate is attributed.
const STD_MACROS: &[&str] = &[
    "asm",
    "assert",
    "assert_eq",
    "assert_ne",
    "cfg",
    "cfg_select",
    "column",
    "compile_error",
    "concat",
    "const_format_args",
    "dbg",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "env",
    "eprint",
    "eprintln",
    "file",
    "format",
    "format_args",
    "global_asm",
    "include",
    "include_bytes",
    "include_str",
    "is_aarch64_feature_detected",
    "is_arm_feature_detected",
    "is_loongarch_feature_detected",
    "is_mips64_feature_detected",
    "is_mips_feature_detected",
    "is_powerpc64_feature_detected",
    "is_powerpc_feature_detected",
    "is_riscv_feature_detected",
    "is_s390x_feature_detected",
    "is_x86_feature_detected",
    "line",
    "log_syntax",
    "matches",
    "module_path",
    "naked_asm",
    "option_env",
    "panic",
    "print",
    "println",
    "stringify",
    "thread_local",
    "todo",
    "trace_macros",
    "unimplemented",
    "unreachable",
    "vec",
    "write",
    "writeln",
];

pub(crate) fn is_std_macro(name: &str) -> bool {
    STD_MACROS.contains(&name)
}

/// The module a definition's visibility starts in, and from where.
type Home = (String, Pos);

/// Orders the definitions visible at one position, so the latest wins.
type Rank = (usize, Pos, Pos);

#[derive(Debug, Clone)]
struct ModInfo {
    start: Pos,
    end: Pos,
    macro_use: bool,
}

#[derive(Debug, Default, Clone)]
struct CrateMacros {
    /// The analysis crate key, which is also the root of every qualified name
    /// in the crate.
    crate_path: String,
    definitions: Vec<MacroDefinition>,
    /// Per definition, where its textual scope starts.
    homes: Vec<Vec<Home>>,
    /// Module key -> the `mod` item that declares it.
    mods: HashMap<String, ModInfo>,
    /// Module key -> child module names.
    child_modules: HashMap<String, BTreeSet<String>>,
    /// Path-based names: `(module key, name) -> definition`.
    aliases: HashMap<(String, String), MacroRef>,
    /// Module-level imports, in the order they appear.
    uses: Vec<(String, PositionedUse)>,
    macro_use_extern_crates: Vec<String>,
    extern_aliases: HashMap<String, String>,
}

/// The scope table built from the pre-pass.
#[derive(Debug, Default, Clone)]
pub(crate) struct MacroScopeTable {
    crates: BTreeMap<String, CrateMacros>,
    /// Crate names (underscores) in the workspace's resolve graph.
    dependency_crates: HashSet<String>,
}

/// The name an import binds: its alias, or the last segment of its path.
fn local_name(record: &UseRecord) -> String {
    record.alias.clone().unwrap_or_else(|| {
        record
            .path
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .to_string()
    })
}

pub(crate) fn join_module(crate_name: &str, module_path: &[String]) -> String {
    let mut segments = vec![crate_name.to_string()];
    segments.extend(module_path.iter().cloned());
    segments.join("::")
}

fn key_depth(key: &str) -> usize {
    key.matches("::").count()
}

/// The pre-pass inputs for one analysed crate.
pub(crate) struct CratePrepass {
    pub(crate) crate_path: String,
    pub(crate) prepasses: Vec<MacroFilePrepass>,
    /// Module keys the crate's files occupy, joined as `crate::module::...`.
    pub(crate) module_keys: BTreeSet<String>,
}

impl MacroScopeTable {
    /// Builds the table from every crate's pre-pass results. Path-based names
    /// are resolved to a fixed point over the `use` items, so a macro
    /// re-exported through a chain of modules is reachable through every link.
    pub(crate) fn build(crates: Vec<CratePrepass>, dependency_crates: HashSet<String>) -> Self {
        let mut table = MacroScopeTable {
            dependency_crates,
            ..MacroScopeTable::default()
        };
        for entry in crates {
            table
                .crates
                .insert(entry.crate_path.clone(), CrateMacros::collect(entry));
        }
        // Every crate's own names are in place before imports are followed,
        // because an import may name another analysed crate.
        let names: Vec<String> = table.crates.keys().cloned().collect();
        let limit = table
            .crates
            .values()
            .map(|macros| macros.uses.len())
            .sum::<usize>()
            + 2;
        for _ in 0..limit {
            let mut changed = false;
            for name in &names {
                let updates = table.import_updates(name);
                if let Some(macros) = table.crates.get_mut(name) {
                    for (key, reference) in updates {
                        if let std::collections::hash_map::Entry::Vacant(slot) =
                            macros.aliases.entry(key)
                        {
                            slot.insert(reference);
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        table
    }

    /// The names the imports of one crate add, given what is known now.
    fn import_updates(&self, crate_path: &str) -> Vec<((String, String), MacroRef)> {
        let Some(macros) = self.crates.get(crate_path) else {
            return Vec::new();
        };
        let mut updates = Vec::new();
        for (module_key, used) in &macros.uses {
            let record = &used.record;
            if record.is_glob {
                let Some((target_crate, target)) =
                    self.navigate_module(macros, module_key, &record.path)
                else {
                    continue;
                };
                let Some(target_macros) = self.crates.get(&target_crate) else {
                    continue;
                };
                for ((module, name), reference) in &target_macros.aliases {
                    if module == &target {
                        updates.push(((module_key.clone(), name.clone()), reference.clone()));
                    }
                }
                continue;
            }
            let local = local_name(record);
            if local == "_" {
                continue;
            }
            let segments: Vec<&str> = record.path.split("::").collect();
            let resolved = if segments.len() == 1 {
                macros
                    .textual_lookup(module_key, "", used.position, segments[0], true)
                    .or_else(|| {
                        macros
                            .aliases
                            .get(&(module_key.clone(), segments[0].to_string()))
                            .cloned()
                    })
            } else {
                self.resolve_path(macros, module_key, &segments)
            };
            if let Some(reference) = resolved {
                updates.push(((module_key.clone(), local), reference));
            }
        }
        updates
    }

    /// The definition a `macro_rules!` token in this position describes, for
    /// emitting its declaration while the definition is visited.
    pub(crate) fn find_definition(
        &self,
        crate_path: &str,
        module_path: &[String],
        file_path: &str,
        name: &str,
        position: Pos,
    ) -> Option<(&MacroDefinition, String)> {
        let macros = self.crates.get(crate_path)?;
        let definition = macros.definitions.iter().find(|definition| {
            definition.name == name
                && definition.file_path == file_path
                && definition.module_path == module_path
                && (definition.line, definition.column) == position
        })?;
        Some((definition, definition.canonical_path(&macros.crate_path)))
    }

    /// The definition behind a resolved workspace target.
    pub(crate) fn definition(&self, reference: &MacroRef) -> Option<&MacroDefinition> {
        self.crates
            .get(&reference.crate_path)?
            .definitions
            .get(reference.index)
    }

    pub(crate) fn crate_name_of(&self, crate_path: &str) -> String {
        self.crates
            .get(crate_path)
            .map(|macros| macros.crate_path.clone())
            .unwrap_or_else(|| crate_path.to_string())
    }

    /// Resolves the macro path written at `position` of `file_path`, in the
    /// module `module_path` of crate `crate_path`. `use_records` are the
    /// imports the collector has seen before the invocation in the file.
    pub(crate) fn resolve_invocation(
        &self,
        crate_path: &str,
        module_path: &[String],
        file_path: &str,
        position: Pos,
        invocation_path: &str,
        use_records: &[UseRecord],
    ) -> InvocationTarget {
        let Some(macros) = self.crates.get(crate_path) else {
            return InvocationTarget::Unresolved;
        };
        let module_key = join_module(&macros.crate_path, module_path);
        let segments: Vec<&str> = invocation_path.split("::").collect();
        if segments.len() == 1 {
            return self.resolve_bare_name(
                macros,
                &module_key,
                file_path,
                position,
                segments[0],
                use_records,
            );
        }
        self.resolve_written_path(macros, &module_key, &segments, use_records, 0)
    }

    fn resolve_written_path(
        &self,
        macros: &CrateMacros,
        module_key: &str,
        segments: &[&str],
        use_records: &[UseRecord],
        depth: usize,
    ) -> InvocationTarget {
        let first = segments[0];
        if matches!(first, "std" | "core" | "alloc") {
            return InvocationTarget::Std;
        }
        let first = macros
            .extern_aliases
            .get(first)
            .map(String::as_str)
            .unwrap_or(first);
        let is_own_path = matches!(first, "crate" | "self" | "super");
        let is_module_path =
            self.child_module_exists(macros, module_key, first) || first == macros.crate_path;
        if is_own_path || is_module_path || self.crates.contains_key(first) {
            let mut adjusted: Vec<&str> = segments.to_vec();
            adjusted[0] = first;
            return match self.resolve_path(macros, module_key, &adjusted) {
                Some(reference) => InvocationTarget::Workspace { reference },
                None => InvocationTarget::Unresolved,
            };
        }
        if self.dependency_crates.contains(first) {
            let mut path = vec![first];
            path.extend(&segments[1..]);
            return InvocationTarget::Dependency {
                crate_name: first.to_string(),
                path: path.join("::"),
            };
        }
        // `use serde_json as sj;` followed by `sj::json!`.
        if depth == 0
            && let Some(record) = use_records
                .iter()
                .rev()
                .find(|record| !record.is_glob && local_name(record) == first)
        {
            let head: Vec<String> = record.path.split("::").map(str::to_string).collect();
            let mut expanded: Vec<&str> = head.iter().map(String::as_str).collect();
            expanded.extend(&segments[1..]);
            return self.resolve_written_path(macros, module_key, &expanded, use_records, 1);
        }
        InvocationTarget::Unresolved
    }

    fn resolve_bare_name(
        &self,
        macros: &CrateMacros,
        module_key: &str,
        file_path: &str,
        position: Pos,
        name: &str,
        use_records: &[UseRecord],
    ) -> InvocationTarget {
        if let Some(reference) = macros.textual_lookup(module_key, file_path, position, name, false)
        {
            return InvocationTarget::Workspace { reference };
        }
        if let Some(reference) = macros
            .aliases
            .get(&(module_key.to_string(), name.to_string()))
        {
            return InvocationTarget::Workspace {
                reference: reference.clone(),
            };
        }
        // A `use` that imports the macro from a dependency crate, under the
        // imported name or its alias.
        for record in use_records.iter().rev() {
            if local_name(record) != name || record.is_glob {
                continue;
            }
            let head = record.path.split("::").next().unwrap_or_default();
            if matches!(head, "std" | "core" | "alloc") {
                return InvocationTarget::Std;
            }
            if !self.crates.contains_key(head) && self.dependency_crates.contains(head) {
                return InvocationTarget::Dependency {
                    crate_name: head.to_string(),
                    path: record.path.clone(),
                };
            }
        }
        if is_std_macro(name) {
            return InvocationTarget::Std;
        }
        // Macros brought in by `#[macro_use] extern crate`: an exported macro
        // of a workspace crate is a definite hit, and otherwise every
        // dependency crate could be the one that supplies the name.
        let mut candidates: Vec<String> = Vec::new();
        for crate_name in &macros.macro_use_extern_crates {
            if let Some(other) = self.crates.get(crate_name) {
                if let Some(reference) = other
                    .aliases
                    .get(&(other.crate_path.clone(), name.to_string()))
                {
                    return InvocationTarget::Workspace {
                        reference: reference.clone(),
                    };
                }
            } else {
                candidates.push(crate_name.clone());
            }
        }
        match candidates.len() {
            0 => InvocationTarget::Unresolved,
            1 => InvocationTarget::Dependency {
                crate_name: candidates[0].clone(),
                path: format!("{}::{name}", candidates[0]),
            },
            _ => InvocationTarget::Ambiguous {
                candidates: candidates
                    .into_iter()
                    .map(|crate_name| format!("{crate_name}::{name}"))
                    .collect(),
            },
        }
    }

    fn child_module_exists(&self, macros: &CrateMacros, module_key: &str, name: &str) -> bool {
        macros
            .child_modules
            .get(module_key)
            .is_some_and(|children| children.contains(name))
    }

    /// Resolves a path of two or more segments (or one that begins with
    /// `crate`, `self`, `super` or a crate name) to a definition, through the
    /// path-based names of each module it passes.
    fn resolve_path(
        &self,
        macros: &CrateMacros,
        module_key: &str,
        segments: &[&str],
    ) -> Option<MacroRef> {
        let (target_crate, mut current, rest) = self.path_base(macros, module_key, segments)?;
        let target = self.crates.get(&target_crate)?;
        let (name, modules) = rest.split_last()?;
        for segment in modules {
            if !target
                .child_modules
                .get(&current)
                .is_some_and(|children| children.contains(*segment))
            {
                return None;
            }
            current = format!("{current}::{segment}");
        }
        target.aliases.get(&(current, (*name).to_string())).cloned()
    }

    /// The crate, module key and remaining segments a path starts from.
    fn path_base<'s>(
        &self,
        macros: &CrateMacros,
        module_key: &str,
        segments: &'s [&'s str],
    ) -> Option<(String, String, &'s [&'s str])> {
        let first = *segments.first()?;
        match first {
            "crate" => Some((
                macros.crate_path.clone(),
                macros.crate_path.clone(),
                &segments[1..],
            )),
            "self" => Some((
                macros.crate_path.clone(),
                module_key.to_string(),
                &segments[1..],
            )),
            "super" => {
                let mut base: Vec<&str> = module_key.split("::").collect();
                let mut rest = segments;
                while rest.first() == Some(&"super") {
                    if base.len() <= 1 {
                        return None;
                    }
                    base.pop();
                    rest = &rest[1..];
                }
                Some((macros.crate_path.clone(), base.join("::"), rest))
            }
            _ if first == macros.crate_path => Some((
                macros.crate_path.clone(),
                macros.crate_path.clone(),
                &segments[1..],
            )),
            _ if self.crates.contains_key(first) => {
                Some((first.to_string(), first.to_string(), &segments[1..]))
            }
            // A module declared in the importing module.
            _ if self.child_module_exists(macros, module_key, first) => {
                Some((macros.crate_path.clone(), module_key.to_string(), segments))
            }
            _ => None,
        }
    }

    /// Navigates a `use` target to a module, for glob imports.
    fn navigate_module(
        &self,
        macros: &CrateMacros,
        module_key: &str,
        path: &str,
    ) -> Option<(String, String)> {
        let segments: Vec<&str> = path.split("::").filter(|part| !part.is_empty()).collect();
        let (target_crate, mut current, rest) = self.path_base(macros, module_key, &segments)?;
        let target = self.crates.get(&target_crate)?;
        for segment in rest {
            if !target
                .child_modules
                .get(&current)
                .is_some_and(|children| children.contains(*segment))
            {
                return None;
            }
            current = format!("{current}::{segment}");
        }
        Some((target_crate, current))
    }
}

impl CrateMacros {
    fn collect(entry: CratePrepass) -> Self {
        let crate_root = entry.crate_path.clone();
        let mut macros = CrateMacros {
            crate_path: crate_root.clone(),
            ..CrateMacros::default()
        };
        for key in &entry.module_keys {
            if let Some((parent, child)) = key.rsplit_once("::") {
                macros
                    .child_modules
                    .entry(parent.to_string())
                    .or_default()
                    .insert(child.to_string());
            }
        }
        for prepass in &entry.prepasses {
            for declaration in &prepass.mods {
                let parent = join_module(&crate_root, &declaration.parent);
                macros
                    .child_modules
                    .entry(parent.clone())
                    .or_default()
                    .insert(declaration.name.clone());
                macros.mods.insert(
                    format!("{parent}::{}", declaration.name),
                    ModInfo {
                        start: declaration.start,
                        end: declaration.end,
                        macro_use: declaration.macro_use,
                    },
                );
            }
            for used in &prepass.uses {
                macros.uses.push((
                    join_module(&crate_root, &used.record.module_path),
                    used.clone(),
                ));
            }
            macros
                .macro_use_extern_crates
                .extend(prepass.macro_use_extern_crates.iter().cloned());
            macros
                .extern_aliases
                .extend(prepass.extern_aliases.iter().cloned());
            macros
                .definitions
                .extend(prepass.definitions.iter().cloned());
        }
        // A deterministic order whatever order the files were analysed in.
        macros.definitions.sort_by(|left, right| {
            (&left.file_path, left.line, left.column).cmp(&(
                &right.file_path,
                right.line,
                right.column,
            ))
        });
        macros.uses.sort_by(|left, right| {
            (
                &left.0,
                left.1.position,
                &left.1.record.path,
                &left.1.record.alias,
            )
                .cmp(&(
                    &right.0,
                    right.1.position,
                    &right.1.record.path,
                    &right.1.record.alias,
                ))
        });
        macros.macro_use_extern_crates.sort();
        macros.macro_use_extern_crates.dedup();
        for (index, definition) in macros.definitions.iter().enumerate() {
            macros.homes.push(macros.homes_of(definition));
            if definition.exported && definition.block.is_none() {
                macros.aliases.insert(
                    (crate_root.clone(), definition.name.clone()),
                    MacroRef {
                        crate_path: crate_root.clone(),
                        index,
                    },
                );
            }
        }
        macros
    }

    /// Where a definition is textually in scope: its own module from the
    /// definition on, and, through each `#[macro_use]` module it sits in, the
    /// parent module from the end of that `mod` item on.
    fn homes_of(&self, definition: &MacroDefinition) -> Vec<Home> {
        let mut key = join_module(&self.crate_path, &definition.module_path);
        let mut homes = vec![(key.clone(), (definition.line, definition.column))];
        while let Some(info) = self.mods.get(&key) {
            if !info.macro_use {
                break;
            }
            let Some((parent, _)) = key.rsplit_once("::") else {
                break;
            };
            let parent = parent.to_string();
            homes.push((parent.clone(), info.end));
            key = parent;
        }
        homes
    }

    /// The definition of `name` that is textually in scope at `position` of
    /// `file_path`, in module `module_key`. With `ignore_blocks`, block-local
    /// definitions are not considered (a `use` item at module level cannot
    /// name them).
    fn textual_lookup(
        &self,
        module_key: &str,
        file_path: &str,
        position: Pos,
        name: &str,
        ignore_blocks: bool,
    ) -> Option<MacroRef> {
        let mut best: Option<(Rank, usize)> = None;
        for (index, definition) in self.definitions.iter().enumerate() {
            if definition.name != name {
                continue;
            }
            let rank = match definition.block {
                Some((start, end)) => {
                    let inside = definition.file_path == file_path
                        && join_module(&self.crate_path, &definition.module_path) == module_key
                        && start <= position
                        && position <= end
                        && (definition.line, definition.column) < position;
                    (inside && !ignore_blocks).then(|| {
                        (
                            key_depth(module_key) + 1,
                            start,
                            (definition.line, definition.column),
                        )
                    })
                }
                None => self.homes[index]
                    .iter()
                    .filter_map(|(home, from)| self.home_rank(home, *from, module_key, position))
                    .max(),
            };
            if let Some(rank) = rank
                && best.as_ref().is_none_or(|(current, _)| rank > *current)
            {
                best = Some((rank, index));
            }
        }
        best.map(|(_, index)| MacroRef {
            crate_path: self.crate_path.clone(),
            index,
        })
    }

    /// The rank of a definition whose scope starts at `from` in module
    /// `home`, as seen from `position` in module `module_key`, or `None` when
    /// it is not in scope there.
    fn home_rank(&self, home: &str, from: Pos, module_key: &str, position: Pos) -> Option<Rank> {
        if home == module_key {
            return (from < position).then(|| (key_depth(home), (0, 0), from));
        }
        // An ancestor's macro reaches a descendant module only when the
        // `mod` item that leads to it comes after the definition.
        let below = module_key.strip_prefix(home)?.strip_prefix("::")?;
        let child = below.split("::").next()?;
        let info = self.mods.get(&format!("{home}::{child}"))?;
        (from < info.start).then(|| (key_depth(home), (0, 0), from))
    }
}
