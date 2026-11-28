//! Tests for macro definitions and their scope, one per rule of the Rust
//! Reference chapter "Macros By Example" that the scope table follows.

use std::collections::{BTreeSet, HashSet};

use super::scope::{is_std_macro, join_module, prepass_from_parsed};
use super::*;
use crate::cfg::CfgEvaluator;
use crate::import_resolution::{UseRecord, collect_use_records};

/// One source file of a test crate: its module path and its text.
struct File<'a> {
    module: &'a [&'a str],
    path: &'a str,
    source: &'a str,
}

struct TestCrate<'a> {
    name: &'a str,
    files: Vec<File<'a>>,
}

fn build(crates: &[TestCrate], dependencies: &[&str]) -> MacroScopeTable {
    let entries = crates
        .iter()
        .map(|krate| {
            let mut module_keys = BTreeSet::new();
            let mut prepasses = Vec::new();
            for file in &krate.files {
                let module: Vec<String> = file.module.iter().map(|s| s.to_string()).collect();
                module_keys.insert(join_module(krate.name, &module));
                let syntax = syn::parse_file(file.source).expect("test source parses");
                prepasses.push(prepass_from_parsed(
                    &syntax,
                    &module,
                    file.path,
                    &CfgEvaluator::permissive(),
                    true,
                ));
            }
            CratePrepass {
                crate_path: krate.name.to_string(),
                prepasses,
                module_keys,
            }
        })
        .collect();
    let dependency_crates: HashSet<String> =
        dependencies.iter().map(|name| name.to_string()).collect();
    MacroScopeTable::build(entries, dependency_crates)
}

fn single(source: &str) -> (MacroScopeTable, TestCrate<'_>) {
    let krate = TestCrate {
        name: "app",
        files: vec![File {
            module: &[],
            path: "src/lib.rs",
            source,
        }],
    };
    (build(std::slice::from_ref(&krate), &[]), krate)
}

/// `(line, column)` of the `nth` occurrence of `needle` in `source`.
fn locate(source: &str, needle: &str, nth: usize) -> Pos {
    let mut seen = 0;
    for (index, line) in source.lines().enumerate() {
        let mut from = 0;
        while let Some(found) = line[from..].find(needle) {
            if seen == nth {
                return (index + 1, from + found);
            }
            seen += 1;
            from += found + needle.len();
        }
    }
    panic!("`{needle}` occurrence {nth} not found");
}

fn describe(table: &MacroScopeTable, target: InvocationTarget) -> String {
    match target {
        InvocationTarget::Workspace { reference } => {
            let definition = table.definition(&reference).expect("definition exists");
            format!(
                "workspace {}:{}:{}",
                reference.crate_path, definition.file_path, definition.line
            )
        }
        InvocationTarget::Dependency { path, .. } => format!("dependency {path}"),
        InvocationTarget::Ambiguous { candidates } => format!("ambiguous {}", candidates.join(",")),
        InvocationTarget::Std => "std".to_string(),
        InvocationTarget::Unresolved => "unresolved".to_string(),
    }
}

/// Resolves the `nth` occurrence of `invocation` (written with its `!`) in
/// `file`, as the collector would.
fn resolve(
    table: &MacroScopeTable,
    krate: &str,
    file: &File,
    invocation: &str,
    nth: usize,
    imports: &[UseRecord],
) -> String {
    let position = locate(file.source, invocation, nth);
    let module: Vec<String> = file.module.iter().map(|s| s.to_string()).collect();
    let path = invocation.trim_end_matches('!');
    describe(
        table,
        table.resolve_invocation(krate, &module, file.path, position, path, imports),
    )
}

fn imports_of(file: &File) -> Vec<UseRecord> {
    let syntax = syn::parse_file(file.source).expect("test source parses");
    let module: Vec<String> = file.module.iter().map(|s| s.to_string()).collect();
    let mut records = Vec::new();
    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            collect_use_records(item_use, &module, &mut records);
        }
    }
    records
}

fn resolve_in_file(
    table: &MacroScopeTable,
    krate: &str,
    file: &File,
    invocation: &str,
    nth: usize,
) -> String {
    resolve(table, krate, file, invocation, nth, &imports_of(file))
}

// ---------------------------------------------------------------------------
// Textual scope
// ---------------------------------------------------------------------------

#[test]
fn textual_scope_starts_after_the_definition() {
    let source = "m!();\nmacro_rules! m { () => {} }\nm!();\n";
    let (table, krate) = single(source);
    let file = &krate.files[0];
    assert_eq!(resolve_in_file(&table, "app", file, "m!", 0), "unresolved");
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 1),
        "workspace app:src/lib.rs:2"
    );
}

#[test]
fn textual_scope_covers_child_modules_declared_later_only() {
    let root = "mod early;\nmacro_rules! m { () => {} }\nmod late;\n";
    let krate = TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: root,
            },
            File {
                module: &["early"],
                path: "src/early.rs",
                source: "m!();\n",
            },
            File {
                module: &["late"],
                path: "src/late.rs",
                source: "m!();\n",
            },
        ],
    };
    let table = build(std::slice::from_ref(&krate), &[]);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[1], "m!", 0),
        "unresolved"
    );
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[2], "m!", 0),
        "workspace app:src/lib.rs:2"
    );
}

#[test]
fn textual_scope_does_not_leave_the_defining_module() {
    let root = "mod inner;\nm!();\n";
    let krate = TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: root,
            },
            File {
                module: &["inner"],
                path: "src/inner.rs",
                source: "macro_rules! m { () => {} }\nm!();\n",
            },
        ],
    };
    let table = build(std::slice::from_ref(&krate), &[]);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[1], "m!", 0),
        "workspace app:src/inner.rs:1"
    );
    // The parent does not see a macro of its child without `#[macro_use]`.
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "m!", 0),
        "unresolved"
    );
}

#[test]
fn a_later_definition_shadows_an_earlier_one_from_its_position_on() {
    let source = "macro_rules! m { () => {1} }\n\
                  fn a() { m!(); }\n\
                  macro_rules! m { () => {2} }\n\
                  fn b() { m!(); }\n";
    let (table, krate) = single(source);
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 0),
        "workspace app:src/lib.rs:1"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 1),
        "workspace app:src/lib.rs:3"
    );
}

#[test]
fn a_definition_and_an_invocation_on_one_line_are_linked_by_column() {
    let (table, krate) = single("macro_rules! m { () => {} } m!();\n");
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "m!", 0),
        "workspace app:src/lib.rs:1"
    );
    // Before the definition on the same line it is not visible.
    let (table, krate) = single("m!(); macro_rules! m { () => {} }\n");
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "m!", 0),
        "unresolved"
    );
}

#[test]
fn block_local_definitions_stay_in_their_block() {
    let source = "fn f1() { macro_rules! local { () => {} } local!(); }\n\
                  fn f2() { local!(); }\n\
                  fn f3() { { macro_rules! inner { () => {} } } inner!(); }\n";
    let (table, krate) = single(source);
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "local!", 0),
        "workspace app:src/lib.rs:1"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "local!", 1),
        "unresolved"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "inner!", 0),
        "unresolved"
    );
}

#[test]
fn a_block_local_definition_shadows_a_module_one_inside_its_block() {
    let source = "macro_rules! m { () => {1} }\n\
                  fn f() { macro_rules! m { () => {2} } m!(); }\n\
                  fn g() { m!(); }\n";
    let (table, krate) = single(source);
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 0),
        "workspace app:src/lib.rs:2"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 1),
        "workspace app:src/lib.rs:1"
    );
}

// ---------------------------------------------------------------------------
// #[macro_use] mod
// ---------------------------------------------------------------------------

fn nested_macro_use_crate<'a>(inner_macro_use: bool) -> TestCrate<'a> {
    TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: "deep!();\n#[macro_use]\nmod outer;\ndeep!();\n",
            },
            File {
                module: &["outer"],
                path: "src/outer/mod.rs",
                source: if inner_macro_use {
                    "#[macro_use]\nmod inner;\ndeep!();\n"
                } else {
                    "mod inner;\ndeep!();\n"
                },
            },
            File {
                module: &["outer", "inner"],
                path: "src/outer/inner.rs",
                source: "macro_rules! deep { () => {} }\n",
            },
        ],
    }
}

#[test]
fn macro_use_hoists_through_every_level_after_the_mod_item() {
    let krate = nested_macro_use_crate(true);
    let table = build(std::slice::from_ref(&krate), &[]);
    let root = &krate.files[0];
    // Before `mod outer;` nothing is hoisted; after it, the macro of the
    // innermost module is in scope at the root.
    assert_eq!(
        resolve_in_file(&table, "app", root, "deep!", 0),
        "unresolved"
    );
    assert_eq!(
        resolve_in_file(&table, "app", root, "deep!", 1),
        "workspace app:src/outer/inner.rs:1"
    );
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[1], "deep!", 0),
        "workspace app:src/outer/inner.rs:1"
    );
}

#[test]
fn macro_use_stops_at_the_first_module_without_the_attribute() {
    let krate = nested_macro_use_crate(false);
    let table = build(std::slice::from_ref(&krate), &[]);
    let root = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", root, "deep!", 1),
        "unresolved"
    );
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[1], "deep!", 0),
        "unresolved"
    );
}

#[test]
fn hoisted_and_local_definitions_shadow_by_declaration_order() {
    let root = "macro_rules! m { () => {} }\n\
                #[macro_use]\n\
                mod hoisted;\n\
                m!();\n\
                macro_rules! m { () => {} }\n\
                m!();\n";
    let krate = TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: root,
            },
            File {
                module: &["hoisted"],
                path: "src/hoisted.rs",
                source: "macro_rules! m { () => {} }\n",
            },
        ],
    };
    let table = build(std::slice::from_ref(&krate), &[]);
    let file = &krate.files[0];
    // After the `mod` item the hoisted definition is the latest one ...
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 0),
        "workspace app:src/hoisted.rs:1"
    );
    // ... until the root defines its own again.
    assert_eq!(
        resolve_in_file(&table, "app", file, "m!", 1),
        "workspace app:src/lib.rs:5"
    );
}

#[test]
fn macro_use_on_an_inline_module_reaches_the_parent() {
    let source = "#[macro_use]\nmod inline { macro_rules! m { () => {} } }\nm!();\n";
    let (table, krate) = single(source);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "m!", 0),
        "workspace app:src/lib.rs:2"
    );
    let plain = "mod inline { macro_rules! m { () => {} } }\nm!();\n";
    let (table, krate) = single(plain);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "m!", 0),
        "unresolved"
    );
}

// ---------------------------------------------------------------------------
// Path-based scope
// ---------------------------------------------------------------------------

fn macros_layout<'a>() -> TestCrate<'a> {
    TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: "mod macros;\n\
                         use crate::macros::one as uno;\n\
                         fn f() { crate::macros::one!(); uno!(); macros::one!(); \
                         crate::macros::hidden!(); crate::one!(); }\n",
            },
            File {
                module: &["macros"],
                path: "src/macros/mod.rs",
                source: "mod one;\nmod hidden_mod;\npub(crate) use one::*;\n\
                         fn g() { self::one!(); one!(); }\n",
            },
            File {
                module: &["macros", "one"],
                path: "src/macros/one.rs",
                source: "macro_rules! one { () => {} }\npub(crate) use one;\n",
            },
            File {
                module: &["macros", "hidden_mod"],
                path: "src/macros/hidden_mod.rs",
                source: "macro_rules! hidden { () => {} }\n",
            },
            File {
                module: &["sibling"],
                path: "src/sibling.rs",
                source: "fn h() { super::macros::one!(); }\n",
            },
        ],
    }
}

#[test]
fn pub_use_makes_a_macro_an_item_reachable_by_path_and_alias() {
    let mut krate = macros_layout();
    krate.files[0].source = "mod macros;\nmod sibling;\n\
         use crate::macros::one as uno;\n\
         fn f() { crate::macros::one!(); uno!(); macros::one!(); }\n";
    let table = build(std::slice::from_ref(&krate), &[]);
    let root = &krate.files[0];
    let expected = "workspace app:src/macros/one.rs:1";
    assert_eq!(
        resolve_in_file(&table, "app", root, "crate::macros::one!", 0),
        expected
    );
    assert_eq!(resolve_in_file(&table, "app", root, "uno!", 0), expected);
    assert_eq!(
        resolve_in_file(&table, "app", root, "macros::one!", 0),
        expected
    );
    // `self::` and a bare name inside the re-exporting module itself.
    let macros = &krate.files[1];
    assert_eq!(
        resolve_in_file(&table, "app", macros, "self::one!", 0),
        expected
    );
    assert_eq!(resolve_in_file(&table, "app", macros, "one!", 0), expected);
    // `super::` from a sibling module.
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[4], "super::macros::one!", 0),
        expected
    );
}

#[test]
fn a_macro_that_is_not_re_exported_is_not_reachable_by_path() {
    let krate = macros_layout();
    let table = build(std::slice::from_ref(&krate), &[]);
    let root = &krate.files[0];
    // `hidden` has textual scope in its own module only; `one` is not at the
    // crate root.
    assert_eq!(
        resolve_in_file(&table, "app", root, "crate::macros::hidden!", 0),
        "unresolved"
    );
    assert_eq!(
        resolve_in_file(&table, "app", root, "crate::one!", 0),
        "unresolved"
    );
}

#[test]
fn a_glob_import_brings_the_re_exported_macros() {
    let krate = TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: "mod macros;\nmod user;\n",
            },
            File {
                module: &["macros"],
                path: "src/macros/mod.rs",
                source: "macro_rules! made { () => {} }\npub(crate) use made;\n",
            },
            File {
                module: &["user"],
                path: "src/user.rs",
                source: "use crate::macros::*;\nfn f() { made!(); }\n",
            },
        ],
    };
    let table = build(std::slice::from_ref(&krate), &[]);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[2], "made!", 0),
        "workspace app:src/macros/mod.rs:1"
    );
}

// ---------------------------------------------------------------------------
// #[macro_export] and $crate
// ---------------------------------------------------------------------------

fn export_layout<'a>() -> Vec<TestCrate<'a>> {
    vec![
        TestCrate {
            name: "lib_crate",
            files: vec![File {
                module: &[],
                path: "src/lib.rs",
                source: "pub mod a { pub mod b { #[macro_export] macro_rules! top { () => {} } \
                             pub use crate::top as renamed; } }\n\
                             fn f() { crate::top!(); crate::a::b::renamed!(); }\n",
            }],
        },
        TestCrate {
            name: "app",
            files: vec![File {
                module: &[],
                path: "src/lib.rs",
                source: "fn g() { lib_crate::top!(); lib_crate::a::b::renamed!(); \
                         lib_crate::a::b::missing!(); }\n",
            }],
        },
    ]
}

#[test]
fn macro_export_places_the_macro_at_the_crate_root_whatever_defines_it() {
    let crates = export_layout();
    let table = build(&crates, &[]);
    let defining = &crates[0].files[0];
    let expected = "workspace lib_crate:src/lib.rs:1";
    assert_eq!(
        resolve_in_file(&table, "lib_crate", defining, "crate::top!", 0),
        expected
    );
    // Exported macros are items of the root, so the textual `crate::` path
    // and the `$crate` form (rewritten to `crate` by the transcriber) agree.
    assert_eq!(
        resolve_in_file(&table, "lib_crate", defining, "crate::a::b::renamed!", 0),
        expected
    );
    let other = &crates[1].files[0];
    assert_eq!(
        resolve_in_file(&table, "app", other, "lib_crate::top!", 0),
        expected
    );
    assert_eq!(
        resolve_in_file(&table, "app", other, "lib_crate::a::b::renamed!", 0),
        expected
    );
    assert_eq!(
        resolve_in_file(&table, "app", other, "lib_crate::a::b::missing!", 0),
        "unresolved"
    );
}

#[test]
fn dollar_crate_paths_of_any_length_resolve() {
    let crates = vec![TestCrate {
        name: "app",
        files: vec![
            File {
                module: &[],
                path: "src/lib.rs",
                source: "pub mod p;\nfn f() { crate::p::q::r::deep!(); }\n",
            },
            File {
                module: &["p"],
                path: "src/p/mod.rs",
                source: "pub mod q;\n",
            },
            File {
                module: &["p", "q"],
                path: "src/p/q/mod.rs",
                source: "pub mod r;\n",
            },
            File {
                module: &["p", "q", "r"],
                path: "src/p/q/r.rs",
                source: "macro_rules! deep { () => {} }\npub(crate) use deep;\n",
            },
        ],
    }];
    let table = build(&crates, &[]);
    assert_eq!(
        resolve_in_file(
            &table,
            "app",
            &crates[0].files[0],
            "crate::p::q::r::deep!",
            0
        ),
        "workspace app:src/p/q/r.rs:1"
    );
}

// ---------------------------------------------------------------------------
// #[macro_use] extern crate and dependency macros
// ---------------------------------------------------------------------------

#[test]
fn macro_use_extern_crate_of_a_workspace_crate_expands_instead_of_attributing() {
    let crates = vec![
        TestCrate {
            name: "lib_crate",
            files: vec![File {
                module: &[],
                path: "src/lib.rs",
                source: "#[macro_export]\nmacro_rules! shout { () => {} }\n",
            }],
        },
        TestCrate {
            name: "app",
            files: vec![File {
                module: &[],
                path: "src/lib.rs",
                source: "#[macro_use]\nextern crate lib_crate;\nfn f() { shout!(); }\n",
            }],
        },
    ];
    let table = build(&crates, &["lib_crate"]);
    assert_eq!(
        resolve_in_file(&table, "app", &crates[1].files[0], "shout!", 0),
        "workspace lib_crate:src/lib.rs:2"
    );
}

#[test]
fn dependency_macros_resolve_through_every_import_form() {
    let source = "#[macro_use]\nextern crate log;\n\
                  use anyhow::bail;\nuse log::warn as w;\nuse serde_json as sj;\n\
                  fn f() { serde_json::json!(); bail!(); w!(); sj::json!(); trace!(); }\n";
    let (table, krate) = {
        let krate = TestCrate {
            name: "app",
            files: vec![File {
                module: &[],
                path: "src/lib.rs",
                source,
            }],
        };
        (
            build(
                std::slice::from_ref(&krate),
                &["log", "anyhow", "serde_json"],
            ),
            krate,
        )
    };
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "serde_json::json!", 0),
        "dependency serde_json::json"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "bail!", 0),
        "dependency anyhow::bail"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "w!", 0),
        "dependency log::warn"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "sj::json!", 0),
        "dependency serde_json::json"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "trace!", 0),
        "dependency log::trace"
    );
}

#[test]
fn an_extern_crate_alias_names_the_dependency() {
    let krate = TestCrate {
        name: "app",
        files: vec![File {
            module: &[],
            path: "src/lib.rs",
            source: "extern crate serde_json as sj;\nfn f() { sj::json!(); }\n",
        }],
    };
    let table = build(std::slice::from_ref(&krate), &["serde_json"]);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "sj::json!", 0),
        "dependency serde_json::json"
    );
}

#[test]
fn a_bare_name_two_extern_crates_could_supply_is_not_guessed() {
    let krate = TestCrate {
        name: "app",
        files: vec![File {
            module: &[],
            path: "src/lib.rs",
            source: "#[macro_use]\nextern crate log;\n#[macro_use]\nextern crate tracing;\n\
                     fn f() { info!(); dbg!(); }\n",
        }],
    };
    let table = build(std::slice::from_ref(&krate), &["log", "tracing"]);
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "info!", 0),
        "ambiguous log::info,tracing::info"
    );
    // A standard-library macro is never attributed to an extern crate.
    assert_eq!(resolve_in_file(&table, "app", file, "dbg!", 0), "std");
}

#[test]
fn the_standard_library_list_covers_the_current_macros() {
    for name in [
        "dbg",
        "is_x86_feature_detected",
        "is_aarch64_feature_detected",
        "println",
        "vec",
        "format",
        "matches",
        "todo",
        "thread_local",
        "assert_eq",
    ] {
        assert!(is_std_macro(name), "{name} should be a std macro");
    }
    for name in ["info", "json", "bail", "my_macro", "lazy_static"] {
        assert!(!is_std_macro(name), "{name} is not a std macro");
    }
    let (table, krate) = single("fn f() { std::println!(); core::panic!(); }\n");
    let file = &krate.files[0];
    assert_eq!(
        resolve_in_file(&table, "app", file, "std::println!", 0),
        "std"
    );
    assert_eq!(
        resolve_in_file(&table, "app", file, "core::panic!", 0),
        "std"
    );
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

#[test]
fn definitions_carry_their_name_signature_and_canonical_path() {
    let source = "macro_rules! plain { () => {} }\n\
                  #[macro_export]\nmacro_rules! shared { () => {} }\n\
                  mod m { macro_rules! inner { () => {} } }\n";
    let krate = TestCrate {
        name: "app",
        files: vec![File {
            module: &[],
            path: "src/lib.rs",
            source,
        }],
    };
    let table = build(std::slice::from_ref(&krate), &[]);
    let plain = table
        .find_definition("app", &[], "src/lib.rs", "plain", (1, 13))
        .expect("plain is collected");
    assert_eq!(plain.1, "app::plain");
    assert_eq!(plain.0.signature(), "macro_rules! plain");
    let shared = table
        .find_definition("app", &[], "src/lib.rs", "shared", (3, 13))
        .expect("shared is collected");
    assert_eq!(shared.1, "app::shared");
    assert_eq!(shared.0.signature(), "#[macro_export] macro_rules! shared");
    // Looking at the wrong position or module finds nothing.
    assert!(
        table
            .find_definition("app", &[], "src/lib.rs", "plain", (2, 13))
            .is_none()
    );
    assert!(
        table
            .find_definition("app", &["m".to_string()], "src/lib.rs", "inner", (4, 21))
            .is_some_and(|(_, path)| path == "app::m::inner")
    );
}

#[test]
fn definitions_with_unreadable_bodies_are_skipped_not_fatal() {
    let source = "macro_rules! broken { not rules }\nmacro_rules! ok { () => {} }\nok!();\n";
    let (table, krate) = single(source);
    assert_eq!(
        resolve_in_file(&table, "app", &krate.files[0], "ok!", 0),
        "workspace app:src/lib.rs:2"
    );
}
