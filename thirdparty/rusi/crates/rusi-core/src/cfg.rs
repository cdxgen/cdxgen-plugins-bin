//! Conditional-compilation evaluation for the stable backend.
//!
//! The stable backend parses source with `syn` and therefore sees every item in
//! a file, including the ones `rustc` would have discarded: `#[cfg(test)]`
//! modules, platform-specific blocks, and code behind disabled Cargo features.
//! Without evaluation those items produce declarations, call-graph nodes, and
//! taint flows that do not exist in the artifact actually built.
//!
//! This module resolves the active cfg set (target atoms from `rustc --print
//! cfg`, features from the resolved Cargo dependency graph) and evaluates
//! `#[cfg(...)]` attributes against it.
//!
//! Evaluation is deliberately tri-state. A predicate we cannot interpret stays
//! `Unknown` and keeps the item enabled, so an unfamiliar cfg shape loses
//! evidence in neither direction; only a definitively false predicate drops
//! code.

use std::collections::BTreeSet;

use cargo_metadata::{Metadata, Package};
use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

/// The active conditional-compilation environment: bare atoms such as `unix`
/// plus key/value pairs such as `target_os = "linux"` and `feature = "tls"`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CfgOptions {
    atoms: BTreeSet<String>,
    key_values: BTreeSet<(String, String)>,
}

impl CfgOptions {
    /// Builds the environment from `rustc --print cfg`, falling back to the
    /// atoms we can derive from the host when `rustc` is unavailable.
    pub(crate) fn from_host() -> Self {
        let output = crate::capture_command_output("rustc", &["--print", "cfg"]);
        if output != "unknown" {
            let parsed = Self::from_rustc_cfg_output(&output);
            if !parsed.is_empty() {
                return parsed;
            }
        }
        Self::from_host_constants()
    }

    /// Parses the `key="value"` / `atom` lines emitted by `rustc --print cfg`.
    pub(crate) fn from_rustc_cfg_output(output: &str) -> Self {
        let mut options = Self::default();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.split_once('=') {
                Some((key, value)) => {
                    let value = value.trim().trim_matches('"');
                    options.insert_key_value(key.trim(), value);
                }
                None => options.insert_atom(line),
            }
        }
        options
    }

    /// Derives what we can from the compile-time host constants. Coarser than
    /// `rustc --print cfg`, but enough for the common `unix`/`windows` and
    /// `target_os` gates.
    fn from_host_constants() -> Self {
        let mut options = Self::default();
        options.insert_key_value("target_os", std::env::consts::OS);
        options.insert_key_value("target_arch", std::env::consts::ARCH);
        options.insert_key_value("target_pointer_width", &(usize::BITS as usize).to_string());
        options.insert_key_value(
            "target_endian",
            if cfg!(target_endian = "big") {
                "big"
            } else {
                "little"
            },
        );
        let family = if cfg!(windows) {
            "windows"
        } else if cfg!(unix) {
            "unix"
        } else {
            ""
        };
        if !family.is_empty() {
            options.insert_atom(family);
            options.insert_key_value("target_family", family);
        }
        options
    }

    /// Adds `feature = "..."` entries for the features Cargo actually resolved
    /// for `package`. Falls back to the manifest's `default` feature closure
    /// when the metadata carries no resolve graph (`--no-deps`).
    pub(crate) fn insert_package_features(&mut self, metadata: &Metadata, package: &Package) {
        let resolved = metadata.resolve.as_ref().and_then(|resolve| {
            resolve
                .nodes
                .iter()
                .find(|node| node.id == package.id)
                .map(|node| {
                    node.features
                        .iter()
                        .map(|feature| feature.to_string())
                        .collect::<Vec<String>>()
                })
        });
        // An empty resolved set is an answer, not missing data: a dependency
        // pulled in with `default-features = false` legitimately has no
        // features enabled, and falling back to the manifest's `default`
        // closure there would enable code Cargo never compiled.
        let features = match resolved {
            Some(features) => features,
            None => Self::default_feature_closure(package),
        };
        for feature in features {
            self.insert_key_value("feature", &feature);
        }
    }

    /// Expands the manifest's `default` feature transitively. Only used when no
    /// resolve graph is available.
    fn default_feature_closure(package: &Package) -> Vec<String> {
        let mut closure = BTreeSet::new();
        let mut pending = vec!["default".to_string()];
        while let Some(feature) = pending.pop() {
            if !package.features.contains_key(&feature) || !closure.insert(feature.clone()) {
                continue;
            }
            for dependent in package.features.get(&feature).into_iter().flatten() {
                // `dep:foo` and `foo/bar` activate dependencies, not features of
                // this package, so they never become `feature = "..."` atoms.
                if !dependent.contains(':') && !dependent.contains('/') {
                    pending.push(dependent.clone());
                }
            }
        }
        closure.into_iter().collect()
    }

    pub(crate) fn insert_atom(&mut self, atom: &str) {
        self.atoms.insert(atom.to_string());
    }

    pub(crate) fn insert_key_value(&mut self, key: &str, value: &str) {
        self.key_values.insert((key.to_string(), value.to_string()));
    }

    fn is_empty(&self) -> bool {
        self.atoms.is_empty() && self.key_values.is_empty()
    }

    fn contains_atom(&self, atom: &str) -> bool {
        self.atoms.contains(atom)
    }

    fn contains_key_value(&self, key: &str, value: &str) -> bool {
        self.key_values
            .contains(&(key.to_string(), value.to_string()))
    }

    /// Whether `key` is one we claim to know the full value set of. Used so an
    /// unlisted `target_os = "redox"` resolves to false rather than unknown,
    /// while a key we never populated (say `tokio_unstable`) stays unknown.
    fn knows_key(&self, key: &str) -> bool {
        self.key_values.iter().any(|(known, _)| known == key)
    }
}

/// One `cfg` predicate. `Unknown` covers shapes we do not interpret, so they
/// can propagate through `all`/`any`/`not` without silently flipping to false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CfgPredicate {
    Atom(String),
    KeyValue { key: String, value: String },
    All(Vec<CfgPredicate>),
    Any(Vec<CfgPredicate>),
    Not(Box<CfgPredicate>),
    Unknown,
}

impl CfgPredicate {
    fn from_meta(meta: &Meta) -> Self {
        match meta {
            Meta::Path(path) => match path.get_ident() {
                Some(ident) => Self::Atom(ident.to_string()),
                None => Self::Unknown,
            },
            Meta::NameValue(name_value) => {
                let Some(ident) = name_value.path.get_ident() else {
                    return Self::Unknown;
                };
                match &name_value.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }) => Self::KeyValue {
                        key: ident.to_string(),
                        value: value.value(),
                    },
                    _ => Self::Unknown,
                }
            }
            Meta::List(list) => {
                let Some(ident) = list.path.get_ident() else {
                    return Self::Unknown;
                };
                let Ok(nested) = list
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    .map(|nested| nested.iter().map(Self::from_meta).collect::<Vec<_>>())
                else {
                    return Self::Unknown;
                };
                match ident.to_string().as_str() {
                    "all" => Self::All(nested),
                    "any" => Self::Any(nested),
                    "not" => match <[Self; 1]>::try_from(nested) {
                        Ok([inner]) => Self::Not(Box::new(inner)),
                        // `not` takes exactly one predicate; anything else is
                        // not something we should guess about.
                        Err(_) => Self::Unknown,
                    },
                    _ => Self::Unknown,
                }
            }
        }
    }

    /// Renders the predicate back to `cfg`-attribute syntax for reporting.
    fn display(&self) -> String {
        match self {
            Self::Atom(atom) => atom.clone(),
            Self::KeyValue { key, value } => format!("{key} = \"{value}\""),
            Self::All(nested) => format!("all({})", Self::display_list(nested)),
            Self::Any(nested) => format!("any({})", Self::display_list(nested)),
            Self::Not(inner) => format!("not({})", inner.display()),
            Self::Unknown => "?".to_string(),
        }
    }

    fn display_list(nested: &[Self]) -> String {
        nested
            .iter()
            .map(Self::display)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The conjunction of every `#[cfg(...)]` attribute written on one item. An
/// empty expression means unconditional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CfgExpr {
    predicates: Vec<CfgPredicate>,
}

impl CfgExpr {
    pub(crate) fn from_attrs(attrs: &[Attribute]) -> Self {
        let mut predicates = Vec::new();
        for attr in attrs {
            if !attr.path().is_ident("cfg") {
                continue;
            }
            match attr.parse_args::<Meta>() {
                Ok(meta) => predicates.push(CfgPredicate::from_meta(&meta)),
                // A `cfg` we cannot even parse must not drop the item.
                Err(_) => predicates.push(CfgPredicate::Unknown),
            }
        }
        Self { predicates }
    }

    /// The gate as written, for attaching to emitted evidence.
    pub(crate) fn display(&self) -> Option<String> {
        if self.predicates.is_empty() {
            return None;
        }
        Some(
            self.predicates
                .iter()
                .map(CfgPredicate::display)
                .collect::<Vec<_>>()
                .join(" && "),
        )
    }
}

/// Tri-state evaluation result. `Unknown` is treated as enabled by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfgOutcome {
    True,
    False,
    Unknown,
}

impl CfgOutcome {
    fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Evaluates `CfgExpr` against a resolved environment.
///
/// `test_enabled` mirrors `--include-tests`: with tests excluded, `cfg(test)`
/// is definitively false, which is what removes inline `#[cfg(test)] mod tests`
/// blocks from the evidence.
#[derive(Debug, Clone)]
pub(crate) struct CfgEvaluator {
    options: CfgOptions,
    test_enabled: bool,
}

impl CfgEvaluator {
    pub(crate) fn new(options: CfgOptions, test_enabled: bool) -> Self {
        Self {
            options,
            test_enabled,
        }
    }

    /// An evaluator that keeps everything, for callers that opt out of cfg
    /// filtering.
    #[cfg(test)]
    pub(crate) fn permissive() -> Self {
        Self {
            options: CfgOptions::default(),
            test_enabled: true,
        }
    }

    pub(crate) fn attrs_enabled(&self, attrs: &[Attribute]) -> bool {
        self.is_enabled(&CfgExpr::from_attrs(attrs))
    }

    pub(crate) fn is_enabled(&self, expr: &CfgExpr) -> bool {
        expr.predicates
            .iter()
            .all(|predicate| self.evaluate(predicate) != CfgOutcome::False)
    }

    fn evaluate(&self, predicate: &CfgPredicate) -> CfgOutcome {
        match predicate {
            CfgPredicate::Atom(atom) => match atom.as_str() {
                "test" | "doctest" => {
                    if self.test_enabled {
                        CfgOutcome::True
                    } else {
                        CfgOutcome::False
                    }
                }
                // `unix`/`windows` and the other target atoms are fully
                // enumerated by `rustc --print cfg`, so absence means false.
                "unix" | "windows" => {
                    if self.options.contains_atom(atom) {
                        CfgOutcome::True
                    } else {
                        CfgOutcome::False
                    }
                }
                _ => {
                    if self.options.contains_atom(atom) {
                        CfgOutcome::True
                    } else {
                        // A bare atom we never populated is a custom cfg set by
                        // a build script or RUSTFLAGS; we cannot rule it out.
                        CfgOutcome::Unknown
                    }
                }
            },
            CfgPredicate::KeyValue { key, value } => {
                if self.options.contains_key_value(key, value) {
                    CfgOutcome::True
                } else if key == "feature" || self.options.knows_key(key) {
                    // Features come from the resolved graph and target keys from
                    // rustc, so both value sets are complete.
                    CfgOutcome::False
                } else {
                    CfgOutcome::Unknown
                }
            }
            CfgPredicate::All(nested) => {
                let mut outcome = CfgOutcome::True;
                for inner in nested {
                    match self.evaluate(inner) {
                        CfgOutcome::False => return CfgOutcome::False,
                        CfgOutcome::Unknown => outcome = CfgOutcome::Unknown,
                        CfgOutcome::True => {}
                    }
                }
                outcome
            }
            CfgPredicate::Any(nested) => {
                let mut outcome = CfgOutcome::False;
                for inner in nested {
                    match self.evaluate(inner) {
                        CfgOutcome::True => return CfgOutcome::True,
                        CfgOutcome::Unknown => outcome = CfgOutcome::Unknown,
                        CfgOutcome::False => {}
                    }
                }
                outcome
            }
            CfgPredicate::Not(inner) => self.evaluate(inner).negate(),
            CfgPredicate::Unknown => CfgOutcome::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluator(test_enabled: bool) -> CfgEvaluator {
        let mut options = CfgOptions::default();
        options.insert_atom("unix");
        options.insert_key_value("target_os", "linux");
        options.insert_key_value("target_family", "unix");
        options.insert_key_value("feature", "tls");
        CfgEvaluator::new(options, test_enabled)
    }

    fn enabled(source: &str, test_enabled: bool) -> bool {
        let item: syn::ItemFn = syn::parse_str(source).expect("fixture parses");
        evaluator(test_enabled).attrs_enabled(&item.attrs)
    }

    #[test]
    fn unconditional_items_stay_enabled() {
        assert!(enabled("fn plain() {}", false));
    }

    #[test]
    fn test_gate_follows_include_tests() {
        assert!(!enabled("#[cfg(test)] fn gated() {}", false));
        assert!(enabled("#[cfg(test)] fn gated() {}", true));
    }

    #[test]
    fn active_and_inactive_targets_are_distinguished() {
        assert!(enabled("#[cfg(unix)] fn gated() {}", false));
        assert!(!enabled("#[cfg(windows)] fn gated() {}", false));
        assert!(enabled(
            r#"#[cfg(target_os = "linux")] fn gated() {}"#,
            false
        ));
        assert!(!enabled(
            r#"#[cfg(target_os = "macos")] fn gated() {}"#,
            false
        ));
    }

    #[test]
    fn features_resolve_against_the_active_set() {
        assert!(enabled(r#"#[cfg(feature = "tls")] fn gated() {}"#, false));
        assert!(!enabled(r#"#[cfg(feature = "ldap")] fn gated() {}"#, false));
    }

    #[test]
    fn combinators_compose() {
        assert!(enabled(
            r#"#[cfg(all(unix, feature = "tls"))] fn gated() {}"#,
            false
        ));
        assert!(!enabled(
            r#"#[cfg(all(unix, feature = "ldap"))] fn gated() {}"#,
            false
        ));
        assert!(enabled(
            r#"#[cfg(any(windows, feature = "tls"))] fn gated() {}"#,
            false
        ));
        assert!(!enabled("#[cfg(any(windows, test))] fn gated() {}", false));
        assert!(enabled("#[cfg(not(windows))] fn gated() {}", false));
        assert!(!enabled("#[cfg(not(unix))] fn gated() {}", false));
    }

    #[test]
    fn stacked_cfg_attrs_are_conjunctive() {
        assert!(!enabled(
            r#"#[cfg(unix)] #[cfg(feature = "ldap")] fn gated() {}"#,
            false
        ));
    }

    #[test]
    fn unknown_predicates_keep_the_item() {
        // A custom cfg from RUSTFLAGS or a build script: unknown, so kept, and
        // its negation stays unknown rather than dropping code.
        assert!(enabled("#[cfg(tokio_unstable)] fn gated() {}", false));
        assert!(enabled("#[cfg(not(tokio_unstable))] fn gated() {}", false));
        assert!(enabled(r#"#[cfg(nightly = "yes")] fn gated() {}"#, false));
    }

    #[test]
    fn unknown_does_not_mask_a_definite_false() {
        assert!(!enabled(
            "#[cfg(all(tokio_unstable, windows))] fn gated() {}",
            false
        ));
        assert!(enabled(
            "#[cfg(any(tokio_unstable, windows))] fn gated() {}",
            false
        ));
    }

    #[test]
    fn rustc_cfg_output_is_parsed() {
        let options = CfgOptions::from_rustc_cfg_output(
            "unix\ntarget_os=\"linux\"\ntarget_pointer_width=\"64\"\n",
        );
        assert!(options.contains_atom("unix"));
        assert!(options.contains_key_value("target_os", "linux"));
        assert!(options.contains_key_value("target_pointer_width", "64"));
    }

    #[test]
    fn gate_display_round_trips() {
        let item: syn::ItemFn =
            syn::parse_str(r#"#[cfg(all(unix, not(feature = "ldap")))] fn gated() {}"#)
                .expect("fixture parses");
        assert_eq!(
            CfgExpr::from_attrs(&item.attrs).display().as_deref(),
            Some("all(unix, not(feature = \"ldap\"))")
        );
    }
}
