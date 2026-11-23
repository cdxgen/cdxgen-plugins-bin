//! Analysis of several crate directories in one report.
//!
//! Each directory is analyzed on its own (its own `cargo metadata`, its own
//! call graph), then the reports are merged. Every file path in the merged
//! report is relative to one root, and every id carries a suffix naming the
//! directory it came from, so ids stay unique when two crates declare the
//! same function in a file of the same name.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusi_schema::{CallGraph, CryptoEvidence, DataFlowEvidence, Report, stable_id};
use serde_json::Value;

/// Directory names never entered while looking for crates.
const SKIPPED_DIRECTORIES: &[&str] = &["target", ".git"];

/// One analyzed crate directory, relative to the report root.
pub struct CrateReport {
    /// Directory of the crate relative to the root, with `/` separators. Empty
    /// when the crate is the root.
    pub prefix: String,
    pub report: Report,
}

/// Directory of `dir` relative to `root` in the form reports use.
pub fn root_relative_prefix(root: &Path, dir: &Path) -> Result<String> {
    let relative = dir.strip_prefix(root).with_context(|| {
        format!(
            "{} is not inside the report root {}",
            dir.display(),
            root.display()
        )
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

/// The deepest directory that contains every one of `dirs`.
pub fn common_root(dirs: &[PathBuf]) -> Option<PathBuf> {
    let mut common: Option<PathBuf> = None;
    for dir in dirs {
        common = Some(match common {
            None => dir.clone(),
            Some(current) => current
                .components()
                .zip(dir.components())
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect(),
        });
    }
    common
}

/// Find every crate or workspace below `root`.
///
/// A directory with a `Cargo.toml` is one analysis unit and is not entered
/// further: a workspace root covers its members, and a crate without a
/// workspace is its own unit. `target/` and `.git` are never entered, and a
/// directory whose path relative to `root` matches an `exclude` pattern is
/// skipped (see [`glob_matches`]). The result is sorted.
pub fn discover_crate_dirs(root: &Path, exclude: &[String]) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    walk_for_crates(root, "", exclude, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk_for_crates(
    dir: &Path,
    relative: &str,
    exclude: &[String],
    found: &mut Vec<PathBuf>,
) -> Result<()> {
    if !relative.is_empty()
        && exclude
            .iter()
            .any(|pattern| glob_matches(pattern, relative))
    {
        return Ok(());
    }
    if dir.join("Cargo.toml").is_file() {
        found.push(dir.to_path_buf());
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => bail!("failed to read {}: {error}", dir.display()),
    };
    for entry in entries {
        let entry = entry?;
        // `file_type` does not follow symlinks, so a link cannot send the walk
        // out of the root or around a cycle.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if SKIPPED_DIRECTORIES.contains(&name.as_str()) {
            continue;
        }
        let child = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        walk_for_crates(&entry.path(), &child, exclude, found)?;
    }
    Ok(())
}

/// Match `path` (relative to the scanned root, `/` separators) against an
/// exclude glob with the semantics cdxgen gives `--exclude`: the pattern is
/// anchored at the root, `*` and `?` stay inside one path segment, `**` as a
/// whole segment spans any number of segments (including none), and a pattern
/// ending in `/**` also matches the directory itself. A leading `./` on the
/// pattern is ignored.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let pattern_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segments_match(&pattern_segments, &path_segments)
}

fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| segments_match(rest, &path[skip..])),
        Some((segment, rest)) => match path.split_first() {
            Some((name, tail)) => segment_matches(segment, name) && segments_match(rest, tail),
            None => false,
        },
    }
}

fn segment_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Merge per-directory reports into one whose file paths are relative to
/// `root` and whose ids are unique across directories.
///
/// With one entry and an empty prefix the report is returned unchanged, so a
/// single-directory run is byte-identical to one that never went through here.
pub fn merge_reports(root: &Path, mut parts: Vec<CrateReport>) -> Result<Report> {
    if parts.len() == 1 && parts[0].prefix.is_empty() {
        return Ok(parts.remove(0).report);
    }
    let mut merged: Option<Report> = None;
    for part in parts {
        let report = rebase_report(part.report, &part.prefix)?;
        merged = Some(match merged {
            None => report,
            Some(into) => absorb(into, report),
        });
    }
    let mut merged = merged.context("no reports to merge")?;
    let root_text = root.display().to_string();
    merged.runtime.working_directory = root_text.clone();
    merged.options.directory = root_text;
    Ok(merged)
}

/// Prefix every file path of `report` with `prefix` and suffix every id with a
/// tag derived from `prefix`.
///
/// The rewrite works on the serialized form so that a field added to the
/// schema later is covered without a change here: ids are recognized by shape
/// and by having been declared as an `id`, and file paths by the key they
/// sit under (`file_path`, `filename`) or by being one of the report's own
/// file paths.
fn rebase_report(report: Report, prefix: &str) -> Result<Report> {
    let mut value = serde_json::to_value(&report)?;
    drop(report);
    let tag = stable_id("c", &[prefix]);
    let mut declared = BTreeSet::new();
    collect_ids(&value, &mut declared);
    let mut own_files = BTreeSet::new();
    collect_own_files(&value, &mut own_files);
    rewrite(&mut value, None, prefix, &tag, &declared, &own_files);
    Ok(serde_json::from_value(value)?)
}

fn collect_ids(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "id"
                    && let Value::String(id) = child
                {
                    into.insert(id.clone());
                }
                collect_ids(child, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_ids(item, into)),
        _ => {}
    }
}

fn collect_own_files(value: &Value, into: &mut BTreeSet<String>) {
    for file in value["files"].as_array().into_iter().flatten() {
        if let Some(path) = file["path"].as_str() {
            into.insert(path.to_string());
        }
    }
    for package in value["packages"].as_array().into_iter().flatten() {
        for path in package["files"].as_array().into_iter().flatten() {
            if let Some(path) = path.as_str() {
                into.insert(path.to_string());
            }
        }
    }
}

fn looks_like_id(text: &str) -> bool {
    match text.rsplit_once('-') {
        Some((prefix, hex)) => {
            !prefix.is_empty()
                && hex.len() == 16
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && prefix.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        }
        None => false,
    }
}

fn is_absolute_path(text: &str) -> bool {
    Path::new(text).is_absolute()
        || text.starts_with('/')
        || text.as_bytes().get(1) == Some(&b':')
        || text.starts_with("\\\\")
}

fn join_prefix(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}/{path}")
    }
}

fn rewrite(
    value: &mut Value,
    key: Option<&str>,
    prefix: &str,
    tag: &str,
    declared: &BTreeSet<String>,
    own_files: &BTreeSet<String>,
) {
    match value {
        Value::String(text) => {
            if declared.contains(text.as_str()) || looks_like_id(text) {
                *text = format!("{text}@{tag}");
            } else if !prefix.is_empty()
                && !text.is_empty()
                && (own_files.contains(text.as_str())
                    || (matches!(key, Some("file_path" | "filename")) && !is_absolute_path(text)))
            {
                *text = join_prefix(prefix, text);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite(item, key, prefix, tag, declared, own_files);
            }
        }
        Value::Object(map) => {
            for (child_key, child) in map.iter_mut() {
                rewrite(child, Some(child_key), prefix, tag, declared, own_files);
            }
        }
        _ => {}
    }
}

fn absorb(mut into: Report, from: Report) -> Report {
    into.modules.extend(from.modules);
    into.packages.extend(from.packages);
    into.files.extend(from.files);
    into.imports.extend(from.imports);
    into.declarations.extend(from.declarations);
    into.usages.extend(from.usages);
    into.security_signals.extend(from.security_signals);
    into.api_endpoints.extend(from.api_endpoints);
    into.diagnostics.extend(from.diagnostics);
    into.crypto = merge_crypto(into.crypto.take(), from.crypto);
    into.call_graph = merge_call_graph(into.call_graph.take(), from.call_graph);
    into.data_flow = merge_data_flow(into.data_flow.take(), from.data_flow);
    let stats = &mut into.stats;
    let other = from.stats;
    stats.package_count += other.package_count;
    stats.file_count += other.file_count;
    stats.import_count += other.import_count;
    stats.declaration_count += other.declaration_count;
    stats.usage_count += other.usage_count;
    stats.security_signal_count += other.security_signal_count;
    stats.crypto_library_count += other.crypto_library_count;
    stats.crypto_component_count += other.crypto_component_count;
    stats.crypto_material_count += other.crypto_material_count;
    stats.crypto_finding_count += other.crypto_finding_count;
    stats.call_graph_node_count += other.call_graph_node_count;
    stats.call_graph_edge_count += other.call_graph_edge_count;
    stats.data_flow_node_count += other.data_flow_node_count;
    stats.data_flow_edge_count += other.data_flow_edge_count;
    stats.data_flow_slice_count += other.data_flow_slice_count;
    stats.api_endpoint_count += other.api_endpoint_count;
    into
}

fn merge_crypto(
    into: Option<CryptoEvidence>,
    from: Option<CryptoEvidence>,
) -> Option<CryptoEvidence> {
    match (into, from) {
        (Some(mut into), Some(from)) => {
            into.libraries.extend(from.libraries);
            into.components.extend(from.components);
            into.materials.extend(from.materials);
            into.findings.extend(from.findings);
            for (key, value) in from.properties {
                into.properties.entry(key).or_insert(value);
            }
            Some(into)
        }
        (into, from) => into.or(from),
    }
}

fn merge_call_graph(into: Option<CallGraph>, from: Option<CallGraph>) -> Option<CallGraph> {
    match (into, from) {
        (Some(mut into), Some(from)) => {
            into.nodes.extend(from.nodes);
            into.edges.extend(from.edges);
            into.diagnostics.extend(from.diagnostics);
            into.stats.node_count += from.stats.node_count;
            into.stats.edge_count += from.stats.edge_count;
            Some(into)
        }
        (into, from) => into.or(from),
    }
}

fn merge_data_flow(
    into: Option<DataFlowEvidence>,
    from: Option<DataFlowEvidence>,
) -> Option<DataFlowEvidence> {
    match (into, from) {
        (Some(mut into), Some(from)) => {
            into.nodes.extend(from.nodes);
            into.edges.extend(from.edges);
            into.slices.extend(from.slices);
            into.summaries.extend(from.summaries);
            into.diagnostics.extend(from.diagnostics);
            let stats = &mut into.stats;
            stats.source_count += from.stats.source_count;
            stats.sink_count += from.stats.sink_count;
            stats.slice_count += from.stats.slice_count;
            stats.node_count += from.stats.node_count;
            stats.edge_count += from.stats.edge_count;
            stats.summary_count += from.stats.summary_count;
            Some(into)
        }
        (into, from) => into.or(from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_is_anchored_and_segment_bound() {
        assert!(glob_matches("test/**", "test"));
        assert!(glob_matches("test/**", "test/a/b"));
        assert!(!glob_matches("test/**", "sub/test"));
        assert!(glob_matches("**/test/**", "sub/deep/test"));
        assert!(glob_matches("**/test/**", "test"));
        assert!(glob_matches("*/test/**", "sub/test"));
        assert!(!glob_matches("*/test/**", "test"));
        assert!(!glob_matches("*/test/**", "a/b/test"));
        assert!(glob_matches("./thirdparty/*", "thirdparty/golem"));
        assert!(!glob_matches("thirdparty/*", "thirdparty/golem/x"));
        assert!(glob_matches("thirdparty/g*m", "thirdparty/golem"));
        assert!(!glob_matches("probe/test/**", "test"));
    }

    #[test]
    fn common_root_is_the_deepest_shared_directory() {
        let dirs = vec![
            PathBuf::from("/r/thirdparty/a"),
            PathBuf::from("/r/thirdparty/b"),
        ];
        assert_eq!(common_root(&dirs), Some(PathBuf::from("/r/thirdparty")));
        assert_eq!(
            common_root(&dirs[..1]),
            Some(PathBuf::from("/r/thirdparty/a"))
        );
        assert_eq!(common_root(&[]), None);
    }

    #[test]
    fn ids_are_recognized_by_shape() {
        assert!(looks_like_id("decl-0123456789abcdef"));
        assert!(looks_like_id("cg-node-0123456789abcdef"));
        assert!(!looks_like_id("decl-0123456789abcdeg"));
        assert!(!looks_like_id("main"));
        assert!(!looks_like_id("some-crate-name"));
    }

    #[test]
    fn discovery_stops_at_manifests_and_skips_target_and_excluded_trees() {
        let root = std::env::temp_dir().join(format!("rusi-discover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for dir in [
            "a",
            "group/b",
            "group/b/nested",
            "target/stray",
            "vendor/c",
            "plain/deeper",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        for dir in ["a", "group/b", "group/b/nested", "target/stray", "vendor/c"] {
            fs::write(root.join(dir).join("Cargo.toml"), "[package]\n").unwrap();
        }
        let found = discover_crate_dirs(&root, &["vendor/**".to_string()]).unwrap();
        assert_eq!(found, vec![root.join("a"), root.join("group/b")]);
        let all = discover_crate_dirs(&root, &[]).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&root.join("vendor/c")));
        fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
        assert_eq!(discover_crate_dirs(&root, &[]).unwrap(), vec![root.clone()]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_relative_file_path_outside_the_file_list_is_still_prefixed() {
        use rusi_schema::{Diagnostic, Position};
        let mut report = Report::default();
        report.diagnostics.push(Diagnostic {
            kind: "module-resolution".to_string(),
            message: "note".to_string(),
            package_path: None,
            file_path: Some("src/not_listed.rs".to_string()),
            position: Some(Position {
                filename: "src/also_not_listed.rs".to_string(),
                line: 1,
                column: 1,
            }),
        });
        report.diagnostics.push(Diagnostic {
            kind: "backend".to_string(),
            message: "absolute stays".to_string(),
            package_path: None,
            file_path: Some("/abs/elsewhere.rs".to_string()),
            position: None,
        });
        let rebased = rebase_report(report, "crates/a").unwrap();
        assert_eq!(
            rebased.diagnostics[0].file_path.as_deref(),
            Some("crates/a/src/not_listed.rs")
        );
        assert_eq!(
            rebased.diagnostics[0].position.as_ref().unwrap().filename,
            "crates/a/src/also_not_listed.rs"
        );
        assert_eq!(
            rebased.diagnostics[1].file_path.as_deref(),
            Some("/abs/elsewhere.rs")
        );
    }
}
