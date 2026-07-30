//! bom-ref graph helpers.
//!
//! Utilities for walking the component/dependency graph by bom-ref.

use serde_json::Value;

/// Collect all bom-ref values from top-level components, nested sub-components,
/// services, and metadata.component.
///
/// Returns a sorted, deduplicated vector of bom-ref strings.
pub fn collect_bom_refs(bom: &Value) -> Vec<String> {
    let mut refs = Vec::new();

    fn walk_component(comp: &Value, refs: &mut Vec<String>) {
        if let Some(r) = comp.get("bom-ref").and_then(|v| v.as_str()) {
            refs.push(r.to_string());
        }
        if let Some(subs) = comp.get("components").and_then(|v| v.as_array()) {
            for sub in subs {
                walk_component(sub, refs);
            }
        }
    }

    if let Some(meta_comp) = bom.get("metadata").and_then(|m| m.get("component")) {
        walk_component(meta_comp, &mut refs);
    }

    if let Some(comps) = bom.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            walk_component(comp, &mut refs);
        }
    }

    if let Some(services) = bom.get("services").and_then(|v| v.as_array()) {
        for svc in services {
            if let Some(r) = svc.get("bom-ref").and_then(|v| v.as_str()) {
                refs.push(r.to_string());
            }
        }
    }

    refs.sort();
    refs.dedup();
    refs
}

/// Build a map from bom-ref → dependency list from the BOM's `dependencies`
/// array.
pub fn build_dep_graph(bom: &Value) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut graph = std::collections::BTreeMap::new();
    if let Some(deps) = bom.get("dependencies").and_then(|v| v.as_array()) {
        for dep in deps {
            let r#ref = dep
                .get("ref")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let depends_on: Vec<String> = dep
                .get("dependsOn")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if !r#ref.is_empty() {
                graph.insert(r#ref, depends_on);
            }
        }
    }
    graph
}
