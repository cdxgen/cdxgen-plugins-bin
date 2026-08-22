//! `cdxrs info` — reads a BOM and prints summary statistics.
//!
//! Output is a single JSON object on stdout:
//! ```json
//! {
//!   "specVersion": "1.6",
//!   "bomFormat": "CycloneDX",
//!   "componentCount": 42,
//!   "dependencyCount": 35,
//!   "serviceCount": 0,
//!   "vulnerabilityCount": 0,
//!   "hasEvidence": true,
//!   "cdxrsVersion": "3.0.0"
//! }
//! ```
//!
//! Trivial on purpose — it exercises the bridge, protocol, exit codes,
//! logging, and cross-build via a real subcommand.

use serde_json::{Value, json};

use crate::bom::read;
use crate::error::CdxrsError;
use crate::io as io_mod;

/// Default max input for the info subcommand.
const INFO_MAX_INPUT_BYTES: u64 = crate::io::DEFAULT_MAX_INPUT_BYTES;

/// Execute the `info` subcommand.
///
/// Reads the BOM from `input_path` (or stdin if "-"), computes summary
/// statistics, and writes the result to `output_path` (or stdout).
pub fn run(
    input_path: &str,
    output_path: &Option<String>,
    max_input_bytes: Option<u64>,
) -> Result<(), CdxrsError> {
    let max_bytes = max_input_bytes.unwrap_or(INFO_MAX_INPUT_BYTES);

    let data = io_mod::read_input(input_path, max_bytes)?;
    let bom = read::parse_value(&data)?;
    let result = compute_info(&bom);

    let serialized = serde_json::to_string_pretty(&result)?;
    let output = format!("{serialized}\n");
    io_mod::write_output(output_path, output.as_bytes())?;
    Ok(())
}

/// Compute the info summary from a parsed BOM `Value`.
fn compute_info(bom: &Value) -> Value {
    let component_count = count_components(bom);
    let dependency_count = bom
        .get("dependencies")
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    let service_count = bom
        .get("services")
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    let vulnerability_count = bom
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len());
    let has_evidence = detect_evidence(bom);

    json!({
        "bomFormat": bom.get("bomFormat").and_then(|v| v.as_str()).unwrap_or("CycloneDX"),
        "specVersion": bom.get("specVersion").and_then(|v| v.as_str()).unwrap_or(""),
        "componentCount": component_count,
        "dependencyCount": dependency_count,
        "serviceCount": service_count,
        "vulnerabilityCount": vulnerability_count,
        "hasEvidence": has_evidence,
        "cdxrsVersion": crate::CDXRS_VERSION,
    })
}

/// Count top-level components (including nested sub-components).
fn count_components(bom: &Value) -> usize {
    let mut count = 0;
    if let Some(comps) = bom.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            count += 1;
            count += count_nested_components(comp);
        }
    }
    // Also count tool components in metadata
    if let Some(tools) = bom
        .get("metadata")
        .and_then(|m| m.get("tools"))
        .and_then(|t| t.get("components"))
        .and_then(|v| v.as_array())
    {
        count += tools.len();
    }
    count
}

fn count_nested_components(comp: &Value) -> usize {
    let mut count = 0;
    if let Some(subs) = comp.get("components").and_then(|v| v.as_array()) {
        for sub in subs {
            count += 1;
            count += count_nested_components(sub);
        }
    }
    count
}

/// Detect whether any component carries evidence.
fn detect_evidence(bom: &Value) -> bool {
    if let Some(comps) = bom.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            if comp.get("evidence").is_some() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_info_minimal() {
        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                { "type": "library", "name": "foo", "version": "1.0.0" },
                { "type": "library", "name": "bar", "version": "2.0.0" }
            ],
            "dependencies": [
                { "ref": "a", "dependsOn": ["b"] }
            ]
        });
        let info = compute_info(&bom);
        assert_eq!(info["bomFormat"], "CycloneDX");
        assert_eq!(info["specVersion"], "1.6");
        assert_eq!(info["componentCount"], 2);
        assert_eq!(info["dependencyCount"], 1);
        assert_eq!(info["serviceCount"], 0);
        assert_eq!(info["vulnerabilityCount"], 0);
        assert_eq!(info["hasEvidence"], false);
    }

    #[test]
    fn test_compute_info_with_evidence() {
        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "foo",
                    "evidence": { "identity": [] }
                }
            ]
        });
        let info = compute_info(&bom);
        assert_eq!(info["hasEvidence"], true);
    }

    #[test]
    fn test_compute_info_nested_components() {
        let bom = json!({
            "components": [
                {
                    "type": "application",
                    "name": "app",
                    "components": [
                        { "type": "library", "name": "nested1" },
                        { "type": "library", "name": "nested2",
                          "components": [
                            { "type": "library", "name": "deep" }
                          ]
                        }
                    ]
                }
            ]
        });
        let info = compute_info(&bom);
        assert_eq!(info["componentCount"], 4);
    }

    #[test]
    fn test_count_includes_tool_components() {
        let bom = json!({
            "metadata": {
                "tools": {
                    "components": [
                        { "type": "application", "name": "cdxgen" },
                        { "type": "library", "name": "atom" }
                    ]
                }
            },
            "components": [
                { "type": "library", "name": "foo" }
            ]
        });
        let info = compute_info(&bom);
        assert_eq!(info["componentCount"], 3);
    }
}
