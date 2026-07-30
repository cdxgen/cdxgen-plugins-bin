//! Schema validation against vendored CycloneDX 1.6 / 1.7 JSON schemas.
//!
//! Schemas are embedded at compile time via `include_str!` from `schemas/`.
//! A custom retriever resolves inter-schema `$ref` URIs to the embedded
//! copies — no network access, no file I/O.

use std::collections::HashMap;

use jsonschema::{Retrieve, Uri, ValidationOptions, Validator};
use serde_json::Value;

use super::findings::{Finding, Severity};

/// Embed the schema files at compile time.
const BOM_1_6: &str = include_str!("../../schemas/bom-1.6.schema.json");
const BOM_1_7: &str = include_str!("../../schemas/bom-1.7.schema.json");
const JSF_0_82: &str = include_str!("../../schemas/jsf-0.82.schema.json");
const SPDX: &str = include_str!("../../schemas/spdx.schema.json");
const CRYPTO_DEFS: &str = include_str!("../../schemas/cryptography-defs.schema.json");

/// URI prefix used by the CycloneDX schemas for cross-file `$ref`.
const SCHEMA_BASE: &str = "http://cyclonedx.org/schema/";

/// Retriever that serves vendored schemas by URI — no network, no disk.
struct EmbeddedRetriever {
    resources: HashMap<String, Value>,
}

impl EmbeddedRetriever {
    fn new() -> Self {
        let mut resources = HashMap::new();
        resources.insert(
            format!("{SCHEMA_BASE}bom-1.6.schema.json"),
            serde_json::from_str(BOM_1_6).expect("bom-1.6 schema must parse"),
        );
        resources.insert(
            format!("{SCHEMA_BASE}bom-1.7.schema.json"),
            serde_json::from_str(BOM_1_7).expect("bom-1.7 schema must parse"),
        );
        resources.insert(
            format!("{SCHEMA_BASE}jsf-0.82.schema.json"),
            serde_json::from_str(JSF_0_82).expect("jsf-0.82 schema must parse"),
        );
        resources.insert(
            format!("{SCHEMA_BASE}spdx.schema.json"),
            serde_json::from_str(SPDX).expect("spdx schema must parse"),
        );
        resources.insert(
            format!("{SCHEMA_BASE}cryptography-defs.schema.json"),
            serde_json::from_str(CRYPTO_DEFS).expect("cryptography-defs schema must parse"),
        );
        Self { resources }
    }
}

impl Retrieve for EmbeddedRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let uri_str = uri.as_str();
        // Strip fragment
        let base = uri_str.split('#').next().unwrap_or(uri_str);

        // Try exact match
        if let Some(schema) = self.resources.get(base) {
            return Ok(schema.clone());
        }
        // Try matching by filename
        let filename = base.rsplit('/').next().unwrap_or(base);
        for (key, val) in &self.resources {
            if key.rsplit('/').next() == Some(filename) {
                return Ok(val.clone());
            }
        }
        Err(format!("schema not found for URI: {uri_str}").into())
    }
}

/// Compile and cache validators per spec version.
fn get_validator(spec_version: &str) -> Result<Validator, String> {
    let retriever = EmbeddedRetriever::new();
    let main_schema: Value = match spec_version {
        "1.6" => serde_json::from_str(BOM_1_6).map_err(|e| e.to_string())?,
        "1.7" => serde_json::from_str(BOM_1_7).map_err(|e| e.to_string())?,
        _ => return Err(format!("unsupported spec version: {spec_version}")),
    };

    ValidationOptions::default()
        .with_retriever(retriever)
        .build(&main_schema)
        .map_err(|e| e.to_string())
}

/// Run JSON Schema validation and map errors to findings.
pub fn validate_schema(bom: &Value, spec_version: &str) -> Vec<Finding> {
    let validator = match get_validator(spec_version) {
        Ok(v) => v,
        Err(e) => {
            return vec![Finding {
                id: "schema.internal-error".to_string(),
                severity: Severity::Error,
                path: String::new(),
                bom_ref: None,
                message: format!("Failed to compile schema: {e}"),
                hint: None,
            }];
        }
    };

    let mut findings = Vec::new();
    for error in validator.iter_errors(bom) {
        let instance_path = error.instance_path().to_string();
        // Location::Display already includes a leading '/' for non-empty
        // paths (e.g. "/components/0/purl"). Empty path maps to "/" (root).
        let json_pointer = if instance_path.is_empty() {
            "/".to_string()
        } else {
            instance_path.clone()
        };

        let message = format_schema_error(&error.to_string(), &json_pointer);

        findings.push(Finding {
            id: "schema.invalid".to_string(),
            severity: Severity::Error,
            path: json_pointer.clone(),
            bom_ref: extract_bom_ref(bom, &instance_path),
            message,
            hint: None,
        });
    }

    findings
}

/// Produce a user-friendly message for a schema validation error.
fn format_schema_error(detail: &str, path: &str) -> String {
    let location = if path == "/" { "root" } else { path };
    format!("{location}: {detail}")
}

/// Walk the BOM to find a `bom-ref` near the error location.
fn extract_bom_ref(bom: &Value, instance_path_str: &str) -> Option<String> {
    if instance_path_str.is_empty() {
        return None;
    }
    let segments: Vec<&str> = instance_path_str
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut current = bom;
    for seg in &segments {
        if let Some(v) = current.get(*seg) {
            current = v;
        } else if let Ok(idx) = seg.parse::<usize>() {
            if let Some(arr) = current.as_array() {
                if idx < arr.len() {
                    current = &arr[idx];
                } else {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    current
        .get("bom-ref")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
