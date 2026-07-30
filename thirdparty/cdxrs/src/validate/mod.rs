//! Validation module — schema + semantic checks for CycloneDX BOMs.
//!
//! The public entry point is [`validate_bom`], which mirrors the JS
//! `validateBom` + `validateMetadata` + `validatePurls` + `validateRefs` +
//! `validateProps` pipeline from `lib/validator/bomValidator.js`.

pub mod findings;
pub mod schema;
pub mod semantic;

use serde_json::Value;

pub use findings::{Finding, Findings, Severity, Summary};

/// Spec versions supported by this validator.
pub const SUPPORTED_VERSIONS: &[&str] = &["1.6", "1.7"];

/// Run the full validation pipeline.
///
/// Mirrors the JS `validateBom`: schema validation first (short-circuits on
/// failure), then the four semantic validators. Returns a [`Findings`]
/// document.
pub fn validate_bom(bom: &Value) -> Findings {
    let spec_version = bom
        .get("specVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if !SUPPORTED_VERSIONS.contains(&spec_version.as_str()) {
        let msg = format!(
            "Unsupported CycloneDX specVersion '{}'. Supported versions are 1.6, 1.7.",
            spec_version
        );
        return Findings {
            valid: false,
            spec_version,
            findings: vec![Finding {
                id: "schema.unsupported-version".to_string(),
                severity: Severity::Error,
                path: "/specVersion".to_string(),
                bom_ref: None,
                message: msg,
                hint: Some("Set specVersion to \"1.6\" or \"1.7\".".to_string()),
            }],
            summary: Summary {
                error: 1,
                warning: 0,
                info: 0,
            },
        };
    }

    // Phase 1: Schema validation. Short-circuit on failure (matches JS).
    let mut all_findings = schema::validate_schema(bom, &spec_version);
    if all_findings.iter().any(|f| f.severity == Severity::Error) {
        let summary = summarize(&all_findings);
        return Findings {
            valid: false,
            spec_version,
            findings: sort_findings(all_findings),
            summary,
        };
    }

    // Phase 2: Semantic validation.
    all_findings.extend(semantic::validate_metadata(bom));
    all_findings.extend(semantic::validate_purls(bom));
    all_findings.extend(semantic::validate_refs(bom));
    all_findings.extend(semantic::validate_props(bom));

    let summary = summarize(&all_findings);
    Findings {
        valid: summary.error == 0,
        spec_version,
        findings: sort_findings(all_findings),
        summary,
    }
}

fn summarize(findings: &[Finding]) -> Summary {
    let mut summary = Summary {
        error: 0,
        warning: 0,
        info: 0,
    };
    for f in findings {
        match f.severity {
            Severity::Error => summary.error += 1,
            Severity::Warning => summary.warning += 1,
            Severity::Info => summary.info += 1,
        }
    }
    summary
}

/// Sort findings by (path, id) for deterministic output.
fn sort_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.id.cmp(&b.id)));
    findings
}
