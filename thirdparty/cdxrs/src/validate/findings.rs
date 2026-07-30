//! Findings data structures for the validation output.

use serde::{Deserialize, Serialize};

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable dotted identifier (see docs/v13/validation-rules.md).
    pub id: String,
    /// Severity: `error`, `warning`, or `info`.
    pub severity: Severity,
    /// RFC 6901 JSON Pointer to the element that triggered the finding.
    pub path: String,
    /// The `bom-ref` of the relevant component, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    /// Human-readable message describing the problem.
    pub message: String,
    /// Optional remediation hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Summary counts by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub error: usize,
    pub warning: usize,
    pub info: usize,
}

/// The complete findings document emitted by `cdxrs validate`.
///
/// camelCase on the wire: this is a public output format that consumers parse,
/// and it must match both the documented findings shape and its sibling
/// `cdxrs info`, which already emits `specVersion`. Later subcommands will copy
/// this struct, so the convention is cheap to fix here and expensive to change
/// once published.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Findings {
    pub valid: bool,
    pub spec_version: String,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}
