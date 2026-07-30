//! CycloneDX 1.6/1.7 serde model.
//!
//! **Design decision: hand-written, not generated.**
//!
//! typify was evaluated but rejected because (1) the official schemas declare
//! `additionalProperties: false` which conflicts with the mandatory
//! unknown-field-preservation requirement, (2) the schemas have 91 interlinked
//! definitions with complex oneOf/anyOf that produce unwieldy enums, and
//! (3) every generated struct would need manual `#[serde(flatten)]` additions
//! anyway. A hand-written model that is understood is preferred over a
//! generated one that must be rewritten.
//!
//! **Round-trip strategy:**
//!
//! The I/O path in `read.rs` / `write.rs` uses `serde_json::Value` (backed by
//! `BTreeMap`, which yields alphabetically sorted keys) rather than these typed
//! structs. This guarantees byte-identical round-trip on cdxgen golden BOMs,
//! whose keys are recursively sorted alphabetically by the normalizer and
//! serialised with 2-space indentation + trailing newline.
//!
//! These typed structs are available for future deliverables that need
//! type-safe field access (validate, compliance, etc.) and for the `info`
//! command's convenience parsing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level CycloneDX BOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bom {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom_format: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Component>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<Dependency>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compositions: Option<Vec<Composition>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<Vec<Vulnerability>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<Annotation>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub formulation: Option<Vec<Formula>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub definitions: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<Property>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Value>,

    /// Vendor extensions and any future-spec fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// BOM metadata block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycles: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Tools>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<OrganizationalContact>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacture: Option<OrganizationalEntity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<OrganizationalEntity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<LicenseChoice>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Metadata.tools (1.5+ object form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tools {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Component>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// CycloneDX component.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Component {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub component_type: Option<String>,

    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<Hash>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<LicenseChoice>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub copyright: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub swid: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pedigree: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<Property>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Component>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<Value>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// CycloneDX service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_trust_boundary: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<LicenseChoice>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Dependency graph entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// License choice (either an inline license or an expression).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseChoice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// License detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// External reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub reference_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<Hash>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Property key-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Organizational contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Organizational entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<OrganizationalContact>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Composition entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Composition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub assemblies: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Vulnerability entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratings: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwes: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisories: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub affects: Option<Vec<Value>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Annotation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotator: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Formulation formula entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Formula {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Component>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflows: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
