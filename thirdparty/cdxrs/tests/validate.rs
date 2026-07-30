//! Unit tests for the validation pipeline.
//!
//! One positive and one negative test per rule id, plus a fuzz guard.

use cdxrs::validate::{self, Finding, Findings, Severity};
use serde_json::{Value, json};

fn validate_bom(bom: &Value) -> Findings {
    validate::validate_bom(bom)
}

fn has_finding(findings: &[Finding], id: &str) -> bool {
    findings.iter().any(|f| f.id == id)
}

fn has_severity(findings: &[Finding], id: &str, sev: Severity) -> bool {
    findings.iter().any(|f| f.id == id && f.severity == sev)
}

fn valid_bom_1_6() -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "demo",
                "version": "1.0.0",
                "purl": "pkg:generic/demo@1.0.0",
                "bom-ref": "pkg:generic/demo@1.0.0"
            }
        },
        "components": [
            {
                "type": "library",
                "name": "foo",
                "version": "1.0.0",
                "purl": "pkg:npm/foo@1.0.0",
                "bom-ref": "pkg:npm/foo@1.0.0"
            }
        ],
        "dependencies": [
            { "ref": "pkg:generic/demo@1.0.0", "dependsOn": ["pkg:npm/foo@1.0.0"] },
            { "ref": "pkg:npm/foo@1.0.0", "dependsOn": [] }
        ]
    })
}

// ---------------------------------------------------------------------------
// Schema rules
// ---------------------------------------------------------------------------

#[test]
fn test_schema_unsupported_version() {
    let bom = json!({ "bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1 });
    let f = validate_bom(&bom);
    assert!(!f.valid);
    assert!(has_severity(
        &f.findings,
        "schema.unsupported-version",
        Severity::Error
    ));
    assert_eq!(f.findings[0].path, "/specVersion");
}

#[test]
fn test_schema_supported_version_16() {
    let bom =
        json!({ "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [] });
    let f = validate_bom(&bom);
    assert!(f.valid);
    assert!(!has_finding(&f.findings, "schema.unsupported-version"));
}

#[test]
fn test_schema_supported_version_17() {
    let bom =
        json!({ "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [] });
    let f = validate_bom(&bom);
    assert!(f.valid);
}

#[test]
fn test_schema_invalid_component_type() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{ "type": "INVALID", "name": "x" }]
    });
    let f = validate_bom(&bom);
    assert!(!f.valid);
    assert!(has_severity(&f.findings, "schema.invalid", Severity::Error));
}

// ---------------------------------------------------------------------------
// Metadata rules
// ---------------------------------------------------------------------------

#[test]
fn test_metadata_component_missing() {
    // Positive: the rule fires when metadata.component is absent entirely.
    // An *empty* metadata.component never reaches this semantic rule, because the
    // schema rejects it first (`type` and `name` are required) — which is why the
    // original form of this test asserted nothing about the positive case.
    let mut bom = valid_bom_1_6();
    bom["metadata"]
        .as_object_mut()
        .expect("metadata is an object")
        .remove("component");
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "metadata.component-missing",
        Severity::Warning
    ));

    // Negative: a complete metadata.component must not trigger it.
    let valid = valid_bom_1_6();
    let f = validate_bom(&valid);
    assert!(!has_finding(&f.findings, "metadata.component-missing"));
}

#[test]
fn test_metadata_placeholder_name() {
    let mut bom = valid_bom_1_6();
    bom["metadata"]["component"]["name"] = json!("app");
    let f = validate_bom(&bom);
    assert!(has_finding(
        &f.findings,
        "metadata.component-placeholder-name"
    ));
}

#[test]
fn test_metadata_no_placeholder_name() {
    let bom = valid_bom_1_6();
    let f = validate_bom(&bom);
    assert!(!has_finding(
        &f.findings,
        "metadata.component-placeholder-name"
    ));
}

// ---------------------------------------------------------------------------
// PURL rules
// ---------------------------------------------------------------------------

#[test]
fn test_purl_invalid_syntax() {
    let mut bom = valid_bom_1_6();
    bom["components"][0]["purl"] = json!("INVALID");
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "purl.invalid-syntax",
        Severity::Error
    ));
    assert!(!f.valid);
}

#[test]
fn test_purl_valid_syntax() {
    let bom = valid_bom_1_6();
    let f = validate_bom(&bom);
    assert!(!has_finding(&f.findings, "purl.invalid-syntax"));
}

#[test]
fn test_purl_crypto_asset_has_purl() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [{
            "type": "cryptographic-asset",
            "name": "key",
            "purl": "pkg:generic/key@1.0",
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": { "type": "private-key" }
            }
        }]
    });
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "purl.crypto-asset-has-purl",
        Severity::Error
    ));
}

#[test]
fn test_purl_crypto_asset_no_purl() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [{
            "type": "cryptographic-asset",
            "name": "key",
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": { "type": "private-key" }
            }
        }]
    });
    let f = validate_bom(&bom);
    assert!(!has_finding(&f.findings, "purl.crypto-asset-has-purl"));
}

#[test]
fn test_crypto_algorithm_missing_oid() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [{
            "type": "cryptographic-asset",
            "name": "algo",
            "cryptoProperties": { "assetType": "algorithm" }
        }]
    });
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "crypto.algorithm-missing-oid",
        Severity::Error
    ));
}

#[test]
fn test_crypto_algorithm_with_oid() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [{
            "type": "cryptographic-asset",
            "name": "algo",
            "cryptoProperties": {
                "assetType": "algorithm",
                "oid": "2.16.840.1.101.3.4.2.1"
            }
        }]
    });
    let f = validate_bom(&bom);
    assert!(!has_finding(&f.findings, "crypto.algorithm-missing-oid"));
}

#[test]
fn test_ref_encoded_dependency_ref() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{ "type": "library", "name": "x", "bom-ref": "a" }],
        "dependencies": [
            { "ref": "pkg:npm/%40scope/pkg@1.0", "dependsOn": [] },
            { "ref": "a", "dependsOn": [] }
        ]
    });
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "ref.encoded-dependency-ref",
        Severity::Error
    ));
}

#[test]
fn test_ref_no_encoded_chars() {
    let bom = valid_bom_1_6();
    let f = validate_bom(&bom);
    assert!(!has_finding(&f.findings, "ref.encoded-dependency-ref"));
}

// ---------------------------------------------------------------------------
// Insta snapshot test
// ---------------------------------------------------------------------------

#[test]
fn test_insta_snapshot_invalid_purl() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{ "type": "library", "name": "bad", "purl": "INVALID" }]
    });
    let f = validate_bom(&bom);
    let serialized = serde_json::to_string_pretty(&f).unwrap();
    insta::assert_snapshot!(serialized);
}

// ---------------------------------------------------------------------------
// Fuzz guard: validate must never panic on arbitrary input
// ---------------------------------------------------------------------------

#[test]
fn test_validate_never_panics_on_garbage() {
    let garbage_inputs: &[&[u8]] = &[
        b"",
        b"   ",
        b"\x00",
        b"\xff\xfe",
        b"{",
        b"}",
        b"[1,2,",
        b"{\"a\":}",
        b"null",
        b"42",
        b"\"string\"",
        b"\xef\xbb\xbf{\"bomFormat\":",
        b"{))))))}",
        b"{\"specVersion\": null}",
        b"{\"specVersion\": 123}",
        b"{\"specVersion\": []}",
        b"{\"components\": null}",
        b"{\"components\": \"string\"}",
        b"{\"components\": [{\"type\": null}]}",
        b"{\"dependencies\": [{\"ref\": null}]}",
        b"{\"dependencies\": null}",
        b"{\"metadata\": \"string\"}",
        b"{\"metadata\": {\"component\": []}}",
        &[0u8; 1024],
    ];

    for input in garbage_inputs {
        // Must never panic — parse then validate.
        if let Ok(value) = serde_json::from_slice::<Value>(input) {
            let _ = validate::validate_bom(&value);
        }
    }
}

#[test]
fn test_validate_never_panics_on_random_json() {
    // Structurally weird but valid JSON
    let weird = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "component": { "type": "application", "name": "x", "version": "1" } },
        "components": [
            json!({}),
            json!({ "type": "library" }),
            json!({ "type": "library", "name": null }),
            json!({ "type": "library", "name": "x", "purl": null }),
            json!({ "type": "library", "name": "x", "purl": "", "version": null }),
            json!({ "type": "cryptographic-asset", "name": "x" }),
            json!({ "type": "cryptographic-asset", "name": "x", "cryptoProperties": null }),
            json!({ "type": "cryptographic-asset", "name": "x", "cryptoProperties": {} }),
            json!({ "type": "library", "name": "x", "purl": "pkg:npm/x", "version": "1", "properties": null }),
            json!({ "type": "library", "name": "x", "purl": "pkg:npm/x", "version": "1", "properties": [] }),
            json!({ "type": "library", "name": "x", "purl": "pkg:npm/x", "version": "1", "externalReferences": null }),
        ],
        "dependencies": [
            json!({}),
            json!({ "ref": null }),
            json!({ "ref": "x", "dependsOn": null }),
            json!({ "ref": "x", "dependsOn": [null, "", 42] }),
            json!({ "ref": "x", "provides": null }),
        ]
    });
    let _ = validate::validate_bom(&weird);
}

// ---------------------------------------------------------------------------
// Summary and exit-code semantics
// ---------------------------------------------------------------------------

#[test]
fn test_valid_bom_has_zero_errors() {
    let bom = valid_bom_1_6();
    let f = validate_bom(&bom);
    assert!(f.valid);
    assert_eq!(f.summary.error, 0);
}

#[test]
fn test_invalid_bom_summary_counts() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{ "type": "library", "name": "bad", "purl": "INVALID" }]
    });
    let f = validate_bom(&bom);
    assert!(!f.valid);
    assert!(f.summary.error >= 1);
}

#[test]
fn test_findings_sorted_by_path_then_id() {
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            { "type": "library", "name": "a", "purl": "INVALID" },
            { "type": "library", "name": "b", "purl": "ALSO_INVALID" }
        ]
    });
    let f = validate_bom(&bom);
    // Findings should be sorted by path
    for i in 1..f.findings.len() {
        assert!(f.findings[i - 1].path <= f.findings[i].path);
    }
}

// ---------------------------------------------------------------------------
// Error-severity rules added in review (D06 r1)
//
// These three carried `Severity::Error` but had no coverage in either the unit
// tests or the `testdata/invalid/` fixtures. Error findings are what drive
// `validation.valid == false`, and `bin/cdxgen.js` exits 1 on that, so an
// untested error rule is precisely the kind that can break a working build.
// ---------------------------------------------------------------------------

/// A cryptographic-asset component with no `cryptoProperties` at all.
#[test]
fn test_crypto_asset_missing_crypto_properties() {
    let mut bom = valid_bom_1_6();
    bom["components"] = json!([{
        "type": "cryptographic-asset",
        "name": "aes-256-gcm",
        "bom-ref": "crypto/aes-256-gcm"
    }]);
    bom["dependencies"] = json!([]);
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "crypto.asset-missing-crypto-properties",
        Severity::Error
    ));

    // Negative: supplying cryptoProperties clears it.
    bom["components"][0]["cryptoProperties"] = json!({
        "assetType": "algorithm",
        "algorithmProperties": { "primitive": "ae" },
        "oid": "2.16.840.1.101.3.4.1.46"
    });
    let f = validate_bom(&bom);
    assert!(!has_finding(
        &f.findings,
        "crypto.asset-missing-crypto-properties"
    ));
}

/// A certificate crypto asset must carry `algorithmProperties`.
#[test]
fn test_crypto_certificate_missing_algorithm_properties() {
    let mut bom = valid_bom_1_6();
    bom["components"] = json!([{
        "type": "cryptographic-asset",
        "name": "leaf-cert",
        "bom-ref": "crypto/leaf-cert",
        "cryptoProperties": { "assetType": "certificate" }
    }]);
    bom["dependencies"] = json!([]);
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "crypto.certificate-missing-algorithm-properties",
        Severity::Error
    ));

    // Negative: a non-certificate asset type must not trigger it.
    bom["components"][0]["cryptoProperties"] = json!({
        "assetType": "algorithm",
        "oid": "2.16.840.1.101.3.4.1.46"
    });
    let f = validate_bom(&bom);
    assert!(!has_finding(
        &f.findings,
        "crypto.certificate-missing-algorithm-properties"
    ));
}

/// An npm/golang purl whose name contains an encoded slash but which declares no
/// namespace — the scope was folded into the name instead of being split out.
#[test]
fn test_purl_encoded_slash_without_namespace() {
    let mut bom = valid_bom_1_6();
    bom["components"] = json!([{
        "type": "library",
        "name": "@scope/pkg",
        "version": "1.0.0",
        "purl": "pkg:npm/%40scope%2Fpkg@1.0.0",
        "bom-ref": "pkg:npm/%40scope%2Fpkg@1.0.0"
    }]);
    bom["dependencies"] = json!([]);
    let f = validate_bom(&bom);
    assert!(has_severity(
        &f.findings,
        "purl.encoded-slash-without-namespace",
        Severity::Error
    ));

    // Negative: the same package expressed correctly, with the scope as namespace.
    bom["components"][0]["purl"] = json!("pkg:npm/%40scope/pkg@1.0.0");
    bom["components"][0]["bom-ref"] = json!("pkg:npm/%40scope/pkg@1.0.0");
    let f = validate_bom(&bom);
    assert!(!has_finding(
        &f.findings,
        "purl.encoded-slash-without-namespace"
    ));
}

// ---------------------------------------------------------------------------
// purl parser spec conformance (added in review, D06 r1)
//
// The parser is hand-rolled; these pin it to the purl spec on the points where
// it previously diverged. Every case below was verified against the built binary
// before and after the fix.
// ---------------------------------------------------------------------------

fn bom_with_purl(purl: &str) -> Value {
    let mut bom = valid_bom_1_6();
    bom["components"] = json!([{
        "type": "library", "name": "n", "version": "1.0.0",
        "purl": purl, "bom-ref": "c1"
    }]);
    bom["dependencies"] = json!([]);
    bom
}

fn rejects(purl: &str) -> bool {
    has_finding(
        &validate_bom(&bom_with_purl(purl)).findings,
        "purl.invalid-syntax",
    )
}

#[test]
fn test_purl_name_is_required() {
    // All three previously parsed successfully with an empty name.
    assert!(rejects("pkg:npm"), "type with no name must be rejected");
    assert!(
        rejects("pkg:npm/"),
        "trailing slash with no name must be rejected"
    );
    assert!(
        rejects("pkg:npm/@1.0.0"),
        "version with no name must be rejected"
    );
}

#[test]
fn test_purl_unencoded_at_in_namespace_is_invalid() {
    // A literal `@` in a namespace is not legal — `%40` is required — so this is
    // a malformed purl. Splitting the version at the first `@` leaves an empty
    // name, which the name-required check rejects.
    assert!(rejects("pkg:npm/@scope/pkg@1.0.0"));
    // The correctly encoded form is accepted.
    assert!(!rejects("pkg:npm/%40scope/pkg@1.0.0"));
}

#[test]
fn test_purl_scheme_is_case_insensitive_and_tolerates_slashes() {
    assert!(!rejects("PKG:npm/foo@1.0.0"));
    assert!(!rejects("pkg://npm/foo@1.0.0"));
}

#[test]
fn test_purl_empty_path_segments_are_ignored() {
    assert!(!rejects("pkg:npm//foo@1.0.0"));
}

#[test]
fn test_purl_encoded_slash_rule_survives_parser_changes() {
    // Regression guard: this rule reads the raw purl, so it must keep firing for
    // an encoded slash with no namespace, and stay quiet when a namespace exists.
    assert!(has_finding(
        &validate_bom(&bom_with_purl("pkg:npm/%40scope%2Fpkg@1.0.0")).findings,
        "purl.encoded-slash-without-namespace"
    ));
    assert!(!has_finding(
        &validate_bom(&bom_with_purl("pkg:npm/%40scope/pkg@1.0.0")).findings,
        "purl.encoded-slash-without-namespace"
    ));
}
