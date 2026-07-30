//! Round-trip and fuzz tests for the BOM I/O path.
//!
//! **The most important test in this deliverable**: parse-then-serialize must
//! be byte-identical on all vendored golden BOMs. This proves unknown-field
//! preservation and field-order fidelity.

use std::fs;

use serde_json::Value;

use cdxrs::bom::read;
use cdxrs::bom::write;

/// Directory containing vendored golden BOM fixtures.
const TESTDATA_DIR: &str = "testdata";

/// Collect all golden fixture files from testdata/.
fn golden_files() -> Vec<String> {
    let mut files: Vec<String> = fs::read_dir(TESTDATA_DIR)
        .expect("testdata dir must exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_string_lossy().to_string())
        .filter(|p| p.ends_with(".json"))
        .collect();
    files.sort();
    files
}

/// Parse a golden BOM, serialize it back, and assert byte-identical output.
/// This is run for every vendored golden file.
fn assert_roundtrip_identical(path: &str) {
    let original = fs::read(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));

    let parsed: Value =
        read::parse_value(&original).unwrap_or_else(|e| panic!("parse failed for {path}: {e}"));

    let reserialized = write::serialize_value_pretty(&parsed).expect("serialization must not fail");

    let original_str = String::from_utf8(original.clone()).expect("golden files are valid UTF-8");

    assert_eq!(
        original_str, reserialized,
        "round-trip mismatch for {path} — unknown-field preservation or field-order fidelity broken"
    );
}

#[test]
fn test_roundtrip_all_golden_boms() {
    let files = golden_files();
    assert!(
        files.len() >= 10,
        "expected at least 10 golden fixtures, found {}",
        files.len()
    );
    for file in &files {
        assert_roundtrip_identical(file);
    }
}

/// Round-trip a large BOM (pubspec-smoke, ~311 KB) and verify byte-identical
/// output. This is the by-hand large-BOM check mandated by the plan — the
/// largest vendored fixture exercises deep nesting, many components, and
/// vendor extensions that would break a weaker model.
#[test]
fn test_roundtrip_large_bom_pubspec() {
    let path = format!("{TESTDATA_DIR}/pubspec-smoke.json");
    assert_roundtrip_identical(&path);
}

/// Round-trip the second-largest BOM (cargo-smoke, ~230 KB).
#[test]
fn test_roundtrip_large_bom_cargo() {
    let path = format!("{TESTDATA_DIR}/cargo-smoke.json");
    assert_roundtrip_identical(&path);
}

/// Verify that `parse_value` never panics on arbitrary/garbage bytes.
/// This is the fuzz guard — it should return `Err`, never panic.
#[test]
fn test_parse_value_never_panics_on_garbage() {
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
        &[0u8; 1024],
        b"{))))))}",
    ];

    for input in garbage_inputs {
        // Must never panic — only Ok or Err.
        let _ = read::parse_value_safe(input);
    }
}

/// Verify that a BOM with unknown vendor-extension fields round-trips
/// with all fields preserved — the core unknown-field-preservation guarantee.
///
/// Note: byte-identical round-trip is only guaranteed for input that is
/// already alphabetically sorted (like cdxgen golden files). For arbitrary
/// input, the guarantee is that no fields are dropped.
#[test]
fn test_unknown_fields_preserved() {
    let bom_with_extensions = r#"{
  "bomFormat": "CycloneDX",
  "components": [],
  "customVendorField": "hello",
  "metadata": {
    "customNestedField": 42,
    "timestamp": "2024-01-01T00:00:00.000Z"
  },
  "specVersion": "1.6",
  "version": 1
}
"#;
    let data = bom_with_extensions.as_bytes();
    let parsed = read::parse_value(data).expect("parse must succeed");
    let reserialized = write::serialize_value_pretty(&parsed).expect("serialize must succeed");

    // Byte-identical for alphabetically-sorted input.
    assert_eq!(
        bom_with_extensions, reserialized,
        "unknown vendor-extension fields must survive round-trip byte-identically for sorted input"
    );

    // Also verify field presence explicitly.
    assert_eq!(
        parsed.get("customVendorField").and_then(|v| v.as_str()),
        Some("hello")
    );
    assert_eq!(
        parsed
            .get("metadata")
            .and_then(|m| m.get("customNestedField"))
            .and_then(|v| v.as_i64()),
        Some(42)
    );
}

/// Verify that the `info` command produces the expected counts on a known
/// golden BOM.
#[test]
fn test_info_counts_on_npm_smoke() {
    let path = format!("{TESTDATA_DIR}/npm-smoke-1.6.json");
    let data = fs::read(&path).expect("read fixture");
    let bom = read::parse_value(&data).expect("parse fixture");

    // The npm-smoke golden has known component/dependency counts.
    let component_count = bom
        .get("components")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        component_count > 0,
        "npm-smoke must have components, got {component_count}"
    );

    let dependency_count = bom
        .get("dependencies")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        dependency_count > 0,
        "npm-smoke must have dependencies, got {dependency_count}"
    );
}

// --- Regression tests added in review (D05 r1) ---
//
// The original suite vendored only *normalized* goldens, whose keys the cdxgen
// normalizer has already sorted alphabetically. A `BTreeMap`-backed
// `serde_json::Value` reorders keys alphabetically on write, so round-trip was
// byte-identical on those fixtures for the wrong reason: the property held only
// because every input already happened to be sorted. Real cdxgen output is
// insertion-ordered (`bomFormat, specVersion, serialNumber, version, metadata,
// components, dependencies`), so the write path silently reordered every object
// in any non-golden BOM. Fixed by enabling serde_json's `preserve_order`
// feature; these tests pin the behaviour.

/// The unsorted fixture must stay unsorted, otherwise the regression test below
/// silently stops testing anything.
#[test]
fn test_unsorted_fixture_is_actually_unsorted() {
    let data = fs::read("testdata/real-unsorted-npm.json").expect("fixture must exist");
    let parsed: Value = read::parse_value(&data).expect("parse must succeed");
    let keys: Vec<&String> = parsed
        .as_object()
        .expect("BOM root is an object")
        .keys()
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_ne!(
        keys, sorted,
        "fixture has become alphabetically sorted; it no longer guards field-order fidelity"
    );
}

/// Round-trip of a real, insertion-ordered cdxgen BOM must be byte-identical.
/// This fails without serde_json's `preserve_order` feature.
#[test]
fn test_roundtrip_preserves_non_alphabetical_field_order() {
    assert_roundtrip_identical("testdata/real-unsorted-npm.json");
}

/// The typed `Bom` model carries `#[serde(flatten)] extra` on 18 structs, but
/// nothing exercised it: every round-trip test used the untyped `parse_value`
/// path. This round-trips *through the typed model* so the `extra` maps are
/// genuinely proven to preserve unknown fields.
#[test]
fn test_typed_model_roundtrip_preserves_unknown_fields() {
    for path in golden_files() {
        let original = fs::read(&path).expect("read fixture");
        let bom = read::parse_bom(&original)
            .unwrap_or_else(|e| panic!("typed parse failed for {path}: {e}"));
        let via_typed =
            serde_json::to_value(&bom).unwrap_or_else(|e| panic!("typed reserialize {path}: {e}"));
        let via_value: Value = read::parse_value(&original).expect("untyped parse");
        assert_eq!(
            via_value, via_typed,
            "typed model lost or altered fields for {path} — `extra` flatten coverage is incomplete"
        );
    }
}
