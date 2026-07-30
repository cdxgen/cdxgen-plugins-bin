//! Drift guard: verify vendored schemas match the committed checksums.
//!
//! The CycloneDX JSON schemas are copied from cdxgen's `data/` directory so
//! there is exactly one source of truth. This test catches accidental drift
//! by comparing SHA-256 hashes against `schemas/checksums.sha256`.

use std::collections::HashMap;
use std::fs;

use sha2::{Digest, Sha256};

const CHECKSUMS_FILE: &str = "schemas/checksums.sha256";

/// Hash schema *content*, independent of checkout line endings.
///
/// CRLF normalisation matters: git checks these JSON files out with CRLF on
/// Windows, so hashing raw bytes makes the guard fail for a reason unrelated to
/// drift (`bom-1.6.schema.json` hashes to 25dea08c… with LF, b82391bf… with
/// CRLF). The cdxgen-side guard in `lib/validator/schema-drift.poku.js`
/// normalises identically, so both sides agree on one digest per schema.
fn compute_sha256(data: &[u8]) -> String {
    let normalized: Vec<u8> = match std::str::from_utf8(data) {
        Ok(text) => text.replace("\r\n", "\n").into_bytes(),
        // Not UTF-8: hash as-is rather than guessing.
        Err(_) => data.to_vec(),
    };
    let mut hasher = Sha256::new();
    hasher.update(&normalized);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_checksums(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, "  ").collect();
        if parts.len() == 2 {
            map.insert(parts[1].trim().to_string(), parts[0].trim().to_string());
        }
    }
    map
}

#[test]
fn test_vendored_schemas_match_checksums() {
    let checksums_content = fs::read_to_string(CHECKSUMS_FILE)
        .unwrap_or_else(|e| panic!("failed to read {CHECKSUMS_FILE}: {e}"));
    let expected = parse_checksums(&checksums_content);

    let schema_dir = fs::read_dir("schemas").unwrap_or_else(|e| panic!("schemas dir: {e}"));
    for entry in schema_dir {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let expected_hash = expected
            .get(&name)
            .unwrap_or_else(|| panic!("no checksum entry for {name}"));
        let buf = fs::read(entry.path()).unwrap();
        let actual = compute_sha256(&buf);
        assert_eq!(
            actual, *expected_hash,
            "schema drift: {name} has changed. Re-copy from cdxgen data/ and update checksums.sha256"
        );
    }
}

#[test]
fn test_all_vendored_schemas_are_valid_json() {
    let schema_dir = fs::read_dir("schemas").unwrap_or_else(|e| panic!("schemas dir: {e}"));
    for entry in schema_dir {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = fs::read(entry.path()).unwrap();
        let result: Result<serde_json::Value, _> = serde_json::from_slice(&data);
        assert!(
            result.is_ok(),
            "vendored schema {name} is not valid JSON: {:?}",
            result.err()
        );
    }
}
