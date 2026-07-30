//! BOM reading: JSON parsing through `serde_json::Value` for guaranteed
//! round-trip fidelity.
//!
//! The I/O path uses `Value` rather than the typed `Bom` struct, because `Value`
//! cannot drop a field it has no struct member for.
//!
//! `serde_json`'s `preserve_order` feature is **required**, not incidental: it
//! backs `Value`'s maps with `IndexMap` so keys serialize in the order they were
//! read. Without it `Value` uses a `BTreeMap` and writes every object's keys
//! alphabetically. That is invisible when testing against normalized goldens
//! (the cdxgen normalizer already sorts those recursively) but silently reorders
//! every object in real cdxgen output, which is insertion-ordered
//! (`bomFormat, specVersion, serialNumber, version, metadata, components,
//! dependencies`). `testdata/real-unsorted-npm.json` guards this.

use crate::bom::model::Bom;
use crate::error::CdxrsError;

/// Parse a byte slice into a `serde_json::Value`.
///
/// This is the primary parse path for round-trip operations. The resulting
/// `Value` preserves all fields (known and unknown) and serializes keys in
/// alphabetical order (via `BTreeMap`), matching the golden-file format.
pub fn parse_value(data: &[u8]) -> Result<serde_json::Value, CdxrsError> {
    if data.is_empty() || data.iter().all(|&b| b.is_ascii_whitespace()) {
        return Err(CdxrsError::EmptyInput);
    }
    // Use from_slice to avoid a UTF-8 conversion round-trip; serde_json
    // handles the encoding internally.
    let value: serde_json::Value = serde_json::from_slice(data)?;
    Ok(value)
}

/// Parse a byte slice into a typed `Bom` struct.
///
/// Use this when type-safe field access is needed (e.g. in the `info`
/// command). For round-trip I/O, use `parse_value` instead.
pub fn parse_bom(data: &[u8]) -> Result<Bom, CdxrsError> {
    if data.is_empty() || data.iter().all(|&b| b.is_ascii_whitespace()) {
        return Err(CdxrsError::EmptyInput);
    }
    let bom: Bom = serde_json::from_slice(data)?;
    Ok(bom)
}

/// Fuzz guard: `parse_value` must never panic on arbitrary bytes.
/// Returns `Ok(value)` on success, `Err` on parse failure; never panics.
pub fn parse_value_safe(data: &[u8]) -> Result<serde_json::Value, CdxrsError> {
    parse_value(data)
}
