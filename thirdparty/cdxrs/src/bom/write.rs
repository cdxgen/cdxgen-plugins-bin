//! BOM writing: serialization with canonical key order and formatting.
//!
//! Output format: 2-space pretty-printed JSON with a trailing newline, keys in
//! the order they were read (guaranteed by the `preserve_order` feature; see
//! `bom::read`). This reproduces both cdxgen's normalized golden format and its
//! insertion-ordered live output, because in each case the input order is
//! carried through untouched.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::CdxrsError;

static COMPACT: AtomicBool = AtomicBool::new(false);

/// Select compact (minified) JSON for every serializer in this module and the
/// cmd serializers that route through `serialize_doc`. Set once from main.
pub fn set_compact(on: bool) {
    COMPACT.store(on, Ordering::Relaxed);
}

fn compact() -> bool {
    COMPACT.load(Ordering::Relaxed)
}

fn render<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    if compact() {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
}

/// Serialize any serializable document in the output format selected by
/// `set_compact`, with the trailing newline the cmd serializers expect.
pub fn serialize_doc<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, CdxrsError> {
    let serialized = render(value)?;
    Ok(format!("{serialized}\n"))
}

/// Serialize a `serde_json::Value` to canonical JSON (2-space indent, trailing
/// newline, alphabetically sorted keys).
///
/// This is the inverse of `bom::read::parse_value` and produces byte-identical
/// output on any golden BOM that was itself canonicalized by cdxgen's
/// normalizer (sorted keys, 2-space indent).
pub fn serialize_value_pretty(value: &serde_json::Value) -> Result<String, CdxrsError> {
    let serialized = render(value)?;
    Ok(format!("{serialized}\n"))
}

/// Serialize to bytes (same format as `serialize_value_pretty`).
pub fn serialize_value_pretty_bytes(value: &serde_json::Value) -> Result<Vec<u8>, CdxrsError> {
    let serialized = render(value)?;
    let mut bytes = serialized.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}
