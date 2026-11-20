//! A fetched document, held as checked JSON text.
//!
//! `cdxrs fetch` never looks inside a document: it hands each one to the JS
//! side unchanged. Holding a body as a parsed `serde_json::Value` would cost
//! far more memory than its text (an array of small numbers takes about 30
//! times its byte length as a tree of `Value`s), and that cost would escape
//! the batch's decoded-byte budget, which counts bytes. A [`Body`] keeps the
//! text itself, checked once to be well-formed JSON, so the memory it holds
//! is the byte count the budget charged for it.
//!
//! The text sits behind an `Arc`, so a body fanned out to several caller ids,
//! or copied between the cache and the result list, is shared rather than
//! duplicated.

use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

/// Well-formed JSON text, shared and never re-parsed.
#[derive(Clone)]
pub struct Body(Arc<RawValue>);

impl Body {
    /// The body of a JSON response. `None` when the bytes are not UTF-8 or
    /// not one well-formed JSON value. The check walks the text without
    /// building a tree, so it allocates nothing beyond the text.
    pub fn from_json_bytes(bytes: Vec<u8>) -> Option<Self> {
        let text = String::from_utf8(bytes).ok()?;
        let raw = RawValue::from_string(text).ok()?;
        Some(Self(Arc::from(raw)))
    }

    /// A non-JSON response (an HTML licence page, say), carried as a JSON
    /// string so the caller can scrape it. `None` when it is not UTF-8.
    pub fn from_text_bytes(bytes: Vec<u8>) -> Option<Self> {
        let text = String::from_utf8(bytes).ok()?;
        let quoted = serde_json::to_string(&text).ok()?;
        drop(text);
        RawValue::from_string(quoted)
            .ok()
            .map(|raw| Self(Arc::from(raw)))
    }

    /// JSON `null`, the body of a 304 answer.
    pub fn null() -> Self {
        Self(Arc::from(
            RawValue::from_string("null".to_string()).expect("null is valid JSON"),
        ))
    }

    /// The JSON text.
    pub fn as_str(&self) -> &str {
        self.0.get()
    }

    /// Bytes of JSON text held, which is what the batch budget charges.
    pub fn len(&self) -> usize {
        self.0.get().len()
    }

    /// Whether the text is empty. A [`Body`] always holds one JSON value, so
    /// this is always false; it exists to pair with [`Body::len`].
    pub fn is_empty(&self) -> bool {
        self.0.get().is_empty()
    }

    /// The body parsed into a tree. Tests and debugging only: the fetch path
    /// itself never builds one.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::from_str(self.0.get()).unwrap_or(serde_json::Value::Null)
    }

    /// A body from a parsed value, for tests and fixtures.
    pub fn from_value(value: &serde_json::Value) -> Self {
        let text = serde_json::to_string(value).expect("a Value always serializes");
        Self(Arc::from(
            RawValue::from_string(text).expect("serialized Value is valid JSON"),
        ))
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Body({} bytes)", self.len())
    }
}

impl PartialEq for Body {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Serialize for Body {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Body {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        Ok(Self(Arc::from(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_bytes_are_checked_but_kept_as_text() {
        let body = Body::from_json_bytes(br#"{"a": [1, 2]}"#.to_vec()).unwrap();
        assert_eq!(body.as_str(), r#"{"a": [1, 2]}"#);
        assert_eq!(body.len(), 13);
        assert_eq!(body.to_value()["a"][1], 2);
    }

    #[test]
    fn malformed_json_and_invalid_utf8_are_refused() {
        assert!(Body::from_json_bytes(b"{\"a\":".to_vec()).is_none());
        assert!(Body::from_json_bytes(b"1 2".to_vec()).is_none());
        assert!(Body::from_json_bytes(b"".to_vec()).is_none());
        assert!(Body::from_json_bytes(vec![b'"', 0xff, b'"']).is_none());
        assert!(Body::from_text_bytes(vec![0xff]).is_none());
    }

    #[test]
    fn text_becomes_a_json_string() {
        let body = Body::from_text_bytes(b"<p>\"MIT\"</p>".to_vec()).unwrap();
        assert_eq!(body.to_value(), serde_json::json!("<p>\"MIT\"</p>"));
    }

    #[test]
    fn serializes_as_the_text_it_holds() {
        #[derive(Serialize, Deserialize)]
        struct Wrap {
            body: Body,
        }
        let w = Wrap {
            body: Body::from_json_bytes(br#"{"k":[true,null]}"#.to_vec()).unwrap(),
        };
        let out = serde_json::to_string(&w).unwrap();
        assert_eq!(out, r#"{"body":{"k":[true,null]}}"#);
        let back: Wrap = serde_json::from_str(&out).unwrap();
        assert!(back.body == w.body);
    }

    #[test]
    fn clones_share_one_allocation() {
        let a = Body::from_json_bytes(b"[1,2,3]".to_vec()).unwrap();
        let b = a.clone();
        assert!(std::ptr::eq(a.as_str().as_ptr(), b.as_str().as_ptr()));
    }
}
