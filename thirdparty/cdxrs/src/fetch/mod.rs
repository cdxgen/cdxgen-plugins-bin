//! Batched registry fetching.
//!
//! `cdxrs fetch` is a parallel, cached, rate-limit-aware HTTP GET batcher and
//! nothing more. It has no knowledge of registries, components or purls: the JS
//! side builds the URLs and derives every component field from the documents
//! this module returns, so the Rust path cannot produce a different SBOM than
//! the JS path. See `batch.rs` for the reasoning behind that split.
//!
//! - `client` — reqwest/rustls client with concurrency caps, retries, timeouts.
//! - `rate`   — per-host minimum-interval gate, overridden by `Retry-After`.
//! - `cache`  — on-disk conditional cache, keyed on URL + method + Accept +
//!   auth-realm identity.
//! - `batch`  — request coalescing, fan-out and statistics.

pub mod batch;
pub mod cache;
pub mod client;
pub mod rate;
