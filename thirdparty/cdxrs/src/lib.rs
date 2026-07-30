//! cdxrs — Rust-native CycloneDX BOM tooling.
//!
//! Library/binary split: all logic lives here; `main.rs` is argument parsing
//! and dispatch only.

pub mod bom;
pub mod cli;
pub mod cmd;
pub mod error;
pub mod io;
pub mod log;
pub mod validate;

/// Semantic version of the cdxrs binary, embedded at compile time from
/// `env!("CARGO_PKG_VERSION")`.
pub const CDXRS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Spec versions supported by this build of cdxrs.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["1.6", "1.7"];
