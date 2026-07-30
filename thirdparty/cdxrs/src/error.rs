//! Error types and exit-code mapping.
//!
//! Exit codes (per AGENT-WORKFLOW.md):
//!   0 — success
//!   1 — operational failure
//!   2 — bad usage
//!   3 — validation failure with findings on stdout

use thiserror::Error;

/// Library-level error type. `main.rs` converts this to an exit code.
#[derive(Debug, Error)]
pub enum CdxrsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("input size {0} bytes exceeds max-input-bytes limit of {1}")]
    InputTooLarge(u64, u64),

    #[error("input is empty or not valid UTF-8")]
    EmptyInput,

    #[error("{0}")]
    Other(String),
}

/// Exit codes used by the binary.
pub mod exit_code {
    pub const OK: i32 = 0;
    pub const OPERATIONAL_FAILURE: i32 = 1;
    pub const BAD_USAGE: i32 = 2;
    pub const VALIDATION_FAILURE: i32 = 3;
}

impl CdxrsError {
    /// Map a library error to the process exit code `main.rs` should return.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) | Self::Json(_) | Self::InputTooLarge(..) | Self::EmptyInput => {
                exit_code::OPERATIONAL_FAILURE
            }
            Self::Other(_) => exit_code::OPERATIONAL_FAILURE,
        }
    }
}
