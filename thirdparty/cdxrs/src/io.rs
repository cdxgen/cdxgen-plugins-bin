//! Input/output resolution: file paths, stdin, stdout, and size guards.
//!
//! Protocol (per AGENT-WORKFLOW.md and DELIVERABLE-05 plan):
//! - `--input -` reads stdin; `--input <path>` reads a file.
//! - `--output -` writes stdout; `--output <path>` writes a file.
//! - Inputs over 32 MB should go through a file path, enforced by the bridge.
//! - `--max-input-bytes` guard defaults to 2 GB.
//! - Streaming: `serde_json::from_reader` over a buffered reader, never
//!   read-to-string.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use crate::error::CdxrsError;

/// Default maximum input size: 2 GB.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Read input from a file path or stdin (when path is "-").
///
/// Enforces the `max_bytes` size guard by checking the file length before
/// reading. For stdin, we read in chunks and abort if the limit is exceeded.
pub fn read_input(path: &str, max_bytes: u64) -> Result<Vec<u8>, CdxrsError> {
    if path == "-" {
        read_stdin(max_bytes)
    } else {
        read_file(path, max_bytes)
    }
}

fn read_file(path: &str, max_bytes: u64) -> Result<Vec<u8>, CdxrsError> {
    let pb = PathBuf::from(path);
    let metadata = std::fs::metadata(&pb)?;
    let size = metadata.len();
    if size > max_bytes {
        return Err(CdxrsError::InputTooLarge(size, max_bytes));
    }
    let mut file = File::open(&pb)?;
    let mut buf = Vec::with_capacity(size as usize);
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_stdin(max_bytes: u64) -> Result<Vec<u8>, CdxrsError> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut tmp = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        if (buf.len() + n) as u64 > max_bytes {
            return Err(CdxrsError::InputTooLarge((buf.len() + n) as u64, max_bytes));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Write output to a file path or stdout (when path is "-" or None).
pub fn write_output(path: &Option<String>, data: &[u8]) -> Result<(), CdxrsError> {
    match path {
        None => {
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            writer.write_all(data)?;
            Ok(())
        }
        Some(p) if p == "-" => {
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            writer.write_all(data)?;
            Ok(())
        }
        Some(p) => {
            let file = File::create(p)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(data)?;
            writer.flush()?;
            Ok(())
        }
    }
}
