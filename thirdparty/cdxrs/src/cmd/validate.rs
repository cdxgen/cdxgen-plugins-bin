//! `cdxrs validate` — schema + semantic validation for CycloneDX BOMs.
//!
//! Output: a single JSON document on stdout matching the findings format
//! defined in docs/v13/validation-rules.md.
//!
//! Exit codes:
//!   0 — BOM is valid (no `error` findings)
//!   3 — BOM is invalid (at least one `error` finding)
//!   1 — operational failure (I/O, parse error)

use crate::bom::read;
use crate::error::CdxrsError;
use crate::io as io_mod;
use crate::validate;

/// Execute the `validate` subcommand.
pub fn run(
    input_path: &str,
    output_path: &Option<String>,
    max_input_bytes: Option<u64>,
) -> Result<(), CdxrsError> {
    let max_bytes = max_input_bytes.unwrap_or(crate::io::DEFAULT_MAX_INPUT_BYTES);

    let data = io_mod::read_input(input_path, max_bytes)?;
    let bom = read::parse_value(&data)?;

    let findings = validate::validate_bom(&bom);

    // Serialize and write findings document
    let serialized = serde_json::to_string_pretty(&findings)
        .map_err(|e| CdxrsError::Other(format!("failed to serialize findings: {e}")))?;
    let output = format!("{serialized}\n");
    io_mod::write_output(output_path, output.as_bytes())?;

    // Signal exit code 3 when the BOM has error findings. The findings
    // document is already on stdout; this just controls the process exit.
    if !findings.valid {
        return Err(CdxrsError::ValidationFailure);
    }

    Ok(())
}
