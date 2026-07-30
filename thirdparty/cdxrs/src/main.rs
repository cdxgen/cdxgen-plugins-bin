//! cdxrs binary entry point — argument parsing and dispatch ONLY.
//!
//! No logic lives here; every subcommand delegates to `cdxrs::cmd`.

use clap::Parser;

use cdxrs::cli::{Cli, Command};
use cdxrs::error::CdxrsError;
use cdxrs::error::exit_code;
use cdxrs::{CDXRS_VERSION, SUPPORTED_SPEC_VERSIONS, log};

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Some(Command::Info) => cdxrs::cmd::info::run(&cli.input, &cli.output, cli.max_input_bytes),
        Some(Command::Validate) => {
            cdxrs::cmd::validate::run(&cli.input, &cli.output, cli.max_input_bytes)
        }
        Some(Command::SchemaVersion) => {
            let versions: Vec<String> = SUPPORTED_SPEC_VERSIONS
                .iter()
                .map(|v| format!("\"{v}\""))
                .collect();
            println!("{{\"supportedSpecVersions\":[{}]}}", versions.join(","));
            Ok(())
        }
        None => {
            // No subcommand: print version and basic usage hint.
            println!("cdxrs {CDXRS_VERSION}");
            println!("Supported spec versions: {}", versions_str());
            println!("Run 'cdxrs --help' for usage.");
            Ok(())
        }
    };

    match result {
        Ok(()) => std::process::exit(exit_code::OK),
        Err(e) => {
            // ValidationFailure is not an operational error: findings are
            // already on stdout. Log at info, not error.
            match &e {
                CdxrsError::ValidationFailure => {
                    log::info("validation failure (findings on stdout)")
                }
                _ => log::error(&e.to_string()),
            }
            std::process::exit(e.exit_code());
        }
    }
}

fn versions_str() -> String {
    SUPPORTED_SPEC_VERSIONS.join(", ")
}
