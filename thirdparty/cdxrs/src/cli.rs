//! Clap derive structs for the cdxrs CLI.

use clap::{Parser, Subcommand};

/// cdxrs — Rust-native CycloneDX BOM tooling.
#[derive(Parser, Debug)]
#[command(name = "cdxrs", version, about = "Rust-native CycloneDX BOM tooling")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Input file path ("-" for stdin).
    #[arg(long, short = 'i', global = true, default_value = "-")]
    pub input: String,

    /// Output file path ("-" or omitted for stdout).
    #[arg(long, short = 'o', global = true)]
    pub output: Option<String>,

    /// Maximum input size in bytes (default: 2 GB).
    #[arg(long, global = true)]
    pub max_input_bytes: Option<u64>,
}

/// Subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print BOM summary statistics.
    Info,

    /// Print the supported CycloneDX spec versions.
    SchemaVersion,
}
