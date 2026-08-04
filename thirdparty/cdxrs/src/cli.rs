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

    /// Validate a CycloneDX BOM (schema + semantic checks).
    Validate,

    /// Fetch a batch of registry URLs in parallel, with an on-disk cache.
    Fetch(FetchArgs),
}

/// Arguments for the `fetch` subcommand.
#[derive(Parser, Debug, Clone)]
pub struct FetchArgs {
    /// Global concurrency cap.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_CONCURRENCY)]
    pub concurrency: usize,

    /// Per-host concurrency cap.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_PER_HOST_CONCURRENCY)]
    pub per_host_concurrency: usize,

    /// Connect timeout in seconds.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_CONNECT_TIMEOUT_SECS)]
    pub connect_timeout: u64,

    /// Read (inter-chunk) timeout in seconds.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_READ_TIMEOUT_SECS)]
    pub read_timeout: u64,

    /// Total timeout for a single attempt, in seconds.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_TOTAL_TIMEOUT_SECS)]
    pub total_timeout: u64,

    /// Ceiling on the whole retry sequence for one request, in seconds.
    #[arg(long, default_value_t = crate::fetch::client::DEFAULT_REQUEST_DEADLINE_SECS)]
    pub request_deadline: u64,

    /// Cache TTL in seconds (0 = no expiry).
    #[arg(long, default_value_t = crate::fetch::cache::DEFAULT_CACHE_TTL_SECS)]
    pub cache_ttl: u64,

    /// Maximum decompressed response body in bytes.
    #[arg(long, default_value_t = crate::fetch::client::MAX_BODY_BYTES)]
    pub max_body_bytes: usize,

    /// Disable on-disk cache.
    #[arg(long)]
    pub no_cache: bool,

    /// Explicit cache directory. When omitted, Rust resolves it from the
    /// platform convention (standalone CLI use only).
    #[arg(long)]
    pub cache_dir: Option<String>,

    /// Byte ceiling for the on-disk cache. When exceeded, entries are evicted
    /// least-recently-used first.
    #[arg(long, default_value_t = crate::fetch::cache::DEFAULT_MAX_CACHE_BYTES)]
    pub max_cache_bytes: u64,

    /// Offline mode: serve only from cache, never hit the network. A cache
    /// miss is a recorded non-fatal absence.
    #[arg(long)]
    pub offline: bool,
}
