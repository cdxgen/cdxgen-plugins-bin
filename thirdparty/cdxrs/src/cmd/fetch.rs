//! `cdxrs fetch` — batched, cached, concurrent registry GETs.
//!
//! Reads `{"requests":[{"id","url","accept"?,"authRealm"?}]}` on stdin and
//! writes `{"schemaVersion","results":[...],"stats":{...}}` on stdout. Per-host
//! statistics go to stderr as NDJSON so `--debug` can surface them without
//! disturbing the stdout contract.
//!
//! This subcommand does **not** understand registries, components or purls. It
//! is the network, and only the network; `lib/ecosystems/ecosystems.js` builds
//! the URLs and derives every field from the returned documents, exactly as it
//! does when the Rust path is unavailable. See `src/fetch/batch.rs` for why.

use std::sync::Arc;

use crate::error::CdxrsError;
use crate::fetch::batch::{BatchInput, BatchOptions, run_batch};
use crate::fetch::cache::{DEFAULT_CACHE_TTL_SECS, DEFAULT_MAX_CACHE_BYTES, HttpCache};
use crate::fetch::client::{FetchClient, FetchClientConfig};
use crate::io as io_mod;
use crate::log;

/// Configuration for the fetch subcommand.
pub struct FetchConfig {
    pub client_config: FetchClientConfig,
    pub cache_enabled: bool,
    pub cache_ttl_secs: u64,
    pub cache_max_bytes: u64,
    /// Explicit cache directory from `--cache-dir`. When `None`, Rust falls
    /// back to its own resolution (standalone CLI use only).
    pub cache_dir: Option<std::path::PathBuf>,
    pub offline: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            client_config: FetchClientConfig::default(),
            cache_enabled: true,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            cache_max_bytes: DEFAULT_MAX_CACHE_BYTES,
            cache_dir: None,
            offline: false,
        }
    }
}

/// Execute the `fetch` subcommand.
pub async fn run(
    input_path: &str,
    output_path: &Option<String>,
    max_input_bytes: Option<u64>,
    config: FetchConfig,
) -> Result<(), CdxrsError> {
    let max_bytes = max_input_bytes.unwrap_or(crate::io::DEFAULT_MAX_INPUT_BYTES);
    let data = io_mod::read_input(input_path, max_bytes)?;
    let input: BatchInput = serde_json::from_slice(&data)?;

    if input.requests.is_empty() {
        // An empty batch is a valid, successful, no-op — the caller found
        // nothing to look up. It must not be an error, or a project with no
        // dependencies would fail the run.
        let output = serde_json::json!({
            "schemaVersion": crate::fetch::batch::BATCH_SCHEMA_VERSION,
            "results": [],
            "stats": { "requests": 0, "unique": 0 },
        });
        io_mod::write_output(output_path, format!("{output}\n").as_bytes())?;
        return Ok(());
    }

    let client = Arc::new(
        FetchClient::new(config.client_config)
            .map_err(|e| CdxrsError::Other(format!("failed to create HTTP client: {e}")))?,
    );

    // JS is the authority for the cache directory: when it passes --cache-dir,
    // that path wins. Rust's own resolution is the fallback for standalone CLI
    // use only.
    let resolved = config
        .cache_dir
        .clone()
        .or_else(HttpCache::resolve_cache_dir);
    let cache_enabled = config.cache_enabled && resolved.is_some();
    let cache_root = resolved.unwrap_or_else(|| {
        log::debug("no cache directory could be resolved; running without a cache");
        std::path::PathBuf::from(".cdxgen-cache-unavailable")
    });
    let cache = Arc::new(HttpCache::new(
        cache_root,
        config.cache_ttl_secs,
        config.cache_max_bytes,
        cache_enabled,
    ));

    if config.offline && !cache_enabled {
        // --offline --no-cache can never produce a single result. Saying so is
        // more useful than returning an envelope of absences.
        return Err(CdxrsError::Other(
            "--offline requires the cache; it cannot be combined with --no-cache".to_string(),
        ));
    }

    let output = run_batch(
        input,
        client,
        cache,
        BatchOptions {
            offline: config.offline,
        },
    )
    .await;

    // Per-host report on stderr, one object per host.
    for (host, host_stats) in &output.stats.hosts {
        log::log(
            crate::log::Level::Info,
            &format!("fetch: {host}"),
            Some(&serde_json::json!({
                "host": host,
                "requests": host_stats.requests,
                "cacheHits": host_stats.cache_hits,
                "failures": host_stats.failures,
                "rateLimited": host_stats.rate_limited,
            })),
        );
    }
    log::log(
        crate::log::Level::Info,
        &format!(
            "fetch: {} request(s), {} unique, {} ok, {} failed, {} from cache in {} ms",
            output.stats.requests,
            output.stats.unique,
            output.stats.ok,
            output.stats.failures,
            output.stats.cache_hits,
            output.stats.elapsed_ms,
        ),
        Some(&serde_json::to_value(&output.stats).unwrap_or_default()),
    );

    let body = serde_json::to_string(&output)?;
    io_mod::write_output(output_path, format!("{body}\n").as_bytes())?;
    Ok(())
}
