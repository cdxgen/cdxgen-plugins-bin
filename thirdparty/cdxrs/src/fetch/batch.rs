//! Batched, cached, concurrent HTTP GET.
//!
//! This module is deliberately registry-agnostic. It knows how to fetch a list
//! of URLs politely, in parallel, with an on-disk cache — and nothing else. It
//! does not know what npm metadata looks like, it does not construct purls, and
//! it never decides what a component should contain.
//!
//! That division is the whole point. An earlier design put per-registry field
//! extraction in Rust: it had to reproduce, in a second language, every
//! fallback chain, every provenance property and every SPDX lookup that
//! `lib/ecosystems/ecosystems.js` performs — and it silently diverged from all
//! three registries it covered, dropped ~65 provenance properties, and emitted
//! component keys that CycloneDX rejects. Keeping derivation in JS means the
//! Rust path cannot produce a different SBOM than the JS path, because the same
//! JavaScript builds the components either way from the same registry
//! documents. Rust supplies the one thing JS is bad at: 2000 concurrent HTTP
//! requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::cache::{CacheEntry, CacheKey, HttpCache, Lookup, unix_now};
use super::client::{FetchClient, FetchFailure, Validators};

/// Wire format version for the request/response envelope. The JS bridge
/// asserts on this, so a change here is a change there.
pub const BATCH_SCHEMA_VERSION: u32 = 1;

/// One requested URL.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRequest {
    /// Caller-chosen correlation id, echoed back on the result. The JS side
    /// uses the registry cache key it would have used anyway.
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub accept: Option<String>,
    /// Identity of the auth realm this request belongs to — part of the cache
    /// key so that an authenticated response is never served to an anonymous
    /// lookup. Never a credential: tokens are read from the environment by the
    /// client and never cross this boundary.
    #[serde(default, rename = "authRealm")]
    pub auth_realm: Option<String>,
}

/// The batch envelope read from stdin.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchInput {
    pub requests: Vec<BatchRequest>,
}

/// One result, correlated by `id`.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "fromCache")]
    pub from_cache: bool,
    /// True when a stale cache entry was confirmed still valid with a 304.
    pub revalidated: bool,
}

/// Aggregate counters, emitted on stderr as NDJSON and on stdout with the
/// results so `--debug` can surface them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BatchStats {
    pub requests: usize,
    /// Distinct cache keys actually fetched (identical URLs are coalesced).
    pub unique: usize,
    pub ok: usize,
    pub failures: usize,
    #[serde(rename = "cacheHits")]
    pub cache_hits: usize,
    pub revalidated: usize,
    #[serde(rename = "offlineMisses")]
    pub offline_misses: usize,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: u64,
    #[serde(rename = "peakConcurrency")]
    pub peak_concurrency: usize,
    /// Per-host request counts and server-imposed back-offs.
    pub hosts: HashMap<String, HostStats>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostStats {
    pub requests: usize,
    pub failures: usize,
    #[serde(rename = "cacheHits")]
    pub cache_hits: usize,
    #[serde(rename = "rateLimited")]
    pub rate_limited: u32,
}

/// The complete response envelope.
#[derive(Debug, Clone, Serialize)]
pub struct BatchOutput {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub results: Vec<BatchResult>,
    pub stats: BatchStats,
}

/// Options that are not part of the HTTP client itself.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Serve from cache only; never touch the network. A miss is a recorded
    /// absence, not an error.
    pub offline: bool,
}

/// Run a batch of GETs.
pub async fn run_batch(
    input: BatchInput,
    client: Arc<FetchClient>,
    cache: Arc<HttpCache>,
    options: BatchOptions,
) -> BatchOutput {
    let started = Instant::now();
    let mut stats = BatchStats {
        requests: input.requests.len(),
        ..Default::default()
    };

    // Coalesce duplicate cache keys. Two components frequently resolve to the
    // same registry document (a monorepo with one dependency listed by many
    // workspaces), and the JS path deduplicates through its in-process
    // `metadata_cache`. Not doing the same here would issue N identical
    // requests and look like a rate-limit problem of our own making.
    let mut order: Vec<String> = Vec::new();
    let mut by_key: HashMap<String, (CacheKey, Vec<String>)> = HashMap::new();
    for req in &input.requests {
        let key = CacheKey::get(&req.url)
            .with_accept(req.accept.as_deref())
            .with_auth_realm(req.auth_realm.as_deref());
        let hash = key.hash();
        match by_key.get_mut(&hash) {
            Some((_, ids)) => ids.push(req.id.clone()),
            None => {
                order.push(hash.clone());
                by_key.insert(hash, (key, vec![req.id.clone()]));
            }
        }
    }
    stats.unique = order.len();

    let mut tasks = Vec::with_capacity(order.len());
    for hash in &order {
        let (key, _) = by_key.get(hash).expect("hash was just inserted");
        let key = key.clone();
        let client = Arc::clone(&client);
        let cache = Arc::clone(&cache);
        let offline = options.offline;
        tasks.push(tokio::spawn(async move {
            fetch_one(&client, &cache, &key, offline).await
        }));
    }

    let mut results: Vec<BatchResult> = Vec::with_capacity(input.requests.len());
    for (hash, task) in order.iter().zip(tasks) {
        let (key, ids) = by_key.get(hash).expect("hash was just inserted");
        let host = super::client::extract_host(&key.url).unwrap_or_else(|| "?".to_string());
        let host_stats = stats.hosts.entry(host).or_default();
        host_stats.requests += 1;

        // A panicking task must not take the batch down with it: the remaining
        // results are still worth returning.
        let outcome = match task.await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::Failed(format!("worker task failed: {e}")),
        };

        let (ok, status, body, error, from_cache, revalidated) = match outcome {
            Outcome::Fetched { status, body } => {
                (true, Some(status), Some(body), None, false, false)
            }
            Outcome::Cached { status, body } => (true, Some(status), Some(body), None, true, false),
            Outcome::Revalidated { status, body } => {
                (true, Some(status), Some(body), None, true, true)
            }
            Outcome::OfflineMiss => (
                false,
                None,
                None,
                Some("offline-miss".to_string()),
                false,
                false,
            ),
            Outcome::Status(code) => (
                false,
                Some(code),
                None,
                Some(format!("http status {code}")),
                false,
                false,
            ),
            Outcome::Failed(msg) => (false, None, None, Some(msg), false, false),
        };

        if ok {
            stats.ok += ids.len();
        } else {
            stats.failures += ids.len();
            host_stats.failures += 1;
        }
        if from_cache {
            stats.cache_hits += ids.len();
            host_stats.cache_hits += 1;
        }
        if revalidated {
            stats.revalidated += ids.len();
        }
        if error.as_deref() == Some("offline-miss") {
            stats.offline_misses += ids.len();
        }

        // Fan the single fetch back out to every caller id that asked for it.
        for id in ids {
            results.push(BatchResult {
                id: id.clone(),
                ok,
                status,
                body: body.clone(),
                error: error.clone(),
                from_cache,
                revalidated,
            });
        }
    }

    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    // The client counts this after its permits are held, so it is real HTTP
    // concurrency and not the number of tasks parked behind a semaphore.
    stats.peak_concurrency = client.peak_in_flight();

    BatchOutput {
        schema_version: BATCH_SCHEMA_VERSION,
        results,
        stats,
    }
}

enum Outcome {
    Fetched {
        status: u16,
        body: serde_json::Value,
    },
    Cached {
        status: u16,
        body: serde_json::Value,
    },
    Revalidated {
        status: u16,
        body: serde_json::Value,
    },
    OfflineMiss,
    Status(u16),
    Failed(String),
}

async fn fetch_one(
    client: &FetchClient,
    cache: &HttpCache,
    key: &CacheKey,
    offline: bool,
) -> Outcome {
    let lookup = cache.get(key);

    if offline {
        return match lookup {
            // Offline deliberately accepts a stale entry: the alternative is a
            // recorded absence, and a slightly old licence string is more
            // useful than none.
            Lookup::Fresh(entry) | Lookup::Stale(entry) => Outcome::Cached {
                status: entry.status,
                body: entry.body,
            },
            Lookup::Miss => Outcome::OfflineMiss,
        };
    }

    let validators = match &lookup {
        Lookup::Fresh(entry) => {
            return Outcome::Cached {
                status: entry.status,
                body: entry.body.clone(),
            };
        }
        Lookup::Stale(entry) => Validators {
            etag: entry.etag.clone(),
            last_modified: entry.last_modified.clone(),
        },
        Lookup::Miss => Validators::default(),
    };

    match client
        .get_json(&key.url, key.accept.as_deref(), None, &validators)
        .await
    {
        Ok(success) if success.not_modified => {
            // 304: the stale entry is good after all. Rewrite it with a fresh
            // timestamp so the next run does not revalidate again.
            match lookup {
                Lookup::Stale(mut entry) => {
                    let body = entry.body.clone();
                    let status = entry.status;
                    entry.fetched_at = unix_now();
                    if success.etag.is_some() {
                        entry.etag = success.etag;
                    }
                    if success.last_modified.is_some() {
                        entry.last_modified = success.last_modified;
                    }
                    cache.put(key, &entry);
                    Outcome::Revalidated { status, body }
                }
                // A 304 without a cached body should not happen (we only send
                // validators when we have one) but must not be reported as a
                // success with no content.
                _ => Outcome::Failed("304 with no cached entry".to_string()),
            }
        }
        Ok(success) => {
            let entry = CacheEntry {
                v: super::cache::CACHE_SCHEMA_VERSION,
                url: key.url.clone(),
                method: key.method.clone(),
                status: success.status,
                etag: success.etag.clone(),
                last_modified: success.last_modified.clone(),
                fetched_at: unix_now(),
                body: success.body.clone(),
            };
            cache.put(key, &entry);
            Outcome::Fetched {
                status: success.status,
                body: success.body,
            }
        }
        Err(FetchFailure::Status(code)) => {
            // A stale entry is better than nothing when the origin has started
            // failing — but only for server-side failures. A 404 means the
            // document is gone and the stale copy should not be resurrected.
            if code >= 500
                && let Lookup::Stale(entry) = lookup
            {
                return Outcome::Cached {
                    status: entry.status,
                    body: entry.body,
                };
            }
            Outcome::Status(code)
        }
        Err(failure) => {
            if let Lookup::Stale(entry) = lookup {
                return Outcome::Cached {
                    status: entry.status,
                    body: entry.body,
                };
            }
            Outcome::Failed(failure.to_string())
        }
    }
}
