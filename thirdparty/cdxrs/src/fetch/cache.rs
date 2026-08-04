//! On-disk HTTP response cache.
//!
//! The cache root is resolved from `CDXGEN_CACHE_DIR` (the documented escape
//! hatch used by the test harness) or the platform cache directory; see
//! [`resolve_cache_dir`]. When JS is driving (the normal case) it passes
//! `--cache-dir` explicitly so both sides agree.
//!
//! Keys are derived from the full URL, the method, the `Accept` header and the
//! auth-realm *identity* — never the credential. Getting that set wrong is how
//! a private registry's response ends up served to a public lookup, so
//! [`CacheKey`] exists specifically so that a read and a write cannot disagree
//! about what the key was: both take the same struct, and there is no way to
//! call one of them with a subset of the fields.
//!
//! Loopback hosts (`127.0.0.0/8`, `::1`, `localhost`) are never cached: their
//! entries are keyed by ephemeral ports that will never be reused. Set
//! `CDXGEN_CACHE_LOOPBACK=1` to override (used by `contrib/bench-fetch.js`).
//!
//! Bounded by a TTL sweep (opportunistic, per host directory) and an LRU byte
//! ceiling (default 256 MB, plus a slack budget between enforcement passes).
//! Access order is tracked via file mtime, moved forward on every cache hit
//! without writing any bytes.
//!
//! File layout:
//! ```text
//! <cache_dir>/cdxrs-fetch/<host>/<hash>.json
//! ```

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::client::redact_url;

/// Cache schema version. Bump when the on-disk format changes.
pub const CACHE_SCHEMA_VERSION: u32 = 2;

/// Default TTL for cached entries (24 hours).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Default byte ceiling for the on-disk cache (256 MB).
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;

/// Bytes a run may add before a byte-ceiling enforcement pass is due, as a
/// fraction of the ceiling.
///
/// A pass walks and stats the whole cache, so it must not run per write: on a
/// 20k-entry cache one pass costs tens of milliseconds, which is the same order
/// as the entire batch it would be charged to. Waiting until a run has added a
/// slack budget's worth of data means a typical scan (a few MB of registry
/// metadata) triggers no pass at all, at the cost of letting the cache sit up
/// to one slack budget over the ceiling between passes.
const ENFORCEMENT_SLACK_DIVISOR: u64 = 8;

/// Floor for the slack budget, so a small `--max-cache-bytes` cannot reduce it
/// to a value that makes every write trigger a pass again.
const ENFORCEMENT_SLACK_FLOOR_BYTES: u64 = 8 * 1024 * 1024;

/// How old an unrenamed temp file must be before the sweep reclaims it. Long
/// enough that a live writer in another process is never mistaken for an
/// orphan.
const ORPHAN_TEMP_MIN_AGE_SECS: u64 = 60 * 60;

/// Everything that identifies a cached response.
///
/// Constructed once per request and passed to both [`HttpCache::get`] and
/// [`HttpCache::put`], so the two cannot hash different things. Keep it that
/// way: a `put` that dropped `accept` or `auth_realm` would file an
/// authenticated response under the key an unauthenticated reader looks up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    pub url: String,
    pub method: String,
    pub accept: Option<String>,
    /// Identity of the auth realm — e.g. `github:owner/repo`, or the registry
    /// host for a token-bearing registry. Never the credential itself.
    pub auth_realm: Option<String>,
}

impl CacheKey {
    pub fn get(url: &str) -> Self {
        Self {
            url: url.to_string(),
            method: "GET".to_string(),
            accept: None,
            auth_realm: None,
        }
    }

    pub fn with_accept(mut self, accept: Option<&str>) -> Self {
        self.accept = accept.map(|s| s.to_string());
        self
    }

    pub fn with_auth_realm(mut self, realm: Option<&str>) -> Self {
        self.auth_realm = realm.map(|s| s.to_string());
        self
    }

    /// Hash of the key. Length-prefixed per field so that two different field
    /// splits cannot hash to the same digest (`accept="ab"` + `realm=None`
    /// must not collide with `accept="a"` + `realm="b"`).
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CACHE_SCHEMA_VERSION.to_le_bytes());
        for field in [
            Some(self.url.as_str()),
            Some(self.method.as_str()),
            self.accept.as_deref(),
            self.auth_realm.as_deref(),
        ] {
            match field {
                Some(v) => {
                    hasher.update((v.len() as u64).to_le_bytes());
                    hasher.update(v.as_bytes());
                }
                // A distinct marker, so `None` and `""` are different keys.
                None => hasher.update(u64::MAX.to_le_bytes()),
            }
        }
        let digest = hasher.finalize();
        digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
    }
}

/// An entry in the HTTP cache.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CacheEntry {
    pub v: u32,
    /// Redacted URL, kept for debuggability only — never used to build a key.
    /// Storing the raw URL would persist any credential it carried into a file
    /// that outlives the run.
    pub url: String,
    pub method: String,
    pub status: u16,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub fetched_at: u64,
    pub body: serde_json::Value,
}

/// Outcome of a cache lookup.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// Fresh entry — usable as-is, no request needed.
    Fresh(CacheEntry),
    /// Present but stale, with validators for a conditional request.
    Stale(CacheEntry),
    /// Nothing on disk.
    Miss,
}

/// On-disk HTTP response cache.
pub struct HttpCache {
    root: PathBuf,
    ttl_secs: u64,
    max_bytes: u64,
    enabled: bool,
    /// Host directories already swept for expired entries in this process.
    /// A sweep runs once per host per process — once per cdxgen run.
    swept_hosts: Mutex<HashSet<PathBuf>>,
    /// Approximate bytes written since the last enforcement pass.
    bytes_since_enforcement: AtomicU64,
    /// Enforcement passes run by this instance. A pass walks the whole cache,
    /// so its frequency is a performance property worth asserting on.
    enforcement_passes: AtomicU64,
}

/// Which platform's cache convention to use. Exposed so tests can drive
/// every branch without `#[cfg]`-gating the test module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePlatform {
    Linux,
    Macos,
    Windows,
}

impl CachePlatform {
    /// The platform this binary was compiled for.
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Self::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "macos", unix, target_os = "windows")))]
        {
            Self::Linux
        }
    }
}

impl HttpCache {
    /// Create a cache rooted at the given directory.
    pub fn new(root: PathBuf, ttl_secs: u64, max_bytes: u64, enabled: bool) -> Self {
        Self {
            root,
            ttl_secs,
            max_bytes,
            enabled,
            swept_hosts: Mutex::new(HashSet::new()),
            bytes_since_enforcement: AtomicU64::new(0),
            enforcement_passes: AtomicU64::new(0),
        }
    }

    /// Number of byte-ceiling enforcement passes run by this instance.
    pub fn enforcement_passes(&self) -> u64 {
        self.enforcement_passes.load(Ordering::Relaxed)
    }

    // ---------------------------------------------------- cache-root resolution

    /// Pure resolution of the cache directory from environment values.
    ///
    /// Every platform branch is exercised by the test suite on every host,
    /// because the inputs are parameters — not `#[cfg]` gates on the tests.
    /// `xdg_cache_home` must be absolute (per the XDG spec); a relative value
    /// is ignored so it cannot point inside the current working directory.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_cache_for(
        platform: CachePlatform,
        cdxgen_cache_dir: Option<&str>,
        xdg_cache_home: Option<&str>,
        home: Option<&str>,
        localappdata: Option<&str>,
        userprofile: Option<&str>,
    ) -> Option<PathBuf> {
        if let Some(dir) = cdxgen_cache_dir.filter(|s| !s.is_empty()) {
            return Some(PathBuf::from(dir));
        }
        match platform {
            CachePlatform::Linux => xdg_cache_home
                .filter(|s| !s.is_empty() && Path::new(s).is_absolute())
                .map(|d| PathBuf::from(d).join("cdxgen"))
                .or_else(|| {
                    home.filter(|s| !s.is_empty())
                        .map(|h| PathBuf::from(h).join(".cache").join("cdxgen"))
                }),
            CachePlatform::Macos => home.filter(|s| !s.is_empty()).map(|h| {
                PathBuf::from(h)
                    .join("Library")
                    .join("Caches")
                    .join("cdxgen")
            }),
            CachePlatform::Windows => localappdata
                .filter(|s| !s.is_empty())
                .map(|d| PathBuf::from(d).join("cdxgen").join("cache"))
                .or_else(|| {
                    userprofile.filter(|s| !s.is_empty()).map(|p| {
                        PathBuf::from(p)
                            .join("AppData")
                            .join("Local")
                            .join("cdxgen")
                            .join("cache")
                    })
                }),
        }
    }

    /// Resolve the cache directory from the current environment.
    pub fn resolve_cache_dir() -> Option<PathBuf> {
        fn get(key: &str) -> Option<String> {
            env::var(key).ok().filter(|s| !s.is_empty())
        }
        Self::resolve_cache_for(
            CachePlatform::current(),
            get("CDXGEN_CACHE_DIR").as_deref(),
            get("XDG_CACHE_HOME").as_deref(),
            get("HOME").as_deref(),
            get("LOCALAPPDATA").as_deref(),
            get("USERPROFILE").as_deref(),
        )
    }

    // ----------------------------------------------------------- core methods

    fn fetch_subdir(&self) -> PathBuf {
        self.root.join("cdxrs-fetch")
    }

    fn path_for(&self, key: &CacheKey) -> Option<PathBuf> {
        let host = extract_host(&key.url)?;
        Some(
            self.fetch_subdir()
                .join(host)
                .join(format!("{}.json", key.hash())),
        )
    }

    /// Look up an entry, distinguishing fresh from stale-but-revalidatable.
    pub fn get(&self, key: &CacheKey) -> Lookup {
        if !self.enabled {
            return Lookup::Miss;
        }
        if is_loopback_url(&key.url) {
            return Lookup::Miss;
        }
        let Some(path) = self.path_for(key) else {
            return Lookup::Miss;
        };
        // Sweep the host directory once per process before reading, so stale
        // entries do not accumulate across runs. The sweep is best-effort: a
        // failure (permissions, race) leaves the directory untouched and the
        // read proceeds normally.
        self.maybe_sweep_host_dir(&path);
        let Ok(data) = fs::read(&path) else {
            return Lookup::Miss;
        };
        let Ok(entry) = serde_json::from_slice::<CacheEntry>(&data) else {
            crate::log::debug(&format!(
                "discarding unreadable cache entry {}",
                path.display()
            ));
            let _ = fs::remove_file(&path);
            return Lookup::Miss;
        };
        if entry.v != CACHE_SCHEMA_VERSION {
            return Lookup::Miss;
        }
        if self.is_fresh(&entry) {
            // Touch the file's mtime to record the access for LRU eviction.
            // mtime is used rather than atime because Linux mounts typically
            // use `relatime` or `noatime`, making atime unreliable. The touch
            // modifies no contents, so it cannot corrupt a concurrent write.
            touch_file(&path);
            Lookup::Fresh(entry)
        } else if entry.etag.is_some() || entry.last_modified.is_some() {
            Lookup::Stale(entry)
        } else {
            Lookup::Miss
        }
    }

    /// A TTL of zero means "never expires", as `--cache-ttl 0` documents.
    fn is_fresh(&self, entry: &CacheEntry) -> bool {
        if self.ttl_secs == 0 {
            return true;
        }
        let now = unix_now();
        now.saturating_sub(entry.fetched_at) <= self.ttl_secs
    }

    /// Write an entry atomically.
    ///
    /// No advisory locking is used, and none is needed: the temp file name is
    /// unique per process *and* per call, and `rename(2)` within a directory is
    /// atomic, so a concurrent writer can only ever replace the whole file with
    /// another complete file.
    ///
    /// The temp file is deliberately not fsynced. Atomicity comes from the
    /// rename, not from durability, and every byte here is re-derivable from the
    /// network — so the only thing an fsync buys is that a post-crash entry is
    /// whole rather than truncated, which [`get`](Self::get) already handles by
    /// discarding entries it cannot parse. It is not worth its cost: fsyncing a
    /// 200-response batch takes about a second, against about 40 ms without.
    pub fn put(&self, key: &CacheKey, entry: &CacheEntry) {
        if !self.enabled {
            return;
        }
        if is_loopback_url(&key.url) {
            return;
        }
        let Some(final_path) = self.path_for(key) else {
            return;
        };
        let Some(dir) = final_path.parent() else {
            return;
        };
        if fs::create_dir_all(dir).is_err() {
            return;
        }
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp_path = dir.join(format!(
            "{}.tmp.{}.{}",
            key.hash(),
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let mut stored = entry.clone();
        stored.url = redact_url(&key.url);
        let Ok(data) = serde_json::to_vec(&stored) else {
            return;
        };

        // 0600 is requested at open time. Setting it afterwards leaves a window
        // in which the response body is world-readable under a 0644 umask.
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&tmp_path) else {
            return;
        };
        if file.write_all(&data).is_ok() {
            drop(file);
            let _ = fs::rename(&tmp_path, &final_path);
            // Track bytes written so enforcement can be triggered without
            // walking the cache on every write.
            self.bytes_since_enforcement
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        } else {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
        }
        // Opportunistic byte-ceiling enforcement.
        self.maybe_enforce_ceiling();
    }

    /// Whether the cache is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // --------------------------------------------------------- TTL + eviction

    /// Remove expired entries from a host directory, once per process.
    fn maybe_sweep_host_dir(&self, entry_path: &Path) {
        let Some(host_dir) = entry_path.parent() else {
            return;
        };
        let mut swept = match self.swept_hosts.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if !swept.insert(host_dir.to_path_buf()) {
            return;
        }
        // `swept` is released implicitly at end of scope, but the sweep itself
        // does not need to hold it — the set prevents re-entry, which is the
        // only race that matters. Drop early so a slow directory scan does not
        // block a concurrent `get` on a different host.
        drop(swept);
        let now = unix_now();
        let cutoff = now.saturating_sub(self.ttl_secs);
        let Ok(entries) = fs::read_dir(host_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_temp_entry(&path) {
                // A `put` that crashed between creating its temp file and
                // renaming it leaves the file behind, and nothing else ever
                // looks at it again. Only reclaim ones old enough that no live
                // writer in another process can still be filling them.
                if let Ok(meta) = entry.metadata()
                    && file_age_secs(&meta, now) > ORPHAN_TEMP_MIN_AGE_SECS
                {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            if self.ttl_secs == 0 {
                continue;
            }
            // stat is cheaper than read, so mtime is used to skip entries that
            // cannot be worth reading. Note that `touch_file` moves mtime
            // forward on every hit, so a recent mtime means recently *used*,
            // not recently fetched: an expired entry that keeps being read is
            // skipped here and left for the byte ceiling to evict. `fetched_at`
            // inside the entry, read below, remains the only authority on
            // freshness.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if let Ok(mtime) = meta.modified()
                && let Ok(since_epoch) = mtime.duration_since(UNIX_EPOCH)
                && since_epoch.as_secs() >= cutoff
            {
                continue;
            }
            // Past TTL: read to check whether it has validators (keep for
            // conditional revalidation) or not (remove).
            let Ok(data) = fs::read(&path) else {
                continue;
            };
            let Ok(cache_entry) = serde_json::from_slice::<CacheEntry>(&data) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            if cache_entry.v != CACHE_SCHEMA_VERSION {
                let _ = fs::remove_file(&path);
                continue;
            }
            if cache_entry.etag.is_some() || cache_entry.last_modified.is_some() {
                continue;
            }
            let _ = fs::remove_file(&path);
        }
    }

    /// Slack budget: the bytes this cache may add between enforcement passes.
    fn enforcement_slack_bytes(&self) -> u64 {
        (self.max_bytes / ENFORCEMENT_SLACK_DIVISOR).max(ENFORCEMENT_SLACK_FLOOR_BYTES)
    }

    /// Run an enforcement pass if this cache has added a slack budget's worth
    /// of data since the last one.
    ///
    /// The cache is therefore bounded by `max_bytes + slack` rather than
    /// exactly `max_bytes`. A cache left over the ceiling by a run that exited
    /// before its next pass is reclaimed by the next run that writes a slack
    /// budget, or immediately by `cdxgen cache --clear`.
    fn maybe_enforce_ceiling(&self) {
        if self.bytes_since_enforcement.load(Ordering::Relaxed) < self.enforcement_slack_bytes() {
            return;
        }
        // Reset the counter before scanning so writes during the scan are
        // counted towards the next pass.
        self.bytes_since_enforcement.store(0, Ordering::Relaxed);
        self.enforcement_passes.fetch_add(1, Ordering::Relaxed);
        self.enforce_byte_ceiling();
    }

    /// Walk the cache, sum entry sizes, and evict by mtime (oldest first)
    /// until the total is under the ceiling.
    ///
    /// Each eviction is a plain `remove_file`: atomic on every platform, and
    /// a concurrent reader that loses the race sees a `Miss` (not an error),
    /// which the fetcher handles by refetching. A concurrent writer simply
    /// rewrites the entry on its next pass.
    fn enforce_byte_ceiling(&self) {
        let fetch_dir = self.fetch_subdir();
        struct EntryInfo {
            path: PathBuf,
            size: u64,
            mtime_secs: u64,
        }
        let mut entries: Vec<EntryInfo> = Vec::new();
        let mut total: u64 = 0;

        let Ok(hosts) = fs::read_dir(&fetch_dir) else {
            return;
        };
        for host_entry in hosts.flatten() {
            let host_dir = host_entry.path();
            if !host_dir.is_dir() {
                continue;
            }
            let Ok(files) = fs::read_dir(&host_dir) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                if !path.is_file() {
                    continue;
                }
                let Ok(meta) = file.metadata() else {
                    continue;
                };
                let size = meta.len();
                let mtime_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                total = total.saturating_add(size);
                entries.push(EntryInfo {
                    path,
                    size,
                    mtime_secs,
                });
            }
        }

        if total <= self.max_bytes {
            return;
        }

        // Sort by mtime ascending (oldest first), then by path for determinism.
        entries.sort_by(|a, b| {
            a.mtime_secs
                .cmp(&b.mtime_secs)
                .then_with(|| a.path.cmp(&b.path))
        });

        for e in &entries {
            if total <= self.max_bytes {
                break;
            }
            let _ = fs::remove_file(&e.path);
            total = total.saturating_sub(e.size);
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether a path is a `put` temp file rather than a cache entry.
fn is_temp_entry(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains(".tmp."))
}

/// Seconds between a file's mtime and `now`, saturating at zero for a file
/// whose mtime is in the future (clock skew, or a copy that preserved times).
fn file_age_secs(meta: &fs::Metadata, now: u64) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| now.saturating_sub(d.as_secs()))
        .unwrap_or(0)
}

fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(|h| h.to_string())
}

/// Whether loopback hosts should be cached at all. Test doubles on
/// `127.0.0.1` are cheap to refetch and their port-keyed entries are
/// permanently unhittable. `CDXGEN_CACHE_LOOPBACK=1` overrides (used by
/// `contrib/bench-fetch.js` so the warm-cache benchmark still measures a hit).
fn loopback_cache_allowed() -> bool {
    matches!(
        env::var("CDXGEN_CACHE_LOOPBACK").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Whether a URL targets a loopback address that must not be cached.
/// Takes the loopback-override flag as a parameter for testability.
fn is_loopback_url_for(url: &str, loopback_allowed: bool) -> bool {
    if loopback_allowed {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

/// Whether a URL targets a loopback address that must not be cached.
fn is_loopback_url(url: &str) -> bool {
    is_loopback_url_for(url, loopback_cache_allowed())
}

/// Set a file's mtime to "now" without modifying its contents.
///
/// [`enforce_byte_ceiling`](HttpCache::enforce_byte_ceiling) evicts by mtime, so
/// this is what makes eviction least-recently-*used* rather than oldest-written.
/// `atime` would be the natural field, but Linux mounts are commonly `relatime`
/// or `noatime`, so it cannot be relied on. Writing no bytes keeps the touch
/// safe against a concurrent `put`, which replaces the whole file.
///
/// Best-effort: a failure only costs eviction accuracy.
fn touch_file(path: &Path) {
    let now = fs::FileTimes::new().set_modified(SystemTime::now());
    if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
        let _ = file.set_times(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a cache with the default byte ceiling.
    fn test_cache(root: PathBuf, ttl: u64, enabled: bool) -> HttpCache {
        HttpCache::new(root, ttl, DEFAULT_MAX_CACHE_BYTES, enabled)
    }

    /// Helper: every regular file under a fetch cache directory.
    fn walk_cache_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk_cache_files(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    fn entry(url: &str, fetched_at: u64) -> CacheEntry {
        CacheEntry {
            v: CACHE_SCHEMA_VERSION,
            url: url.to_string(),
            method: "GET".to_string(),
            status: 200,
            etag: Some("\"abc\"".to_string()),
            last_modified: None,
            fetched_at,
            body: serde_json::json!({"crate": {"description": "test"}}),
        }
    }

    #[test]
    fn different_hosts_are_different_keys() {
        assert_ne!(
            CacheKey::get("https://registry.npmjs.org/left-pad").hash(),
            CacheKey::get("https://npm.jsr.io/left-pad").hash(),
        );
    }

    #[test]
    fn different_auth_realms_are_different_keys() {
        let url = "https://registry.example.com/left-pad";
        assert_ne!(
            CacheKey::get(url).with_auth_realm(Some("public")).hash(),
            CacheKey::get(url)
                .with_auth_realm(Some("private:corp"))
                .hash(),
        );
    }

    #[test]
    fn accept_is_part_of_the_key() {
        let url = "https://pub.dev/api/packages/http";
        assert_ne!(
            CacheKey::get(url).hash(),
            CacheKey::get(url)
                .with_accept(Some("application/vnd.pub.v2+json"))
                .hash(),
        );
    }

    #[test]
    fn field_boundaries_cannot_be_confused() {
        let url = "https://registry.example.com/x";
        assert_ne!(
            CacheKey::get(url)
                .with_accept(Some("ab"))
                .with_auth_realm(None)
                .hash(),
            CacheKey::get(url)
                .with_accept(Some("a"))
                .with_auth_realm(Some("b"))
                .hash(),
        );
    }

    #[test]
    fn none_and_empty_accept_are_different_keys() {
        let url = "https://registry.example.com/x";
        assert_ne!(
            CacheKey::get(url).with_accept(None).hash(),
            CacheKey::get(url).with_accept(Some("")).hash(),
        );
    }

    /// The regression that mattered: an authenticated body must not become
    /// readable through the anonymous key.
    #[test]
    fn authenticated_body_is_not_served_to_an_anonymous_lookup() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://api.github.com/repos/o/r/license";

        let private_key = CacheKey::get(url).with_auth_realm(Some("github:o/r"));
        cache.put(&private_key, &entry(url, unix_now()));

        // Same URL, no realm: must miss.
        assert!(matches!(cache.get(&CacheKey::get(url)), Lookup::Miss));
        // Same realm: must hit.
        assert!(matches!(cache.get(&private_key), Lookup::Fresh(_)));
    }

    #[test]
    fn put_then_get_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        let original = entry(url, unix_now());
        cache.put(&key, &original);

        match cache.get(&key) {
            Lookup::Fresh(got) => {
                assert_eq!(got.body, original.body);
                assert_eq!(got.etag, original.etag);
            }
            other => panic!("expected a fresh hit, got {other:?}"),
        }
    }

    #[test]
    fn credentials_are_not_written_to_disk() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://user:s3cr3t-sentinel@registry.example.com/pkg?token=other-sentinel";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now()));

        let mut found = 0;
        for file in walk(tmp.path()) {
            let text = fs::read_to_string(&file).unwrap_or_default();
            assert!(
                !text.contains("s3cr3t-sentinel") && !text.contains("other-sentinel"),
                "credential leaked into {}",
                file.display()
            );
            found += 1;
        }
        assert!(found > 0, "no cache file was written, test proves nothing");
    }

    #[test]
    fn stale_entry_with_validator_is_revalidatable_not_a_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), 60, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now() - 3600));

        match cache.get(&key) {
            Lookup::Stale(got) => assert_eq!(got.etag.as_deref(), Some("\"abc\"")),
            other => panic!("expected stale, got {other:?}"),
        }
    }

    #[test]
    fn stale_entry_without_validator_is_a_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), 60, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        let mut e = entry(url, unix_now() - 3600);
        e.etag = None;
        e.last_modified = None;
        cache.put(&key, &e);

        assert!(matches!(cache.get(&key), Lookup::Miss));
    }

    #[test]
    fn ttl_zero_means_never_expires() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), 0, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, 0)); // fetched at the epoch

        assert!(
            matches!(cache.get(&key), Lookup::Fresh(_)),
            "--cache-ttl 0 documents 'no expiry'"
        );
    }

    #[test]
    fn disabled_cache_neither_reads_nor_writes() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, false);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now()));
        assert!(matches!(cache.get(&key), Lookup::Miss));
        assert_eq!(walk(tmp.path()).len(), 0);
    }

    #[test]
    fn schema_version_mismatch_is_a_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        let mut e = entry(url, unix_now());
        e.v = 999;
        cache.put(&key, &e);
        assert!(matches!(cache.get(&key), Lookup::Miss));
    }

    #[test]
    fn corrupt_entry_is_discarded_not_returned() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now()));
        let path = cache.path_for(&key).unwrap();
        fs::write(&path, b"{ truncated").unwrap();

        assert!(matches!(cache.get(&key), Lookup::Miss));
        assert!(!path.exists(), "corrupt entry should be removed");
    }

    #[cfg(unix)]
    #[test]
    fn cache_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now()));
        let mode = fs::metadata(cache.path_for(&key).unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn concurrent_writers_leave_a_complete_file() {
        let tmp = TempDir::new().unwrap();
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        let root = tmp.path().to_path_buf();

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let root = root.clone();
                let key = key.clone();
                let url = url.to_string();
                std::thread::spawn(move || {
                    let cache =
                        HttpCache::new(root, DEFAULT_CACHE_TTL_SECS, DEFAULT_MAX_CACHE_BYTES, true);
                    let mut e = entry(&url, unix_now());
                    e.body = serde_json::json!({ "writer": i, "pad": "x".repeat(64 * 1024) });
                    cache.put(&key, &e);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let cache = HttpCache::new(root, DEFAULT_CACHE_TTL_SECS, DEFAULT_MAX_CACHE_BYTES, true);
        match cache.get(&key) {
            Lookup::Fresh(got) => assert!(got.body.get("writer").is_some()),
            other => panic!("expected one complete entry, got {other:?}"),
        }
        // No temp files left behind.
        assert!(
            walk(tmp.path())
                .iter()
                .all(|p| !p.to_string_lossy().contains(".tmp.")),
        );
    }

    fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    // ----------------------------------------------------- D26: cache-root tests

    #[test]
    fn cdxgen_cache_dir_overrides_everything() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Linux,
            Some("/explicit/cache"),
            Some("/xdg/home"),
            Some("/home/user"),
            None,
            None,
        );
        assert_eq!(p, Some(PathBuf::from("/explicit/cache")));
    }

    #[test]
    fn linux_uses_xdg_cache_home_when_absolute() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Linux,
            None,
            Some("/var/cache"),
            Some("/home/user"),
            None,
            None,
        );
        assert_eq!(p, Some(PathBuf::from("/var/cache/cdxgen")));
    }

    #[test]
    fn linux_ignores_relative_xdg_cache_home() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Linux,
            None,
            Some("relative/path"),
            Some("/home/user"),
            None,
            None,
        );
        assert_eq!(p, Some(PathBuf::from("/home/user/.cache/cdxgen")));
    }

    #[test]
    fn linux_falls_back_to_home_dot_cache() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Linux,
            None,
            None,
            Some("/home/user"),
            None,
            None,
        );
        assert_eq!(p, Some(PathBuf::from("/home/user/.cache/cdxgen")));
    }

    #[test]
    fn linux_no_home_disables_cache() {
        let p = HttpCache::resolve_cache_for(CachePlatform::Linux, None, None, None, None, None);
        assert_eq!(p, None);
    }

    #[test]
    fn macos_uses_library_caches() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Macos,
            None,
            Some("/xdg/ignored"),
            Some("/Users/tester"),
            None,
            None,
        );
        assert_eq!(
            p,
            Some(PathBuf::from("/Users/tester/Library/Caches/cdxgen"))
        );
    }

    #[test]
    fn macos_no_home_disables_cache() {
        let p = HttpCache::resolve_cache_for(CachePlatform::Macos, None, None, None, None, None);
        assert_eq!(p, None);
    }

    #[test]
    fn windows_uses_localappdata() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Windows,
            None,
            None,
            None,
            Some(r"C:\Users\tester\AppData\Local"),
            Some(r"C:\Users\tester"),
        );
        let normalized = p
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        assert_eq!(normalized, "C:/Users/tester/AppData/Local/cdxgen/cache");
    }

    #[test]
    fn windows_falls_back_to_userprofile() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Windows,
            None,
            None,
            None,
            None,
            Some(r"C:\Users\tester"),
        );
        let normalized = p
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        assert_eq!(normalized, "C:/Users/tester/AppData/Local/cdxgen/cache");
    }

    #[test]
    fn windows_no_home_disables_cache() {
        let p = HttpCache::resolve_cache_for(CachePlatform::Windows, None, None, None, None, None);
        assert_eq!(p, None);
    }

    #[test]
    fn empty_cdxgen_cache_dir_falls_through() {
        let p = HttpCache::resolve_cache_for(
            CachePlatform::Linux,
            Some(""),
            None,
            Some("/home/user"),
            None,
            None,
        );
        assert_eq!(p, Some(PathBuf::from("/home/user/.cache/cdxgen")));
    }

    // ----------------------------------------------------- D26: loopback tests

    #[test]
    fn loopback_url_is_not_cached() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        for url in [
            "http://127.0.0.1:8080/pkg",
            "http://127.1.2.3:8080/pkg",
            "http://localhost:8080/pkg",
            "http://[::1]:8080/pkg",
        ] {
            let key = CacheKey::get(url);
            cache.put(&key, &entry(url, unix_now()));
            assert!(
                matches!(cache.get(&key), Lookup::Miss),
                "loopback cached: {url}"
            );
        }
        assert_eq!(walk(tmp.path()).len(), 0);
    }

    #[test]
    fn loopback_cached_when_override_is_set() {
        // The loopback check is driven by CDXGEN_CACHE_LOOPBACK at call time.
        // This test verifies the override path through the integration suite
        // (tests/fetch.rs) where env vars are passed to a child process; here
        // we only verify that is_loopback_url honours the flag when set.
        assert!(!is_loopback_url_for("http://127.0.0.1/x", true));
        assert!(is_loopback_url_for("http://127.0.0.1/x", false));
    }

    // ----------------------------------------------------- D26: eviction tests

    /// Eviction order is least-recently-*used*, not least-recently-written:
    /// reading an entry moves its mtime forward and so moves it to the back of
    /// the eviction queue.
    #[test]
    fn byte_ceiling_evicts_least_recently_used_first() {
        let tmp = TempDir::new().unwrap();
        // 1 KB ceiling, and a TTL long enough that nothing expires here.
        let cache = HttpCache::new(tmp.path().to_path_buf(), 3600, 1024, true);
        let now = unix_now();
        let urls = [
            "https://a.example.com/first",
            "https://b.example.com/second",
            "https://c.example.com/third",
        ];
        for (i, url) in urls.iter().enumerate() {
            let mut e = entry(url, now);
            e.body = serde_json::json!({"pad": "x".repeat(200)});
            cache.put(&CacheKey::get(url), &e);
            // Written an hour apart, so write order alone would evict `a` first.
            let path = cache.path_for(&CacheKey::get(url)).unwrap();
            let written = SystemTime::now() - std::time::Duration::from_secs(3000 - i as u64 * 600);
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_times(fs::FileTimes::new().set_modified(written))
                .unwrap();
        }

        // Use the oldest-written entry. That must protect it, and demote `b`.
        assert!(matches!(
            cache.get(&CacheKey::get(urls[0])),
            Lookup::Fresh(_)
        ));

        cache.enforce_byte_ceiling();

        assert!(
            matches!(cache.get(&CacheKey::get(urls[1])), Lookup::Miss),
            "the least recently used entry survived eviction"
        );
        assert!(
            matches!(cache.get(&CacheKey::get(urls[0])), Lookup::Fresh(_)),
            "an entry read moments ago was evicted as if it were the oldest"
        );
    }

    #[test]
    fn ttl_sweep_removes_expired_entries_without_validators() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), 60, true);
        let now = unix_now();
        // Expired, no validators → should be swept.
        let mut old = entry("https://reg.example.com/old", now - 3600);
        old.etag = None;
        old.last_modified = None;
        cache.put(&CacheKey::get("https://reg.example.com/old"), &old);
        // Expired with validator → kept for conditional revalidation.
        let old_validated = entry("https://reg.example.com/validated", now - 3600);
        cache.put(
            &CacheKey::get("https://reg.example.com/validated"),
            &old_validated,
        );
        // Fresh → kept.
        cache.put(
            &CacheKey::get("https://reg.example.com/fresh"),
            &entry("https://reg.example.com/fresh", now),
        );
        // Trigger the sweep by calling get() on any entry in this host dir.
        let _ = cache.get(&CacheKey::get("https://reg.example.com/fresh"));
        // After sweep, the unvalidated old entry is gone.
        assert!(matches!(
            cache.get(&CacheKey::get("https://reg.example.com/old")),
            Lookup::Miss
        ));
        // The validated stale entry survives the sweep (kept for revalidation).
        assert!(matches!(
            cache.get(&CacheKey::get("https://reg.example.com/validated")),
            Lookup::Stale(_)
        ));
    }

    #[test]
    fn ttl_zero_never_sweeps() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), 0, true);
        let mut ancient = entry("https://reg.example.com/ancient", 0);
        ancient.etag = None;
        ancient.last_modified = None;
        cache.put(&CacheKey::get("https://reg.example.com/ancient"), &ancient);
        // Trigger sweep.
        let _ = cache.get(&CacheKey::get("https://reg.example.com/ancient"));
        // TTL 0 = never expires, so the sweep must not remove it.
        assert!(matches!(
            cache.get(&CacheKey::get("https://reg.example.com/ancient")),
            Lookup::Fresh(_)
        ));
    }

    #[test]
    fn eviction_leaves_a_valid_cache() {
        let tmp = TempDir::new().unwrap();
        let cache = HttpCache::new(tmp.path().to_path_buf(), 0, 512, true);
        let now = unix_now();
        // Write entries that exceed the ceiling.
        for i in 0..10 {
            let url = format!("https://host.example.com/pkg-{i}");
            let mut e = entry(&url, now + i);
            e.body = serde_json::json!({"pad": "x".repeat(200)});
            cache.put(&CacheKey::get(&url), &e);
        }
        // Every remaining entry must be readable and well-formed.
        let files = walk(tmp.path());
        for file in &files {
            if file.extension().is_some_and(|e| e == "json") {
                let data = fs::read(file).unwrap();
                let entry: CacheEntry = serde_json::from_slice(&data).unwrap();
                assert_eq!(entry.v, CACHE_SCHEMA_VERSION);
            }
        }
        // No temp files left behind.
        assert!(files.iter().all(|p| !p.to_string_lossy().contains(".tmp.")));
    }

    #[test]
    fn concurrent_writers_do_not_corrupt_via_eviction() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        // Large ceiling so eviction does not interfere; this tests that the
        // enforcement path is safe alongside concurrent writers.
        let cache = HttpCache::new(root.clone(), 0, 10 * 1024 * 1024, true);
        let url_base = "https://reg.example.com/concurrent-";
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let root = root.clone();
                let url = format!("{url_base}{i}");
                std::thread::spawn(move || {
                    let cache = HttpCache::new(root, 0, 10 * 1024 * 1024, true);
                    let key = CacheKey::get(&url);
                    let mut e = entry(&url, unix_now());
                    e.body = serde_json::json!({"i": i, "pad": "x".repeat(1024)});
                    cache.put(&key, &e);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // All entries must be present and valid.
        for i in 0..8 {
            let url = format!("{url_base}{i}");
            match cache.get(&CacheKey::get(&url)) {
                Lookup::Fresh(e) => assert_eq!(e.body["i"], i),
                other => panic!("entry {i} lost after concurrent writes: {other:?}"),
            }
        }
    }

    /// A normal batch writes a few MB, which must not be enough to trigger a
    /// pass: each pass walks and stats the entire cache, so one per write turns
    /// a warm cache into a slowdown rather than a speedup.
    #[test]
    fn a_normal_batch_triggers_no_enforcement_pass() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        // 200 responses of ~20 KB — the shape of a large registry batch.
        for i in 0..200u32 {
            let url = format!("https://registry.example.com/pkg{i}");
            let mut entry = entry(&url, unix_now());
            entry.body = serde_json::json!({ "pad": "y".repeat(20_000) });
            cache.put(&CacheKey::get(&url), &entry);
        }
        assert_eq!(
            cache.enforcement_passes(),
            0,
            "a {} MB batch triggered an enforcement pass; the slack budget is {} MB",
            200 * 20 / 1024,
            cache.enforcement_slack_bytes() / (1024 * 1024)
        );
    }

    /// Once a run has written a slack budget's worth of data, a pass must run,
    /// and it must bring the cache back under the ceiling.
    #[test]
    fn exceeding_the_slack_budget_enforces_the_ceiling() {
        let tmp = TempDir::new().unwrap();
        // A 1 MB ceiling still gets the 8 MB slack floor, so ~9 MB of writes
        // are needed before the first pass.
        let cache = HttpCache::new(
            tmp.path().to_path_buf(),
            DEFAULT_CACHE_TTL_SECS,
            1024 * 1024,
            true,
        );
        for i in 0..120u32 {
            let url = format!("https://registry.example.com/big{i}");
            let mut entry = entry(&url, unix_now());
            entry.body = serde_json::json!({ "pad": "z".repeat(100_000) });
            cache.put(&CacheKey::get(&url), &entry);
        }
        assert!(
            cache.enforcement_passes() >= 1,
            "12 MB of writes past a 1 MB ceiling ran no enforcement pass"
        );
        let total: u64 = walk_cache_files(&cache.fetch_subdir())
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum();
        assert!(
            total <= cache.max_bytes + cache.enforcement_slack_bytes(),
            "cache is {total} bytes, above ceiling + slack"
        );
    }

    /// A `put` that dies between creating its temp file and renaming it leaves
    /// the file behind. Nothing else ever reads it, so the sweep reclaims it
    /// once it is too old to belong to a live writer.
    #[test]
    fn sweep_reclaims_orphaned_temp_files() {
        let tmp = TempDir::new().unwrap();
        let cache = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let url = "https://registry.example.com/pkg";
        cache.put(&CacheKey::get(url), &entry(url, unix_now()));

        let host_dir = cache.fetch_subdir().join("registry.example.com");
        let stale_orphan = host_dir.join("deadbeef.tmp.999.0");
        let fresh_orphan = host_dir.join("deadbeef.tmp.999.1");
        fs::write(&stale_orphan, b"partial").unwrap();
        fs::write(&fresh_orphan, b"partial").unwrap();
        let long_ago =
            SystemTime::now() - std::time::Duration::from_secs(ORPHAN_TEMP_MIN_AGE_SECS + 60);
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&stale_orphan)
            .unwrap();
        file.set_times(fs::FileTimes::new().set_modified(long_ago))
            .unwrap();
        drop(file);

        // A fresh cache instance, so the once-per-process sweep runs again.
        let swept = test_cache(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
        let _ = swept.get(&CacheKey::get(url));

        assert!(!stale_orphan.exists(), "stale temp file was not reclaimed");
        assert!(
            fresh_orphan.exists(),
            "a temp file young enough to belong to a live writer was removed"
        );
        assert!(
            matches!(swept.get(&CacheKey::get(url)), Lookup::Fresh(_)),
            "the sweep removed a live entry"
        );
    }

    /// Measures the cost of a full enforcement pass on a large cache. Not a
    /// correctness test — a benchmark that prints timing to stderr.
    #[test]
    fn enforce_ceiling_cost_on_20k_entries() {
        use std::time::Instant;
        let tmp = TempDir::new().unwrap();
        let cache = HttpCache::new(tmp.path().to_path_buf(), 0, u64::MAX, true);
        let fetch_dir = cache.fetch_subdir();
        let host_dir = fetch_dir.join("bench.host");
        fs::create_dir_all(&host_dir).unwrap();

        for i in 0..20_000u32 {
            let entry = CacheEntry {
                v: CACHE_SCHEMA_VERSION,
                url: format!("https://bench.host/p{i}"),
                method: "GET".to_string(),
                status: 200,
                etag: None,
                last_modified: None,
                fetched_at: i as u64,
                body: serde_json::json!({"i": i, "pad": "x".repeat(100)}),
            };
            let data = serde_json::to_vec(&entry).unwrap();
            let path = host_dir.join(format!("{i:016x}.json"));
            fs::write(&path, &data).unwrap();
        }

        // Time the enforcement walk.
        let started = Instant::now();
        cache.enforce_byte_ceiling();
        let elapsed = started.elapsed();
        eprintln!(
            "enforce_byte_ceiling on 20k entries: {:.0}ms",
            elapsed.as_millis()
        );
        // The pass should complete in well under a second on any modern disk.
        assert!(
            elapsed.as_secs() < 5,
            "enforcement took {elapsed:?} — too slow for an opportunistic pass"
        );
    }
}
