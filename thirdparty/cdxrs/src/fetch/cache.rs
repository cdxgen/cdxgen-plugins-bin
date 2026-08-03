//! On-disk HTTP response cache.
//!
//! Reuses cdxgen's existing cache directory convention (`CDXGEN_CACHE_DIR` or
//! `~/.cdxgen/cache`).
//!
//! Keys are derived from the full URL, the method, the `Accept` header and the
//! auth-realm *identity* — never the credential. Getting that set wrong is how
//! a private registry's response ends up served to a public lookup, so
//! [`CacheKey`] exists specifically so that a read and a write cannot disagree
//! about what the key was: both take the same struct, and there is no way to
//! call one of them with a subset of the fields.
//!
//! File layout:
//! ```text
//! <cache_dir>/cdxrs-fetch/<host>/<hash>.json
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::client::redact_url;

/// Cache schema version. Bump when the on-disk format changes.
pub const CACHE_SCHEMA_VERSION: u32 = 2;

/// Default TTL for cached entries (24 hours).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Everything that identifies a cached response.
///
/// Constructed once per request and passed to both [`HttpCache::get`] and
/// [`HttpCache::put`], so the two cannot hash different things. The previous
/// version took the fields as loose arguments and `put` passed `None` for
/// `accept` and `auth_realm`; every authenticated lookup was therefore a
/// permanent miss, and its body was written to the key an *unauthenticated*
/// reader would look under.
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
    enabled: bool,
}

impl HttpCache {
    /// Create a cache rooted at the given directory.
    pub fn new(root: PathBuf, ttl_secs: u64, enabled: bool) -> Self {
        Self {
            root,
            ttl_secs,
            enabled,
        }
    }

    /// Resolve the cache directory from cdxgen's convention.
    pub fn resolve_cache_dir() -> Option<PathBuf> {
        if let Some(dir) = env::var("CDXGEN_CACHE_DIR").ok().filter(|s| !s.is_empty()) {
            return Some(PathBuf::from(dir));
        }
        for var in ["HOME", "USERPROFILE"] {
            if let Some(home) = env::var(var).ok().filter(|s| !s.is_empty()) {
                return Some(PathBuf::from(home).join(".cdxgen").join("cache"));
            }
        }
        None
    }

    fn path_for(&self, key: &CacheKey) -> Option<PathBuf> {
        let host = extract_host(&key.url)?;
        Some(
            self.root
                .join("cdxrs-fetch")
                .join(host)
                .join(format!("{}.json", key.hash())),
        )
    }

    /// Look up an entry, distinguishing fresh from stale-but-revalidatable.
    pub fn get(&self, key: &CacheKey) -> Lookup {
        if !self.enabled {
            return Lookup::Miss;
        }
        let Some(path) = self.path_for(key) else {
            return Lookup::Miss;
        };
        let Ok(data) = fs::read(&path) else {
            return Lookup::Miss;
        };
        let Ok(entry) = serde_json::from_slice::<CacheEntry>(&data) else {
            // A truncated or garbled file is removed rather than left to be a
            // permanent silent miss.
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
            Lookup::Fresh(entry)
        } else if entry.etag.is_some() || entry.last_modified.is_some() {
            Lookup::Stale(entry)
        } else {
            Lookup::Miss
        }
    }

    /// A TTL of zero means "never expires", as `--cache-ttl 0` documents.
    /// Reading it as "expired immediately" made the flag do the opposite of
    /// what it says.
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
    /// another complete file. The previous version derived the temp name from
    /// the pid alone, so two tasks in one process writing the same key
    /// interleaved their bytes into a shared temp path.
    pub fn put(&self, key: &CacheKey, entry: &CacheEntry) {
        if !self.enabled {
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
        if file.write_all(&data).is_ok() && file.sync_all().is_ok() {
            drop(file);
            let _ = fs::rename(&tmp_path, &final_path);
        } else {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
        }
    }

    /// Whether the cache is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(|h| h.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), 60, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), 60, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), 0, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, false);
        let url = "https://crates.io/api/v1/crates/serde";
        let key = CacheKey::get(url);
        cache.put(&key, &entry(url, unix_now()));
        assert!(matches!(cache.get(&key), Lookup::Miss));
        assert_eq!(walk(tmp.path()).len(), 0);
    }

    #[test]
    fn schema_version_mismatch_is_a_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
        let cache = HttpCache::new(tmp.path().to_path_buf(), DEFAULT_CACHE_TTL_SECS, true);
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
                    let cache = HttpCache::new(root, DEFAULT_CACHE_TTL_SECS, true);
                    let mut e = entry(&url, unix_now());
                    e.body = serde_json::json!({ "writer": i, "pad": "x".repeat(64 * 1024) });
                    cache.put(&key, &e);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let cache = HttpCache::new(root, DEFAULT_CACHE_TTL_SECS, true);
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
}
