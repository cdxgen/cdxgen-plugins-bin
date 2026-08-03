//! HTTP client for the fetch subcommand.
//!
//! Wraps `reqwest` with `rustls` (never OpenSSL — musl/cross-build safe),
//! configurable concurrency caps, per-host rate limiting, and retries with
//! exponential backoff + jitter.
//!
//! Auth: `GITHUB_TOKEN` is sent as a Bearer token to github.com hosts, and a
//! caller may pass an explicit per-request token. `.npmrc` `_authToken`,
//! `NUGET_AUTH` and netrc are deliberately **not** read here — see
//! `docs/fetch-auth.md`. Claiming support that does not exist is worse than
//! not having it, so this module does not pretend.
//!
//! Credentials never reach a log line or the cache: every URL that leaves this
//! module for display or storage goes through [`redact_url`], which strips
//! userinfo and the query string.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, IF_NONE_MATCH};
use reqwest::{Client, NoProxy, Response, StatusCode};
use tokio::sync::{Mutex, Semaphore};

use super::rate::{Credentials, RateLimiter};

/// Default global concurrency cap.
///
/// Registries, not cdxgen, set the ceiling here. crates.io asks for ~1 req/s
/// from anonymous clients and GitHub allows 60 req/h unauthenticated, so the
/// useful parallelism comes from spreading work *across* hosts rather than
/// hammering one. 16 in flight globally saturates a large npm run without
/// putting any single host above the per-host cap below.
pub const DEFAULT_CONCURRENCY: usize = 16;

/// Per-host concurrency when the caller does not override it.
///
/// Zero means "use the per-host policy in `rate::policy_for`", which gives
/// crates.io and GitHub the conservative budget they publish and leaves
/// CDN-fronted registries at the global cap. An explicit `--per-host-concurrency`
/// overrides the policy for every host.
pub const DEFAULT_PER_HOST_CONCURRENCY: usize = 0;

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default read (inter-chunk) timeout.
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

/// Default total timeout for a single attempt (connect + read).
pub const DEFAULT_TOTAL_TIMEOUT_SECS: u64 = 60;

/// Default ceiling on the whole retry sequence for one request.
pub const DEFAULT_REQUEST_DEADLINE_SECS: u64 = 120;

/// Maximum decompressed HTTP response body (50 MB).
///
/// Enforced while streaming, not after buffering, so a gzip bomb is abandoned
/// as soon as it crosses the limit rather than after it has been fully
/// inflated into memory.
pub const MAX_BODY_BYTES: usize = 50 * 1024 * 1024;

/// Maximum redirect hops.
pub const MAX_REDIRECTS: usize = 5;

/// Maximum retry attempts for transient failures (5xx, 429, connection errors).
pub const MAX_RETRIES: u32 = 3;

/// Configuration for the fetch HTTP client.
#[derive(Clone, Debug)]
pub struct FetchClientConfig {
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub total_timeout: Duration,
    /// Ceiling on the entire retry sequence for one request. `total_timeout`
    /// bounds a single attempt; without this a retrying request is unbounded.
    pub request_deadline: Duration,
    /// Maximum decompressed body accepted from a single response.
    pub max_body_bytes: usize,
    pub user_agent: String,
    pub github_token: Option<String>,
}

impl Default for FetchClientConfig {
    fn default() -> Self {
        Self {
            global_concurrency: DEFAULT_CONCURRENCY,
            per_host_concurrency: DEFAULT_PER_HOST_CONCURRENCY,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
            total_timeout: Duration::from_secs(DEFAULT_TOTAL_TIMEOUT_SECS),
            request_deadline: Duration::from_secs(DEFAULT_REQUEST_DEADLINE_SECS),
            max_body_bytes: MAX_BODY_BYTES,
            user_agent: format!("cdxgen-cdxrs/{}", crate::CDXRS_VERSION),
            github_token: env::var("GITHUB_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }
}

/// Why a request produced no usable response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// The URL could not be parsed, or had no host.
    BadUrl,
    /// A non-retryable HTTP status (4xx other than 429, or an exhausted 5xx).
    Status(u16),
    /// The body exceeded [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The body was not valid JSON (or not valid UTF-8 for a text response).
    Malformed,
    /// Connection error, timeout, or the retry deadline elapsed.
    Transport(String),
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl => write!(f, "unparseable url"),
            Self::Status(code) => write!(f, "http status {code}"),
            Self::BodyTooLarge => write!(f, "response body exceeds the configured maximum"),
            Self::Malformed => write!(f, "malformed response body"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

/// A successful response: status, parsed body, and the validators needed to
/// revalidate it later.
#[derive(Debug, Clone)]
pub struct FetchSuccess {
    pub status: u16,
    pub body: serde_json::Value,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// True when the origin answered 304 and the caller should keep the body
    /// it already had.
    pub not_modified: bool,
}

/// Conditional-request validators from a cached entry.
#[derive(Debug, Clone, Default)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Shared state for rate limiting and concurrency control across all hosts.
pub struct FetchClient {
    client: Client,
    config: FetchClientConfig,
    global_sem: Arc<Semaphore>,
    /// Per-host semaphores, lazily created.
    host_sems: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// Per-host rate limiters, lazily created.
    host_rate_limiters: Arc<Mutex<HashMap<String, Arc<RateLimiter>>>>,
    /// Requests actually in flight, and the high-water mark. Counted after the
    /// permits are held, so it reports real HTTP concurrency rather than the
    /// number of tasks queued behind the semaphores.
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak_in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl FetchClient {
    pub fn new(config: FetchClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder = Client::builder()
            .use_rustls_tls()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .timeout(config.total_timeout)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .gzip(true)
            .pool_idle_timeout(Duration::from_secs(90));

        // Proxy support. `NoProxy::from_env` implements the NO_PROXY matching
        // rules (suffix match, leading dot, bare `*`, CIDR, host:port) so they
        // do not have to be reimplemented here — the previous hand-rolled
        // version ignored NO_PROXY entirely and proxied unconditionally.
        // The two schemes are installed separately: HTTPS_PROXY being set must
        // not suppress HTTP_PROXY.
        let no_proxy = NoProxy::from_env();
        if let Some(url) = proxy_env("HTTPS_PROXY", "https_proxy")
            && let Ok(proxy) = reqwest::Proxy::https(&url)
        {
            builder = builder.proxy(proxy.no_proxy(no_proxy.clone()));
        }
        if let Some(url) = proxy_env("HTTP_PROXY", "http_proxy")
            && let Ok(proxy) = reqwest::Proxy::http(&url)
        {
            builder = builder.proxy(proxy.no_proxy(no_proxy.clone()));
        }
        if let Some(url) = proxy_env("ALL_PROXY", "all_proxy")
            && let Ok(proxy) = reqwest::Proxy::all(&url)
        {
            builder = builder.proxy(proxy.no_proxy(no_proxy));
        }

        let client = builder.build()?;

        // A cap of zero would deadlock every request rather than disabling the
        // limit, so clamp it to something usable.
        let global_sem = Arc::new(Semaphore::new(config.global_concurrency.max(1)));

        Ok(Self {
            client,
            config,
            global_sem,
            host_sems: Arc::new(Mutex::new(HashMap::new())),
            host_rate_limiters: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            peak_in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Execute a conditional GET with full retry, rate-limit, and concurrency
    /// handling.
    ///
    /// `validators` come from a cached entry; when the origin answers 304 the
    /// returned [`FetchSuccess`] has `not_modified` set and a null body.
    pub async fn get_json(
        &self,
        url: &str,
        accept: Option<&str>,
        auth_token: Option<&str>,
        validators: &Validators,
    ) -> Result<FetchSuccess, FetchFailure> {
        let host = extract_host(url).ok_or(FetchFailure::BadUrl)?;

        // Concurrency permits are acquired for the whole retry sequence,
        // including its back-off sleeps: a host that is asking us to slow down
        // should not have four more slots opened against it in the meantime.
        let _global_permit = self
            .global_sem
            .acquire()
            .await
            .map_err(|e| FetchFailure::Transport(e.to_string()))?;
        let host_sem = self.get_host_semaphore(&host).await;
        let _host_permit = host_sem
            .acquire()
            .await
            .map_err(|e| FetchFailure::Transport(e.to_string()))?;

        let limiter = self.get_host_rate_limiter(&host).await;

        let _gauge = InFlightGuard::new(&self.in_flight, &self.peak_in_flight);

        let mut headers = HeaderMap::new();
        if let Some(acc) = accept
            && let Ok(v) = HeaderValue::from_str(acc)
        {
            headers.insert(ACCEPT, v);
        }
        if let Some(etag) = &validators.etag
            && let Ok(v) = HeaderValue::from_str(etag)
        {
            headers.insert(IF_NONE_MATCH, v);
        }
        if let Some(lm) = &validators.last_modified
            && let Ok(v) = HeaderValue::from_str(lm)
        {
            headers.insert(reqwest::header::IF_MODIFIED_SINCE, v);
        }
        // Auth priority: explicit token, then GITHUB_TOKEN for github hosts.
        let effective_token = auth_token.or_else(|| {
            if host == "api.github.com" || host == "github.com" {
                self.config.github_token.as_deref()
            } else {
                None
            }
        });
        if let Some(token) = effective_token
            && let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}"))
        {
            headers.insert(AUTHORIZATION, v);
        }

        let deadline = Instant::now() + self.config.request_deadline;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            // Every attempt, including retries, waits its turn at the per-host
            // token bucket. The previous version called this once before the
            // loop, so a retry ignored both the bucket and any Retry-After the
            // server had just sent.
            limiter.wait().await;

            let result = self.client.get(url).headers(headers.clone()).send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    let retryable =
                        status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS;

                    if retryable && attempt <= MAX_RETRIES {
                        // A server-supplied delay wins over our own back-off.
                        // It is recorded against the host bucket *and* waited
                        // for here; recording alone left the retry immediate.
                        let delay = parse_retry_after(&resp)
                            .unwrap_or_else(|| exponential_backoff(attempt));
                        limiter.external_delay(delay).await;
                        if !within_deadline(deadline, delay) {
                            return Err(FetchFailure::Transport(format!(
                                "retry deadline exceeded after {attempt} attempt(s) (status {})",
                                status.as_u16()
                            )));
                        }
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    if status == StatusCode::NOT_MODIFIED {
                        return Ok(FetchSuccess {
                            status: status.as_u16(),
                            body: serde_json::Value::Null,
                            etag: header_string(&resp, reqwest::header::ETAG),
                            last_modified: header_string(&resp, reqwest::header::LAST_MODIFIED),
                            not_modified: true,
                        });
                    }

                    if !status.is_success() {
                        return Err(FetchFailure::Status(status.as_u16()));
                    }

                    let etag = header_string(&resp, reqwest::header::ETAG);
                    let last_modified = header_string(&resp, reqwest::header::LAST_MODIFIED);
                    let content_type =
                        header_string(&resp, reqwest::header::CONTENT_TYPE).unwrap_or_default();
                    let bytes = read_body_capped(resp, url, self.config.max_body_bytes).await?;

                    let body =
                        if content_type.contains("json") || content_type.contains("javascript") {
                            serde_json::from_slice::<serde_json::Value>(&bytes)
                                .map_err(|_| FetchFailure::Malformed)?
                        } else {
                            // Non-JSON (e.g. an HTML licence page) is handed back
                            // as a string so the caller can scrape it.
                            serde_json::Value::String(
                                String::from_utf8(bytes).map_err(|_| FetchFailure::Malformed)?,
                            )
                        };

                    return Ok(FetchSuccess {
                        status: status.as_u16(),
                        body,
                        etag,
                        last_modified,
                        not_modified: false,
                    });
                }
                Err(e) => {
                    // Note the parentheses. Without them this reads as
                    // `(attempt <= MAX_RETRIES && is_connect) || is_timeout`,
                    // which retried a timing-out host forever.
                    let transient = e.is_connect() || e.is_timeout() || e.is_request();
                    if transient && attempt <= MAX_RETRIES {
                        let backoff = exponential_backoff(attempt);
                        if !within_deadline(deadline, backoff) {
                            return Err(FetchFailure::Transport(
                                "retry deadline exceeded".to_string(),
                            ));
                        }
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    // reqwest's Display includes the URL, which may carry
                    // credentials, so the message is rebuilt from the parts we
                    // know are safe.
                    return Err(FetchFailure::Transport(describe_transport_error(&e)));
                }
            }
        }
    }

    /// Whether a credential will be sent to this host.
    ///
    /// Only token presence is considered, never its value. A host we hold no
    /// token for keeps the anonymous budget even if some other host has one.
    fn credentials_for(&self, host: &str) -> Credentials {
        let github =
            host == "api.github.com" || host == "github.com" || host.ends_with(".github.com");
        if github && self.config.github_token.is_some() {
            Credentials::Authenticated
        } else {
            Credentials::Anonymous
        }
    }

    /// Per-host permits: an explicit configured cap when there is one,
    /// otherwise the host's own policy for the credentials we will send.
    async fn get_host_semaphore(&self, host: &str) -> Arc<Semaphore> {
        let configured = self.config.per_host_concurrency;
        let limit = if configured > 0 {
            configured
        } else {
            super::rate::policy_for(host, self.credentials_for(host)).max_concurrency
        };
        let mut map = self.host_sems.lock().await;
        map.entry(host.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(limit.max(1))))
            .clone()
    }

    /// High-water mark of concurrent in-flight requests.
    pub fn peak_in_flight(&self) -> usize {
        self.peak_in_flight
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn get_host_rate_limiter(&self, host: &str) -> Arc<RateLimiter> {
        let mut map = self.host_rate_limiters.lock().await;
        map.entry(host.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::new(host, self.credentials_for(host))))
            .clone()
    }
}

/// Tracks in-flight requests and their high-water mark for the lifetime of one
/// request, so the reported peak concurrency is what actually happened on the
/// wire.
struct InFlightGuard {
    current: Arc<std::sync::atomic::AtomicUsize>,
}

impl InFlightGuard {
    fn new(
        current: &Arc<std::sync::atomic::AtomicUsize>,
        peak: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let now = current.fetch_add(1, Ordering::Relaxed) + 1;
        peak.fetch_max(now, Ordering::Relaxed);
        Self {
            current: Arc::clone(current),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.current
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Read a response body, abandoning it as soon as it crosses the size limit.
///
/// `Response::bytes()` buffers the *decompressed* body in full before any
/// length check can run, which makes a 1 MB gzip bomb a multi-gigabyte
/// allocation. Streaming and checking per chunk is the actual guard.
async fn read_body_capped(
    mut resp: Response,
    url: &str,
    max_body_bytes: usize,
) -> Result<Vec<u8>, FetchFailure> {
    if let Some(len) = resp.content_length()
        && len > max_body_bytes as u64
    {
        crate::log::warn(&format!(
            "declared body length {len} exceeds {max_body_bytes} bytes for {}, skipping",
            redact_url(url)
        ));
        return Err(FetchFailure::BodyTooLarge);
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > max_body_bytes {
                    crate::log::warn(&format!(
                        "body for {} exceeds {max_body_bytes} bytes, skipping",
                        redact_url(url)
                    ));
                    return Err(FetchFailure::BodyTooLarge);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(buf),
            Err(e) => return Err(FetchFailure::Transport(describe_transport_error(&e))),
        }
    }
}

/// Strip anything credential-shaped from a URL before it is logged or stored.
///
/// Userinfo (`https://user:token@host/...`) and the query string (where
/// `?access_token=` and friends live) are both removed. A URL that will not
/// parse is reduced to its scheme and host if possible, and otherwise dropped
/// entirely — a redaction that fails open is not a redaction.
pub fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => "<unparseable url>".to_string(),
    }
}

/// Build a transport error message that cannot contain a credential.
fn describe_transport_error(e: &reqwest::Error) -> String {
    let mut parts = Vec::new();
    if e.is_connect() {
        parts.push("connect");
    }
    if e.is_timeout() {
        parts.push("timeout");
    }
    if e.is_body() {
        parts.push("body");
    }
    if e.is_decode() {
        parts.push("decode");
    }
    if e.is_redirect() {
        parts.push("redirect");
    }
    if parts.is_empty() {
        parts.push("request");
    }
    format!("{} error", parts.join("/"))
}

fn proxy_env(upper: &str, lower: &str) -> Option<String> {
    env::var(upper)
        .or_else(|_| env::var(lower))
        .ok()
        .filter(|s| !s.is_empty())
}

fn header_string(resp: &Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn within_deadline(deadline: Instant, delay: Duration) -> bool {
    Instant::now() + delay < deadline
}

pub fn extract_host(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    parsed.host_str().map(|h| h.to_string())
}

/// Parse a server-supplied back-off.
///
/// `Retry-After` may be seconds or an HTTP-date; `X-RateLimit-Reset` is a Unix
/// timestamp. A value that would park the request for longer than the retry
/// deadline is clamped by the deadline check at the call site.
fn parse_retry_after(resp: &Response) -> Option<Duration> {
    if let Some(val) = resp.headers().get(reqwest::header::RETRY_AFTER)
        && let Ok(s) = val.to_str()
    {
        let s = s.trim();
        if let Ok(secs) = s.parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }
        // HTTP-date form.
        if let Some(secs) = httpdate_secs_from_now(s) {
            return Some(Duration::from_secs(secs));
        }
    }
    // GitHub sends the reset timestamp rather than Retry-After.
    for name in ["x-ratelimit-reset", "ratelimit-reset"] {
        if let Some(val) = resp.headers().get(name)
            && let Ok(s) = val.to_str()
            && let Ok(ts) = s.trim().parse::<u64>()
        {
            let now = unix_now();
            // A small value is a delta, a large one is an absolute timestamp.
            if ts > now {
                return Some(Duration::from_secs(ts - now));
            }
            if ts < 3600 {
                return Some(Duration::from_secs(ts));
            }
        }
    }
    None
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Seconds from now until an HTTP-date, or `None` if it is unparseable or past.
fn httpdate_secs_from_now(value: &str) -> Option<u64> {
    let target = httpdate::parse_http_date(value).ok()?;
    let target = target.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let now = unix_now();
    if target > now {
        Some(target - now)
    } else {
        None
    }
}

/// Exponential back-off with full jitter, capped.
///
/// The jitter is drawn from the clock rather than a counter: a counter produces
/// a deterministic sweep across concurrent tasks, which does not decorrelate a
/// thundering herd — the whole point of jittering. The cap is applied after the
/// jitter is added, so the returned delay never exceeds it.
fn exponential_backoff(attempt: u32) -> Duration {
    const CAP_MS: u64 = 30_000;
    let base_ms = 100u64.saturating_mul(1u64 << attempt.min(8));
    let jitter = jitter_ms(base_ms);
    Duration::from_millis((base_ms + jitter).min(CAP_MS))
}

/// Full jitter in `0..=base_ms`, derived from the nanosecond clock mixed with a
/// per-call counter so that two tasks entering in the same nanosecond differ.
fn jitter_ms(base_ms: u64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // splitmix64-style avalanche so neighbouring inputs do not give
    // neighbouring outputs.
    let mut x = nanos ^ (n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    x % base_ms.max(1)
}

#[cfg(test)]
mod client_tests {
    use super::*;

    #[test]
    fn redacts_userinfo_and_query() {
        assert_eq!(
            redact_url("https://user:s3cr3t@registry.example.com/pkg?access_token=abc"),
            "https://registry.example.com/pkg"
        );
    }

    #[test]
    fn redaction_fails_closed_on_unparseable_url() {
        assert_eq!(redact_url("not a url"), "<unparseable url>");
    }

    #[test]
    fn backoff_is_capped_including_jitter() {
        for attempt in 1..12 {
            assert!(exponential_backoff(attempt) <= Duration::from_millis(30_000));
        }
    }

    #[test]
    fn backoff_jitter_is_not_a_deterministic_sweep() {
        // A counter-based "jitter" yields strictly increasing values; this
        // asserts the distribution is at least not monotonic.
        let samples: Vec<u64> = (0..32).map(|_| jitter_ms(1000)).collect();
        let monotonic = samples.windows(2).all(|w| w[0] <= w[1]);
        assert!(!monotonic, "jitter is a deterministic sweep: {samples:?}");
    }

    #[tokio::test]
    async fn github_token_raises_only_github_concurrency() {
        let with_token = FetchClient::new(FetchClientConfig {
            github_token: Some("token".to_string()),
            ..Default::default()
        })
        .expect("client builds");
        let without = FetchClient::new(FetchClientConfig {
            github_token: None,
            ..Default::default()
        })
        .expect("client builds");

        assert_eq!(
            with_token.credentials_for("api.github.com"),
            Credentials::Authenticated
        );
        assert_eq!(
            without.credentials_for("api.github.com"),
            Credentials::Anonymous
        );
        // A token for GitHub must not raise anyone else's budget.
        assert_eq!(
            with_token.credentials_for("crates.io"),
            Credentials::Anonymous
        );

        // And the permit count follows: 8 with a token, 4 without.
        let authed = with_token.get_host_semaphore("api.github.com").await;
        let anon = without.get_host_semaphore("api.github.com").await;
        assert_eq!(authed.available_permits(), 8);
        assert_eq!(anon.available_permits(), 4);
        // Non-github hosts are unaffected either way.
        assert_eq!(
            with_token
                .get_host_semaphore("registry.npmjs.org")
                .await
                .available_permits(),
            16
        );
    }

    #[tokio::test]
    async fn an_explicit_per_host_cap_overrides_the_policy() {
        let client = FetchClient::new(FetchClientConfig {
            per_host_concurrency: 2,
            github_token: Some("token".to_string()),
            ..Default::default()
        })
        .expect("client builds");
        assert_eq!(
            client
                .get_host_semaphore("api.github.com")
                .await
                .available_permits(),
            2
        );
    }

    #[test]
    fn zero_concurrency_is_clamped_not_deadlocked() {
        let config = FetchClientConfig {
            global_concurrency: 0,
            per_host_concurrency: 0,
            ..Default::default()
        };
        let client = FetchClient::new(config).expect("client builds");
        assert_eq!(client.global_sem.available_permits(), 1);
    }
}
