//! HTTP client for the fetch subcommand.
//!
//! Wraps `reqwest` with `rustls` (never OpenSSL — musl/cross-build safe),
//! configurable concurrency caps, per-host rate limiting, and retries with
//! exponential backoff + jitter.
//!
//! Auth: no credential is read from the environment. The batch envelope
//! carries URLs that the scanned project can choose (a lockfile's `resolved`
//! URL, an `.npmrc` scope registry), so a token chosen by host name would let
//! that project pick which document is read with the operator's authority.
//! Requests therefore go out anonymously unless the caller passes a token for
//! that one request to [`FetchClient::get_json`] (the batch protocol's
//! `githubToken` field), and even then the token is sent only when
//! [`token_allowed_for`] accepts the URL: https, on the default port, to
//! github.com or api.github.com, with no userinfo. `GITHUB_TOKEN`, `.npmrc`
//! `_authToken`, `NUGET_AUTH` and netrc are all ignored.
//!
//! Credentials never reach a log line or the cache: every URL that leaves this
//! module for display or storage goes through [`redact_url`], which strips
//! userinfo and the query string.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, HeaderMap, HeaderValue, IF_NONE_MATCH,
};
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

/// Default ceiling on the *total* decoded bytes one batch may buffer (512 MB).
///
/// [`MAX_BODY_BYTES`] bounds a single body; without a batch-wide ceiling, a
/// batch of a few thousand requests — every URL of which the scanned
/// lockfile chose — can hold gigabytes of decoded bodies in memory and in
/// the output document. Charged per accepted chunk while decoding, so a
/// run cannot overshoot by more than the chunks already in flight.
/// `--max-total-bytes 0` disables the ceiling.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum tolerated ratio of decoded bytes to bytes received on the wire.
///
/// Registry metadata does not compress anywhere near this well, so a body
/// that expands more than this once it passes
/// [`DECODE_RATIO_FLOOR_BYTES`] decoded bytes is an attack, not a document.
/// Only enforced when the wire size is known — which is why this client
/// decodes gzip itself rather than letting reqwest do it invisibly: with
/// automatic decompression the `Content-Length` header is gone by the time
/// the body is seen, and there is no way left to relate the two sizes.
pub const MAX_DECODE_RATIO: u64 = 100;

/// A body is only held against [`MAX_DECODE_RATIO`] above this many decoded
/// bytes. Below it the ratio is meaningless — a gzip member costs ~18 bytes
/// of header and trailer, so tiny bodies routinely "expand" enormously.
pub const DECODE_RATIO_FLOOR_BYTES: usize = 1024 * 1024;

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
    /// Ceiling on the decoded bytes the whole batch may buffer (0 = no
    /// ceiling). See [`DEFAULT_MAX_TOTAL_BYTES`].
    pub max_total_bytes: u64,
    pub user_agent: String,
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
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            user_agent: format!("cdxgen-cdxrs/{}", crate::CDXRS_VERSION),
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
    /// The decoded bytes of this body exceeded [`MAX_DECODE_RATIO`] times the
    /// bytes received for it.
    BodyExpandsTooMuch,
    /// The batch's shared decoded-byte budget ([`DEFAULT_MAX_TOTAL_BYTES`])
    /// is spent; remaining requests were not decoded.
    BudgetExhausted,
    /// The body was not valid JSON (or not valid UTF-8 for a text response).
    Malformed,
    /// Connection error, timeout, or the retry deadline elapsed.
    Transport(String),
    /// A 403 or 429 that says the host's request quota is used up: no
    /// requests remaining, or a `Retry-After`. `retry_after_secs` is how long
    /// the host asked the caller to wait, when it said.
    QuotaExhausted {
        status: u16,
        retry_after_secs: Option<u64>,
    },
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl => write!(f, "unparseable url"),
            Self::Status(code) => write!(f, "http status {code}"),
            Self::BodyTooLarge => write!(f, "response body exceeds the configured maximum"),
            Self::BodyExpandsTooMuch => write!(
                f,
                "decoded body exceeds {}x the bytes received",
                MAX_DECODE_RATIO
            ),
            Self::BudgetExhausted => write!(
                f,
                "batch decoded-body budget exhausted (raise --max-total-bytes)"
            ),
            Self::Malformed => write!(f, "malformed response body"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::QuotaExhausted { status, .. } => {
                write!(f, "http status {status} (request quota used up)")
            }
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

/// The batch's shared ceiling on decoded bytes, charged as bodies decode.
///
/// Every accepted chunk is charged before it is buffered, by the decoding
/// reader itself, so the sum of what the batch holds — in memory and in the
/// output document — cannot pass the ceiling by more than the chunks that
/// were in flight when it tipped. Requests that would tip it fail with
/// [`FetchFailure::BudgetExhausted`]; a ceiling of zero means unlimited.
#[derive(Debug)]
pub struct DecodedBudget {
    ceiling: u64,
    used: std::sync::atomic::AtomicU64,
}

impl DecodedBudget {
    pub fn new(ceiling: u64) -> Self {
        Self {
            ceiling,
            used: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Charge `bytes` against the ceiling; `false` when the batch is over it.
    ///
    /// The charge stands even when the answer is no — an over-budget batch
    /// stays over budget, so every later request also fails fast instead of
    /// each re-reading the same almost-enough headroom.
    fn charge(&self, bytes: usize) -> bool {
        if self.ceiling == 0 {
            return true;
        }
        let used = self
            .used
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        used.saturating_add(bytes as u64) <= self.ceiling
    }
}

/// Shared state for rate limiting and concurrency control across all hosts.
pub struct FetchClient {
    client: Client,
    config: FetchClientConfig,
    budget: Arc<DecodedBudget>,
    global_sem: Arc<Semaphore>,
    /// Per-host semaphores, lazily created.
    host_sems: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// Per-host rate limiters, lazily created.
    host_rate_limiters: Arc<Mutex<HashMap<String, Arc<RateLimiter>>>>,
    /// Hosts this run sends a per-request token to, which get the host's
    /// authenticated budget. Set before any request to the host is made.
    authenticated_hosts: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Requests actually in flight, and the high-water mark. Counted after the
    /// permits are held, so it reports real HTTP concurrency rather than the
    /// number of tasks queued behind the semaphores.
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak_in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl FetchClient {
    pub fn new(config: FetchClientConfig) -> Result<Self, reqwest::Error> {
        let mut builder = Client::builder()
            .use_rustls_tls()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .timeout(config.total_timeout)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            // No automatic gzip: [`read_body_capped`] decodes it itself so
            // that the decoded size can be held against the bytes actually
            // received (see [`MAX_DECODE_RATIO`]). reqwest's transparent
            // decompression deletes the Content-Length header on the way
            // past, after which no ratio between the two sizes exists.
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
        let budget = Arc::new(DecodedBudget::new(config.max_total_bytes));

        Ok(Self {
            client,
            config,
            budget,
            global_sem,
            host_sems: Arc::new(Mutex::new(HashMap::new())),
            host_rate_limiters: Arc::new(Mutex::new(HashMap::new())),
            authenticated_hosts: std::sync::Mutex::new(std::collections::HashSet::new()),
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

        let headers = request_headers(url, accept, auth_token, validators);

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
                        if let Some(retry_after_secs) = quota_exhausted(&resp) {
                            return Err(FetchFailure::QuotaExhausted {
                                status: status.as_u16(),
                                retry_after_secs,
                            });
                        }
                        return Err(FetchFailure::Status(status.as_u16()));
                    }

                    let etag = header_string(&resp, reqwest::header::ETAG);
                    let last_modified = header_string(&resp, reqwest::header::LAST_MODIFIED);
                    let content_type =
                        header_string(&resp, reqwest::header::CONTENT_TYPE).unwrap_or_default();
                    let bytes =
                        read_body_capped(resp, url, self.config.max_body_bytes, &self.budget)
                            .await?;

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

    /// Give a host its authenticated budget for the rest of this client's
    /// life, because the batch sends a per-request token to it. Only a URL
    /// that [`token_allowed_for`] accepts marks its host; call it before the
    /// first request to that host, since budgets are fixed on first use.
    pub fn note_token_for(&self, url: &str) {
        if !token_allowed_for(url) {
            return;
        }
        if let Some(host) = extract_host(url)
            && let Ok(mut hosts) = self.authenticated_hosts.lock()
        {
            hosts.insert(host.to_ascii_lowercase());
        }
    }

    /// The budget a host gets: authenticated only when this run sends a
    /// per-request token to it, anonymous otherwise.
    fn credentials_for(&self, host: &str) -> Credentials {
        match self.authenticated_hosts.lock() {
            Ok(hosts) if hosts.contains(&host.to_ascii_lowercase()) => Credentials::Authenticated,
            _ => Credentials::Anonymous,
        }
    }

    /// Per-host permits: an explicit configured cap when there is one,
    /// otherwise the host's policy for the credentials it will receive.
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

/// Read a response body under the size caps, the expansion ratio and the
/// batch budget.
///
/// The wire bytes are read first, capped at `max_body_bytes`: compression
/// never grows a body by more than its own overhead, so a raw body past the
/// cap can only decode past the cap, and refusing it early bounds what a
/// gzip decoder is ever handed. A body the response declares as gzip is
/// inflated here — not by reqwest — so that decoded bytes can be held
/// against the bytes actually received; see [`MAX_DECODE_RATIO`] for why
/// that comparison needs this manual decode. A corrupt gzip container was a
/// transport-level decode error when reqwest owned decompression; it is a
/// [`FetchFailure::Malformed`] now, which names the body rather than the
/// connection.
async fn read_body_capped(
    mut resp: Response,
    url: &str,
    max_body_bytes: usize,
    budget: &DecodedBudget,
) -> Result<Vec<u8>, FetchFailure> {
    let encoding = header_string(&resp, reqwest::header::CONTENT_ENCODING)
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let gzipped = encoding
        .split(',')
        .map(str::trim)
        .any(|e| e == "gzip" || e == "x-gzip");
    if !gzipped && !encoding.is_empty() && encoding != "identity" {
        // An encoding this client did not ask for and cannot decode
        // (deflate, br, zstd): the wire bytes are not the body, and
        // returning them as-is would hand compressed bytes to the JSON
        // parser as though they were the document.
        return Err(FetchFailure::Malformed);
    }
    if let Some(len) = resp.content_length()
        && len > max_body_bytes as u64
    {
        crate::log::warn(&format!(
            "declared body length {len} exceeds {max_body_bytes} bytes for {}, skipping",
            redact_url(url)
        ));
        return Err(FetchFailure::BodyTooLarge);
    }
    let mut wire: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if wire.len() + chunk.len() > max_body_bytes {
                    crate::log::warn(&format!(
                        "body for {} exceeds {max_body_bytes} bytes on the wire, skipping",
                        redact_url(url)
                    ));
                    return Err(FetchFailure::BodyTooLarge);
                }
                wire.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(FetchFailure::Transport(describe_transport_error(&e))),
        }
    }
    if !gzipped {
        // Identity: the wire bytes are the body, so the budget is charged
        // for exactly what is about to be buffered and held.
        if !budget.charge(wire.len()) {
            crate::log::warn(&format!(
                "batch decoded-body budget exhausted at {} for {}",
                wire.len(),
                redact_url(url)
            ));
            return Err(FetchFailure::BudgetExhausted);
        }
        return Ok(wire);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut reader = flate2::read::MultiGzDecoder::new(wire.as_slice());
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        use std::io::Read;
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > max_body_bytes {
                    crate::log::warn(&format!(
                        "body for {} exceeds {max_body_bytes} bytes decoded, skipping",
                        redact_url(url)
                    ));
                    return Err(FetchFailure::BodyTooLarge);
                }
                if out.len() + n > DECODE_RATIO_FLOOR_BYTES
                    && (out.len() + n) as u64 > wire.len() as u64 * MAX_DECODE_RATIO
                {
                    crate::log::warn(&format!(
                        "body for {} decodes to over {}x its {} wire bytes, skipping",
                        redact_url(url),
                        MAX_DECODE_RATIO,
                        wire.len()
                    ));
                    return Err(FetchFailure::BodyExpandsTooMuch);
                }
                if !budget.charge(n) {
                    crate::log::warn(&format!(
                        "batch decoded-body budget exhausted at {} decoded bytes for {}",
                        out.len() + n,
                        redact_url(url)
                    ));
                    return Err(FetchFailure::BudgetExhausted);
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(_) => return Err(FetchFailure::Malformed),
        }
    }
}

/// Hosts a per-request token may be sent to.
const TOKEN_HOSTS: &[&str] = &["github.com", "api.github.com"];

/// Whether a per-request token may be sent with a request for `url`: the URL
/// must be https on the default port, name github.com or api.github.com
/// exactly, and carry no userinfo. Anything else goes out without the token.
pub fn token_allowed_for(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https"
        || parsed.port().is_some_and(|port| port != 443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            TOKEN_HOSTS.contains(&host.trim_end_matches('.'))
        }
        _ => false,
    }
}

/// Headers for one request. The Authorization header is added only when
/// `auth_token` is given and [`token_allowed_for`] accepts the URL, and it is
/// marked sensitive so it never appears in a debug rendering.
pub fn request_headers(
    url: &str,
    accept: Option<&str>,
    auth_token: Option<&str>,
    validators: &Validators,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    // Advertise gzip exactly as reqwest's `.gzip(true)` used to: the client
    // above no longer decompresses transparently, but the negotiation — and
    // the bandwidth it saves — stays. Only gzip is offered, because only
    // gzip is decoded (see [`read_body_capped`]).
    if let Ok(v) = HeaderValue::try_from("gzip") {
        headers.insert(ACCEPT_ENCODING, v);
    }
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
    if let Some(token) = auth_token.filter(|t| !t.is_empty())
        && token_allowed_for(url)
        && let Ok(mut v) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        v.set_sensitive(true);
        headers.insert(AUTHORIZATION, v);
    }
    headers
}

/// For a 403 or 429 that reports a used-up quota (`x-ratelimit-remaining: 0`
/// or a `Retry-After`), the seconds the host asked to wait, if it said.
/// `None` for any other response.
fn quota_exhausted(resp: &Response) -> Option<Option<u64>> {
    let status = resp.status();
    if status != StatusCode::FORBIDDEN && status != StatusCode::TOO_MANY_REQUESTS {
        return None;
    }
    let spent = header_string(
        resp,
        reqwest::header::HeaderName::from_static("x-ratelimit-remaining"),
    )
    .is_some_and(|v| v.trim() == "0");
    let retry_after = resp.headers().contains_key(reqwest::header::RETRY_AFTER);
    if !spent && !retry_after {
        return None;
    }
    Some(parse_retry_after(resp).map(|d| d.as_secs()))
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
        .map(str::to_string)
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
        .map_or(0, |d| u64::from(d.subsec_nanos()));
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
    fn a_request_token_is_allowed_only_over_https_to_github() {
        for url in [
            "https://api.github.com/repos/acme/lib/license",
            "https://github.com/acme/lib",
            "https://API.GitHub.com:443/repos/acme/lib",
        ] {
            assert!(token_allowed_for(url), "{url}");
        }
        for url in [
            "http://api.github.com/repos/acme/lib/license",
            "https://api.github.com:8443/repos/acme/lib",
            "https://user:pw@api.github.com/repos/acme/lib",
            "https://raw.github.com/acme/lib/main/x",
            "https://api.github.com.example.com/repos/acme/lib",
            "https://registry.npmjs.org/left-pad",
            "https://140.82.112.6/repos/acme/lib",
            "not a url",
        ] {
            assert!(!token_allowed_for(url), "{url}");
        }
    }

    #[test]
    fn the_authorization_header_follows_the_url_rule() {
        let none = Validators::default();
        let headers = request_headers(
            "https://api.github.com/repos/acme/lib/license",
            Some("application/json"),
            Some("t0ken"),
            &none,
        );
        let auth = headers.get(AUTHORIZATION).expect("header is set");
        assert_eq!(auth.to_str().unwrap(), "Bearer t0ken");
        assert!(auth.is_sensitive());
        assert!(!format!("{headers:?}").contains("t0ken"));

        for (url, token) in [
            ("http://api.github.com/repos/acme/lib", Some("t0ken")),
            ("https://registry.npmjs.org/left-pad", Some("t0ken")),
            ("https://api.github.com/repos/acme/lib", Some("")),
            ("https://api.github.com/repos/acme/lib", None),
        ] {
            let headers = request_headers(url, None, token, &none);
            assert!(headers.get(AUTHORIZATION).is_none(), "{url} {token:?}");
        }
    }

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
    async fn github_hosts_keep_the_anonymous_budget() {
        let client = FetchClient::new(FetchClientConfig::default()).expect("client builds");
        for host in ["api.github.com", "github.com"] {
            assert_eq!(
                client.get_host_semaphore(host).await.available_permits(),
                4,
                "{host}"
            );
        }
        assert_eq!(
            client
                .get_host_semaphore("registry.npmjs.org")
                .await
                .available_permits(),
            16
        );
    }

    #[tokio::test]
    async fn a_host_gets_the_authenticated_budget_only_with_an_allowed_token() {
        let client = FetchClient::new(FetchClientConfig::default()).expect("client builds");
        // Neither of these may carry the token, so neither raises a budget.
        client.note_token_for("http://github.com/acme/lib");
        client.note_token_for("https://registry.npmjs.org/left-pad");
        client.note_token_for("https://api.github.com/repos/acme/lib/license");
        assert_eq!(
            client
                .get_host_semaphore("api.github.com")
                .await
                .available_permits(),
            8
        );
        assert_eq!(
            client
                .get_host_semaphore("github.com")
                .await
                .available_permits(),
            4
        );
        assert_eq!(
            client.credentials_for("registry.npmjs.org"),
            Credentials::Anonymous
        );
    }

    #[tokio::test]
    async fn an_explicit_per_host_cap_overrides_the_policy() {
        let client = FetchClient::new(FetchClientConfig {
            per_host_concurrency: 2,
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

    #[test]
    fn a_zero_budget_ceiling_is_unlimited() {
        let budget = DecodedBudget::new(0);
        for _ in 0..1000 {
            assert!(budget.charge(1024 * 1024));
        }
    }

    #[test]
    fn the_budget_tips_exactly_at_the_ceiling() {
        let budget = DecodedBudget::new(1000);
        assert!(budget.charge(600));
        assert!(budget.charge(400), "600 + 400 is exactly the ceiling");
        assert!(!budget.charge(1), "one byte past the ceiling must fail");
        // And it stays tipped: a later request must not reuse the headroom
        // the last failure charged away.
        assert!(!budget.charge(1));
    }

    #[test]
    fn the_budget_counts_every_charge_even_refused_ones() {
        let budget = DecodedBudget::new(100);
        assert!(!budget.charge(200));
        // The refused charge still counted, so even a tiny later charge
        // fails — an over-budget batch stays over budget.
        assert!(!budget.charge(1));
    }

    #[test]
    fn the_default_config_budgets_the_whole_batch() {
        let config = FetchClientConfig::default();
        assert_eq!(config.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert!(config.max_total_bytes > MAX_BODY_BYTES as u64);
    }
}
