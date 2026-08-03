//! Per-host rate limiter: a minimum-interval gate with server override.
//!
//! Published limits, which are what the policy below encodes:
//! - crates.io: asks for ~1 req/s from anonymous clients, and enforces it.
//! - GitHub API: 60 req/h anonymous, 5000 req/h with a token.
//! - npm registry: no documented per-IP limit; a CDN in front of a static
//!   document store.
//! - PyPI: no documented limit; also CDN-fronted.
//!
//! A single interval for every host is the wrong shape. The previous version
//! applied crates.io's 250 ms to *all* hosts, which capped an npm run at 4
//! requests per second — slower than the serial JS path it replaces once the
//! JS path's connection reuse is taken into account. Hosts that publish a limit
//! get an interval; hosts that do not are bounded by the per-host concurrency
//! cap alone, and by whatever `Retry-After` they choose to send.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::time::sleep;

/// Whether a credential will be sent to the host.
///
/// GitHub is the reason this exists: 60 requests an hour anonymously against
/// 5000 with a token is not a difference of degree, and a licence sweep over a
/// few hundred repositories is hopeless in the first case and comfortable in the
/// second. Applying the anonymous budget to a token-bearing client throws away
/// the whole point of having set `GITHUB_TOKEN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credentials {
    /// No credential will be sent.
    Anonymous,
    /// A token will be sent with every request to this host.
    Authenticated,
}

/// How politely to treat one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPolicy {
    /// Minimum gap between two requests to this host.
    pub min_interval: Duration,
    /// Maximum requests in flight to this host.
    pub max_concurrency: usize,
}

/// Hosts that publish a rate limit, and what they publish.
///
/// Everything else is treated as a CDN-fronted document store. That distinction
/// is worth more than it looks: a single-registry project — which is to say,
/// almost every npm project — has exactly one host, so a conservative per-host
/// cap *is* the global cap. Capping npm at 4 turned a 16-way batch into a 4-way
/// one and cost three quarters of the available speedup.
///
/// Columns: host, anonymous interval ms, anonymous concurrency, authenticated
/// interval ms, authenticated concurrency. A host whose limit does not change
/// with a credential repeats the same pair.
const HOST_POLICIES: &[(&str, u64, usize, u64, usize)] = &[
    // crates.io's published budget is per IP and does not improve with a token,
    // and cdxgen sends none to it.
    ("crates.io", 250, 4, 250, 4),
    // GitHub: 60 req/h anonymous, 5000 req/h authenticated. 5000/h is ~1.4 req/s
    // sustained, but the limit is an hourly budget rather than a rate, so a
    // batch of a few hundred lookups is well inside it. Hence no interval and a
    // real concurrency allowance once a token is present.
    ("api.github.com", 250, 4, 0, 8),
    ("github.com", 250, 4, 0, 8),
    // GitLab: 2000 req/min authenticated against 500 unauthenticated.
    ("gitlab.com", 250, 4, 0, 8),
    ("pkg.go.dev", 250, 4, 250, 4),
];

/// Concurrency allowed to a host with no published limit.
const DEFAULT_HOST_CONCURRENCY: usize = 16;

/// Resolve the policy for a host.
pub fn policy_for(host: &str, credentials: Credentials) -> HostPolicy {
    let host = host.to_ascii_lowercase();
    for (candidate, anon_ms, anon_conc, auth_ms, auth_conc) in HOST_POLICIES {
        // Suffix match so `index.crates.io` inherits `crates.io`.
        if host == *candidate || host.ends_with(&format!(".{candidate}")) {
            let (ms, concurrency) = match credentials {
                Credentials::Anonymous => (anon_ms, anon_conc),
                Credentials::Authenticated => (auth_ms, auth_conc),
            };
            return HostPolicy {
                min_interval: Duration::from_millis(*ms),
                max_concurrency: *concurrency,
            };
        }
    }
    HostPolicy {
        min_interval: Duration::from_millis(0),
        max_concurrency: DEFAULT_HOST_CONCURRENCY,
    }
}

/// Resolve the polite minimum interval for a host.
pub fn min_interval_for(host: &str, credentials: Credentials) -> Duration {
    policy_for(host, credentials).min_interval
}

/// A minimum-interval rate limiter for one host.
pub struct RateLimiter {
    state: Mutex<LimiterState>,
}

struct LimiterState {
    /// Earliest time the next request may go out.
    next_available: Instant,
    /// Minimum interval between requests.
    min_interval: Duration,
    /// Server-imposed limits observed so far, for reporting.
    external_delays: u32,
}

impl RateLimiter {
    pub fn new(host: &str, credentials: Credentials) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                next_available: Instant::now(),
                min_interval: min_interval_for(host, credentials),
                external_delays: 0,
            }),
        }
    }

    /// Wait until this host's gate opens, then reserve the next slot.
    pub async fn wait(&self) {
        let delay = {
            let mut state = self.state.lock().await;
            let now = Instant::now();
            let wait_dur = state.next_available.saturating_duration_since(now);
            // Reserve from the later of "now" and the current reservation, so
            // that N waiters queue up rather than all being released together.
            let from = if now > state.next_available {
                now
            } else {
                state.next_available
            };
            state.next_available = from + state.min_interval;
            wait_dur
        };
        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    /// Record a server-imposed delay (`Retry-After` / `X-RateLimit-Reset`).
    ///
    /// This only moves the gate; the caller is responsible for actually waiting
    /// before it retries. Both happen at the call site in `client.rs` — a
    /// previous version did this and then retried immediately, which meant the
    /// server's back-off request was recorded and ignored.
    pub async fn external_delay(&self, delay: Duration) {
        let mut state = self.state.lock().await;
        state.external_delays += 1;
        let target = Instant::now() + delay;
        if target > state.next_available {
            state.next_available = target;
        }
    }

    /// How many times this host asked us to slow down.
    pub async fn external_delay_count(&self) -> u32 {
        self.state.lock().await.external_delays
    }
}

/// Per-host limiters, created on first use.
#[derive(Default)]
pub struct LimiterMap {
    inner: Mutex<HashMap<String, std::sync::Arc<RateLimiter>>>,
}

impl LimiterMap {
    pub async fn get(&self, host: &str, credentials: Credentials) -> std::sync::Arc<RateLimiter> {
        let mut map = self.inner.lock().await;
        map.entry(host.to_string())
            .or_insert_with(|| std::sync::Arc::new(RateLimiter::new(host, credentials)))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use Credentials::{Anonymous, Authenticated};

    #[test]
    fn published_limits_cap_concurrency_too() {
        assert_eq!(policy_for("crates.io", Anonymous).max_concurrency, 4);
        assert_eq!(policy_for("api.github.com", Anonymous).max_concurrency, 4);
    }

    #[test]
    fn a_github_token_buys_more_concurrency() {
        // 60 req/h anonymous vs 5000 with a token: the anonymous budget must not
        // be applied to a client that has one.
        let anon = policy_for("api.github.com", Anonymous);
        let auth = policy_for("api.github.com", Authenticated);
        assert_eq!(anon.max_concurrency, 4);
        assert_eq!(auth.max_concurrency, 8);
        assert_eq!(anon.min_interval, Duration::from_millis(250));
        assert_eq!(auth.min_interval, Duration::from_millis(0));
        assert_eq!(policy_for("github.com", Authenticated).max_concurrency, 8);
        assert_eq!(policy_for("gitlab.com", Authenticated).max_concurrency, 8);
    }

    #[test]
    fn a_token_does_not_change_a_per_ip_limit() {
        // crates.io's budget is per IP; a credential would not help even if we
        // had one to send.
        assert_eq!(
            policy_for("crates.io", Authenticated),
            policy_for("crates.io", Anonymous)
        );
        assert_eq!(
            policy_for("pkg.go.dev", Authenticated),
            policy_for("pkg.go.dev", Anonymous)
        );
    }

    #[test]
    fn cdn_hosts_are_not_capped_at_four() {
        assert_eq!(
            policy_for("registry.npmjs.org", Anonymous).max_concurrency,
            DEFAULT_HOST_CONCURRENCY
        );
        assert_eq!(
            policy_for("pypi.org", Anonymous).max_concurrency,
            DEFAULT_HOST_CONCURRENCY
        );
    }

    #[test]
    fn published_limits_get_an_interval() {
        assert_eq!(
            min_interval_for("crates.io", Anonymous),
            Duration::from_millis(250)
        );
        assert_eq!(
            min_interval_for("index.crates.io", Anonymous),
            Duration::from_millis(250)
        );
        assert_eq!(
            min_interval_for("API.GitHub.com", Anonymous),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn cdn_registries_are_not_throttled_to_four_per_second() {
        assert_eq!(
            min_interval_for("registry.npmjs.org", Anonymous),
            Duration::from_millis(0)
        );
        assert_eq!(
            min_interval_for("pypi.org", Anonymous),
            Duration::from_millis(0)
        );
        // A host that merely contains the substring must not match.
        assert_eq!(
            min_interval_for("crates.io.evil.example", Anonymous),
            Duration::from_millis(0)
        );
    }

    #[tokio::test]
    async fn interval_is_enforced_between_successive_waits() {
        let limiter = RateLimiter::new("crates.io", Anonymous);
        let start = Instant::now();
        limiter.wait().await;
        limiter.wait().await;
        limiter.wait().await;
        // Three requests at 250 ms apart: the first is free, so >= 500 ms.
        assert!(
            start.elapsed() >= Duration::from_millis(450),
            "elapsed {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn unthrottled_host_does_not_sleep() {
        let limiter = RateLimiter::new("registry.npmjs.org", Anonymous);
        let start = Instant::now();
        for _ in 0..50 {
            limiter.wait().await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "elapsed {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn external_delay_pushes_the_gate_out_and_is_counted() {
        let limiter = RateLimiter::new("registry.npmjs.org", Anonymous);
        limiter.external_delay(Duration::from_millis(200)).await;
        assert_eq!(limiter.external_delay_count().await, 1);
        let start = Instant::now();
        limiter.wait().await;
        assert!(
            start.elapsed() >= Duration::from_millis(150),
            "elapsed {:?}",
            start.elapsed()
        );
    }
}
