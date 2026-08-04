//! Integration tests for `cdxrs fetch`.
//!
//! Every test drives the real binary as a subprocess against a wiremock server,
//! so what is exercised is the shipped contract: stdin envelope in, stdout
//! envelope out, statistics on stderr, exit code 0 unless the subcommand itself
//! could not run.

mod common;

use common::{batch, request, run_fetch, run_fetch_cached, run_fetch_env, walk};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const JSON: &str = "application/json";

#[tokio::test]
async fn happy_path_returns_the_body_verbatim() {
    let server = MockServer::start().await;
    let body = serde_json::json!({"name": "left-pad", "dist-tags": {"latest": "1.3.0"}});
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;

    let input = batch(vec![request(
        "npm:left-pad",
        &format!("{}/left-pad", server.uri()),
    )]);
    let run = run_fetch(&input, &[]).expect_success();
    let result = run.result("npm:left-pad");

    assert_eq!(result["ok"], true);
    assert_eq!(result["status"], 200);
    assert_eq!(result["fromCache"], false);
    // The body must be handed back untouched: the JS side derives every field
    // from it, so any normalisation here would be a divergence.
    assert_eq!(result["body"], body);
    assert_eq!(run.stats()["ok"], 1);
    assert_eq!(run.stats()["unique"], 1);
}

#[tokio::test]
async fn accept_header_is_sent_when_requested() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/packages/http"))
        .and(header("accept", "application/vnd.pub.v2+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;

    let input = serde_json::json!({
        "requests": [{
            "id": "pub:http",
            "url": format!("{}/api/packages/http", server.uri()),
            "accept": "application/vnd.pub.v2+json",
        }]
    })
    .to_string();
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("pub:http")["ok"], true);
}

#[tokio::test]
async fn not_found_is_a_recorded_failure_not_a_crash() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let input = batch(vec![request(
        "npm:missing",
        &format!("{}/missing", server.uri()),
    )]);
    let run = run_fetch(&input, &[]).expect_success();
    let result = run.result("npm:missing");

    assert_eq!(result["ok"], false);
    assert_eq!(result["status"], 404);
    assert!(result["body"].is_null());
    assert_eq!(run.stats()["failures"], 1);
}

/// A 4xx that is not 429 must never be retried — retrying a 404 across 2000
/// components is how a scan turns into an outage complaint.
#[tokio::test]
async fn client_errors_are_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gone"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1) // exactly one attempt
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/gone", server.uri()))]);
    run_fetch(&input, &[]).expect_success();
    // `expect(1)` is verified on drop.
}

#[tokio::test]
async fn rate_limit_is_retried_after_the_server_supplied_delay() {
    let server = MockServer::start().await;
    // First call: 429 with Retry-After: 1. Second: success.
    Mock::given(method("GET"))
        .and(path("/throttled"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/throttled"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": 1})))
        .expect(1)
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/throttled", server.uri()))]);
    let started = std::time::Instant::now();
    let run = run_fetch(&input, &[]).expect_success();
    let elapsed = started.elapsed();

    assert_eq!(run.result("x")["ok"], true);
    // The whole point: the delay is honoured, not merely parsed. The previous
    // implementation recorded it against the host bucket and retried instantly.
    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "retry did not wait for Retry-After (elapsed {elapsed:?})"
    );
}

#[tokio::test]
async fn server_errors_are_retried_then_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flaky"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/flaky"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"recovered": true})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/flaky", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["body"]["recovered"], true);
}

#[tokio::test]
async fn exhausted_server_errors_end_the_request_bounded() {
    let server = MockServer::start().await;
    // Persistent 500. MAX_RETRIES = 3, so 4 attempts total and then a verdict —
    // not an unbounded loop.
    Mock::given(method("GET"))
        .and(path("/down"))
        .respond_with(ResponseTemplate::new(500))
        .expect(4)
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/down", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    assert_eq!(run.result("x")["status"], 500);
}

#[tokio::test]
async fn malformed_json_is_a_failure_with_a_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/broken"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("{ not json", JSON)
                .insert_header("content-type", JSON),
        )
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/broken", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    assert_eq!(run.result("x")["error"], "malformed response body");
}

#[tokio::test]
async fn non_json_content_type_is_returned_as_text() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/licence.html"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html>MIT</html>", "text/html"))
        .mount(&server)
        .await;

    let input = batch(vec![request(
        "x",
        &format!("{}/licence.html", server.uri()),
    )]);
    let run = run_fetch(&input, &[]).expect_success();
    // pkg.go.dev licence pages are scraped by the JS side, so the text has to
    // survive the trip rather than being rejected as "not JSON".
    assert_eq!(run.result("x")["body"], "<html>MIT</html>");
}

#[tokio::test]
async fn redirects_are_followed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/new", server.uri()).as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"moved": true})))
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/old", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["body"]["moved"], true);
}

#[tokio::test]
async fn a_body_over_the_limit_is_abandoned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("x".repeat(4096), JSON))
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/huge", server.uri()))]);
    let run = run_fetch(&input, &["--max-body-bytes", "1024"]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    assert!(
        run.result("x")["error"]
            .as_str()
            .unwrap()
            .contains("exceeds the configured maximum"),
        "{}",
        run.result("x")
    );
}

#[tokio::test]
async fn duplicate_urls_are_coalesced_into_one_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"shared": true})))
        // Three callers, one upstream request. A monorepo listing the same
        // dependency in ten workspaces must not become ten requests.
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/shared", server.uri());
    let input = batch(vec![
        request("a", &url),
        request("b", &url),
        request("c", &url),
    ]);
    let run = run_fetch(&input, &[]).expect_success();

    assert_eq!(run.stats()["requests"], 3);
    assert_eq!(run.stats()["unique"], 1);
    for id in ["a", "b", "c"] {
        assert_eq!(run.result(id)["body"]["shared"], true, "id {id}");
    }
}

#[tokio::test]
async fn empty_batch_succeeds() {
    let run = run_fetch(&batch(vec![]), &[]).expect_success();
    assert_eq!(run.json()["results"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn one_failure_does_not_affect_the_others() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/good"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"good": true})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/bad"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let input = batch(vec![
        request("good", &format!("{}/good", server.uri())),
        request("bad", &format!("{}/bad", server.uri())),
        request("unreachable", "http://127.0.0.1:1/nope"),
    ]);
    let run = run_fetch(&input, &[]).expect_success();

    assert_eq!(run.result("good")["ok"], true);
    assert_eq!(run.result("bad")["ok"], false);
    assert_eq!(run.result("unreachable")["ok"], false);
    assert_eq!(run.stats()["ok"], 1);
    assert_eq!(run.stats()["failures"], 2);
}

// ---------------------------------------------------------------- cache tests

#[tokio::test]
async fn second_run_is_served_from_the_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cached"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"v": 1})))
        .expect(1) // one upstream request across two runs
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/cached", server.uri()))]);

    let first = run_fetch_cached(&input, &[], cache.path()).expect_success();
    assert_eq!(first.result("x")["fromCache"], false);

    let second = run_fetch_cached(&input, &[], cache.path()).expect_success();
    assert_eq!(second.result("x")["fromCache"], true);
    assert_eq!(second.result("x")["body"]["v"], 1);
    assert_eq!(second.stats()["cacheHits"], 1);
}

#[tokio::test]
async fn stale_entry_is_revalidated_with_if_none_match() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/etagged"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v1\"")
                .set_body_json(serde_json::json!({"v": 1})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Second run: conditional request arrives with the validator and is told
    // nothing changed.
    Mock::given(method("GET"))
        .and(path("/etagged"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/etagged", server.uri()))]);

    run_fetch_cached(&input, &["--cache-ttl", "1"], cache.path()).expect_success();
    std::thread::sleep(std::time::Duration::from_millis(2200));
    let second = run_fetch_cached(&input, &["--cache-ttl", "1"], cache.path()).expect_success();

    assert_eq!(second.result("x")["revalidated"], true);
    assert_eq!(second.result("x")["fromCache"], true);
    // The body has to come back from the cache — a 304 carries none.
    assert_eq!(second.result("x")["body"]["v"], 1);
}

#[tokio::test]
async fn expired_entry_without_a_validator_is_refetched() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/novalidator"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"v": 1})))
        .expect(2)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/novalidator", server.uri()))]);
    run_fetch_cached(&input, &["--cache-ttl", "1"], cache.path()).expect_success();
    std::thread::sleep(std::time::Duration::from_millis(2200));
    let second = run_fetch_cached(&input, &["--cache-ttl", "1"], cache.path()).expect_success();
    assert_eq!(second.result("x")["fromCache"], false);
}

#[tokio::test]
async fn cache_ttl_zero_means_never_expires() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/forever"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"v": 1})))
        .expect(1)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/forever", server.uri()))]);
    run_fetch_cached(&input, &["--cache-ttl", "0"], cache.path()).expect_success();
    let second = run_fetch_cached(&input, &["--cache-ttl", "0"], cache.path()).expect_success();
    assert_eq!(second.result("x")["fromCache"], true);
}

/// Two hosts serving the same path must not share a cache entry.
#[tokio::test]
async fn cache_keys_are_isolated_between_hosts() {
    let one = MockServer::start().await;
    let two = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"from": "one"})))
        .mount(&one)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"from": "two"})))
        .mount(&two)
        .await;

    let cache = TempDir::new().unwrap();
    run_fetch_cached(
        &batch(vec![request("a", &format!("{}/left-pad", one.uri()))]),
        &[],
        cache.path(),
    )
    .expect_success();
    let second = run_fetch_cached(
        &batch(vec![request("b", &format!("{}/left-pad", two.uri()))]),
        &[],
        cache.path(),
    )
    .expect_success();

    assert_eq!(second.result("b")["body"]["from"], "two");
    assert_eq!(second.result("b")["fromCache"], false);
}

/// The leak that the previous cache had: an authenticated body served to an
/// anonymous lookup of the same URL.
#[tokio::test]
async fn auth_realm_isolates_cache_entries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/private"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"secret": true})))
        // Two requests: the anonymous one must not be answered from the
        // authenticated entry.
        .expect(2)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let url = format!("{}/private", server.uri());
    let with_realm = serde_json::json!({
        "requests": [{ "id": "priv", "url": url, "authRealm": "corp:token-holder" }]
    })
    .to_string();
    run_fetch_cached(&with_realm, &[], cache.path()).expect_success();

    let anonymous = batch(vec![request("anon", &url)]);
    let second = run_fetch_cached(&anonymous, &[], cache.path()).expect_success();
    assert_eq!(
        second.result("anon")["fromCache"],
        false,
        "an authenticated response was served to an anonymous lookup"
    );
}

#[tokio::test]
async fn offline_serves_the_cache_and_records_misses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/warm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"warm": true})))
        .expect(1)
        .mount(&server)
        .await;
    // Deliberately never mounted: an offline run must not reach it.
    let cold_url = format!("{}/cold", server.uri());

    let cache = TempDir::new().unwrap();
    let warm_url = format!("{}/warm", server.uri());
    run_fetch_cached(&batch(vec![request("warm", &warm_url)]), &[], cache.path()).expect_success();

    let run = run_fetch_cached(
        &batch(vec![request("warm", &warm_url), request("cold", &cold_url)]),
        &["--offline"],
        cache.path(),
    )
    .expect_success();

    assert_eq!(run.result("warm")["ok"], true);
    assert_eq!(run.result("warm")["fromCache"], true);
    assert_eq!(run.result("cold")["ok"], false);
    assert_eq!(run.result("cold")["error"], "offline-miss");
    assert_eq!(run.stats()["offlineMisses"], 1);
    // An offline miss is an absence, not a failure of the run.
    assert_eq!(run.status, 0);
}

#[tokio::test]
async fn offline_with_no_cache_is_rejected_rather_than_silently_useless() {
    let run = run_fetch_env(
        &batch(vec![request("x", "https://example.com/x")]),
        &["--offline", "--no-cache"],
        &[],
    );
    assert_ne!(run.status, 0);
    assert!(
        run.stderr.contains("--offline requires the cache"),
        "{}",
        run.stderr
    );
}

// ---------------------------------------------------------- credential safety

/// A sentinel credential must not appear in stdout, stderr, or any cache file.
#[tokio::test]
async fn credentials_never_reach_output_or_disk() {
    const SENTINEL: &str = "s3cr3t-sentinel-token";

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/private"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;

    // The credential appears in three places a naive implementation leaks from:
    // userinfo, a query parameter, and GITHUB_TOKEN.
    let host_port = server.uri().replace("http://", "");
    let url = format!("http://user:{SENTINEL}@{host_port}/private?access_token={SENTINEL}");

    let cache = TempDir::new().unwrap();
    let run = run_fetch_env(
        &batch(vec![request("x", &url)]),
        &[],
        &[
            ("CDXGEN_CACHE_DIR", &cache.path().to_string_lossy()),
            ("CDXGEN_CACHE_LOOPBACK", "1"),
            ("GITHUB_TOKEN", SENTINEL),
        ],
    )
    .expect_success();

    assert!(!run.stdout.contains(SENTINEL), "credential in stdout");
    assert!(!run.stderr.contains(SENTINEL), "credential in stderr");

    let files = walk(cache.path());
    assert!(
        !files.is_empty(),
        "no cache file written; test proves nothing"
    );
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        assert!(
            !text.contains(SENTINEL),
            "credential leaked into {}",
            file.display()
        );
    }
}

/// Failure messages are built from error kinds, not from reqwest's Display,
/// which interpolates the URL.
#[tokio::test]
async fn transport_errors_do_not_echo_the_url() {
    const SENTINEL: &str = "s3cr3t-in-url";
    let url = format!("http://user:{SENTINEL}@127.0.0.1:1/unreachable");
    let run = run_fetch(&batch(vec![request("x", &url)]), &[]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    assert!(!run.stdout.contains(SENTINEL), "{}", run.stdout);
    assert!(!run.stderr.contains(SENTINEL), "{}", run.stderr);
}

#[tokio::test]
async fn github_token_is_sent_to_github_hosts_only() {
    let server = MockServer::start().await;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let recorder = seen.clone();
    Mock::given(method("GET"))
        .and(path("/repos/o/r/license"))
        .respond_with(move |req: &Request| {
            recorder.lock().unwrap().push(
                req.headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
            );
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
        })
        .mount(&server)
        .await;

    // The mock server is not github.com, so the ambient token must not be sent.
    run_fetch_env(
        &batch(vec![request(
            "x",
            &format!("{}/repos/o/r/license", server.uri()),
        )]),
        &[],
        &[("GITHUB_TOKEN", "should-not-be-sent")],
    )
    .expect_success();

    let observed = seen.lock().unwrap().clone();
    assert_eq!(observed, vec![None], "token sent to a non-github host");
}

// -------------------------------------------------------------- concurrency

/// The point of the whole subcommand: many URLs are in flight at once.
#[tokio::test]
async fn requests_run_concurrently() {
    let server = MockServer::start().await;
    // Each response takes 300 ms. 12 requests serially would be 3.6 s; with a
    // global cap of 16 they should all overlap.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"ok": true}))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&server)
        .await;

    let requests: Vec<_> = (0..12)
        .map(|i| request(&format!("r{i}"), &format!("{}/pkg-{i}", server.uri())))
        .collect();
    let started = std::time::Instant::now();
    let run = run_fetch(&batch(requests), &[]).expect_success();
    let elapsed = started.elapsed();

    assert_eq!(run.stats()["ok"], 12);
    assert!(
        elapsed < std::time::Duration::from_millis(2000),
        "12 x 300ms took {elapsed:?} — requests are not overlapping"
    );
    assert!(
        run.stats()["peakConcurrency"].as_u64().unwrap() > 1,
        "peak concurrency was {}",
        run.stats()["peakConcurrency"]
    );
}

#[tokio::test]
async fn per_host_concurrency_cap_is_respected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"ok": true}))
                .set_delay(std::time::Duration::from_millis(200)),
        )
        .mount(&server)
        .await;

    let requests: Vec<_> = (0..8)
        .map(|i| request(&format!("r{i}"), &format!("{}/pkg-{i}", server.uri())))
        .collect();
    let started = std::time::Instant::now();
    let run = run_fetch(&batch(requests), &["--per-host-concurrency", "2"]).expect_success();
    let elapsed = started.elapsed();

    assert_eq!(run.stats()["ok"], 8);
    // 8 requests, 2 at a time, 200 ms each: at least 4 rounds.
    assert!(
        elapsed >= std::time::Duration::from_millis(700),
        "per-host cap was not enforced (elapsed {elapsed:?})"
    );
}

// ---------------------------------------------------------- loopback caching

/// Loopback hosts must not be written to the cache. Their entries are keyed by
/// ephemeral ports that will never be reused, so caching them pollutes the
/// directory permanently.
#[tokio::test]
async fn loopback_hosts_are_not_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": 1})))
        .expect(2)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/pkg", server.uri()))]);
    // run_fetch_cached sets CDXGEN_CACHE_LOOPBACK=1, so use run_fetch_env
    // directly with only CDXGEN_CACHE_DIR (loopback is excluded by default).
    let first = run_fetch_env(
        &input,
        &[],
        &[("CDXGEN_CACHE_DIR", &cache.path().to_string_lossy())],
    )
    .expect_success();
    assert_eq!(first.result("x")["ok"], true);
    assert_eq!(first.result("x")["fromCache"], false);

    let second = run_fetch_env(
        &input,
        &[],
        &[("CDXGEN_CACHE_DIR", &cache.path().to_string_lossy())],
    )
    .expect_success();
    assert_eq!(second.result("x")["ok"], true);
    // Must not be served from cache — loopback entries are never written.
    assert_eq!(second.result("x")["fromCache"], false);

    // No cache files should exist on disk.
    let files = walk(cache.path());
    assert!(
        files.iter().all(|p| !p.to_string_lossy().contains(".json")),
        "loopback host wrote cache files: {files:?}"
    );
}

/// With CDXGEN_CACHE_LOOPBACK=1, loopback hosts are cached normally — needed
/// by contrib/bench-fetch.js so the warm-cache benchmark measures a hit.
#[tokio::test]
async fn loopback_cached_when_override_env_is_set() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"v": 1})))
        .expect(1)
        .mount(&server)
        .await;

    let cache = TempDir::new().unwrap();
    let input = batch(vec![request("x", &format!("{}/pkg", server.uri()))]);
    let first = run_fetch_env(
        &input,
        &[],
        &[
            ("CDXGEN_CACHE_DIR", &cache.path().to_string_lossy()),
            ("CDXGEN_CACHE_LOOPBACK", "1"),
        ],
    )
    .expect_success();
    assert_eq!(first.result("x")["fromCache"], false);

    let second = run_fetch_env(
        &input,
        &[],
        &[
            ("CDXGEN_CACHE_DIR", &cache.path().to_string_lossy()),
            ("CDXGEN_CACHE_LOOPBACK", "1"),
        ],
    )
    .expect_success();
    assert_eq!(second.result("x")["fromCache"], true);
    assert_eq!(second.result("x")["body"]["v"], 1);
}
