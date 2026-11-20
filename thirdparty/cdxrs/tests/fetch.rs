//! Integration tests for `cdxrs fetch`.
//!
//! Every test drives the real binary as a subprocess against a wiremock server,
//! so what is exercised is the shipped contract: stdin envelope in, stdout
//! envelope out, statistics on stderr, exit code 0 unless the subcommand itself
//! could not run.

mod common;

use common::{batch, request, run_fetch, run_fetch_cached, run_fetch_env, walk};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path, path_regex};
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
async fn github_token_is_not_sent_to_other_hosts() {
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

/// The batch envelope carries URLs chosen by the scanned project (a lockfile's
/// `resolved` URL, an `.npmrc` scope registry), so the host name alone must not
/// attach the ambient `GITHUB_TOKEN`. The GitHub hosts are reached through a
/// plain HTTP proxy that is the mock server, which records what each request
/// carried.
#[tokio::test]
async fn ambient_github_token_is_not_sent_to_github_hosts() {
    let server = MockServer::start().await;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let recorder = seen.clone();
    Mock::given(method("GET"))
        .respond_with(move |req: &Request| {
            recorder.lock().unwrap().push(
                req.headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
            );
            ResponseTemplate::new(404)
        })
        .mount(&server)
        .await;

    let run = run_fetch_env(
        &batch(vec![
            request("api", "http://api.github.com/repos/acme/private"),
            request(
                "web",
                "http://github.com/acme/private/raw/main/package.json",
            ),
            request(
                "sub",
                "http://raw.github.com/acme/private/main/package.json",
            ),
        ]),
        &["--no-cache"],
        &[
            ("HTTP_PROXY", &server.uri()),
            ("GITHUB_TOKEN", "ambient-token-must-not-be-sent"),
        ],
    )
    .expect_success();
    assert!(
        !run.stdout.contains("ambient-token-must-not-be-sent"),
        "{}",
        run.stdout
    );

    let observed = seen.lock().unwrap().clone();
    assert_eq!(
        observed.len(),
        3,
        "the proxy did not see every request; test proves nothing"
    );
    assert!(
        observed.iter().all(Option::is_none),
        "ambient token attached by host name: {observed:?}"
    );
}

/// A per-request `githubToken` is sent only over https to github.com or
/// api.github.com. Plain-http GitHub URLs (reached here through a recording
/// proxy) and any other host get the request without it, and the token never
/// appears in the output.
#[tokio::test]
async fn request_token_is_withheld_from_plain_http_and_other_hosts() {
    const TOKEN: &str = "request-token-must-not-be-sent";
    let server = MockServer::start().await;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let recorder = seen.clone();
    Mock::given(method("GET"))
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

    let with_token =
        |id: &str, url: &str| serde_json::json!({ "id": id, "url": url, "githubToken": TOKEN });
    let run = run_fetch_env(
        &batch(vec![
            with_token("api", "http://api.github.com/repos/acme/lib/license"),
            with_token("web", "http://github.com/acme/lib"),
            with_token("other", &format!("{}/repos/acme/lib/license", server.uri())),
        ]),
        &["--no-cache"],
        &[("HTTP_PROXY", &server.uri())],
    )
    .expect_success();
    assert!(!run.stdout.contains(TOKEN), "{}", run.stdout);
    assert!(!run.stderr.contains(TOKEN), "{}", run.stderr);

    let observed = seen.lock().unwrap().clone();
    assert_eq!(
        observed.len(),
        3,
        "the server did not see every request; test proves nothing"
    );
    assert!(
        observed.iter().all(Option::is_none),
        "request token sent where it is not allowed: {observed:?}"
    );
}

/// A request with a token and one without, for the same URL, are fetched
/// separately, so the anonymous caller never receives the authenticated body.
#[tokio::test]
async fn a_token_request_is_not_coalesced_with_an_anonymous_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/lib/license"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .expect(2)
        .mount(&server)
        .await;

    let url = format!("{}/repos/acme/lib/license", server.uri());
    let run = run_fetch(
        &batch(vec![
            request("anonymous", &url),
            serde_json::json!({ "id": "token", "url": url, "githubToken": "t" }),
        ]),
        &[],
    )
    .expect_success();
    assert_eq!(run.stats()["unique"], 2);
    assert_eq!(run.result("anonymous")["ok"], true);
    assert_eq!(run.result("token")["ok"], true);
}

/// A 403 that says the quota is used up is reported as such, with the wait
/// the host asked for, so the caller can pause the host.
#[tokio::test]
async fn a_spent_quota_is_reported_with_the_requested_wait() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/lib/license"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("retry-after", "42"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/forbidden"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;

    let run = run_fetch(
        &batch(vec![
            request("spent", &format!("{}/repos/acme/lib/license", server.uri())),
            request("forbidden", &format!("{}/forbidden", server.uri())),
        ]),
        &[],
    )
    .expect_success();
    let spent = run.result("spent");
    assert_eq!(spent["ok"], false);
    assert_eq!(spent["status"], 403);
    assert_eq!(spent["quotaExhausted"], true);
    assert_eq!(spent["retryAfterSecs"], 42);
    let forbidden = run.result("forbidden");
    assert_eq!(forbidden["status"], 403);
    assert!(forbidden.get("quotaExhausted").is_none(), "{forbidden}");
}

/// `schema-version` names the capabilities cdxgen probes for before it hands
/// cdxrs a request token.
#[test]
fn schema_version_lists_the_request_token_capability() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cdxrs"))
        .arg("schema-version")
        .output()
        .expect("cdxrs runs");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("schema-version prints JSON");
    assert!(
        json["capabilities"]
            .as_array()
            .expect("capabilities is an array")
            .iter()
            .any(|c| c == "fetch-github-token"),
        "{json}"
    );
    assert!(json["supportedSpecVersions"].is_array());
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

// -------------------------------------------------------------- output size

/// Issue 4393 (cdxgen): a workspace-scale batch — many packages, fat
/// packuments — produces an envelope far larger than anything else cdxrs
/// emits. The Rust side must hand it back complete and intact; the ceiling
/// that failed there was the JavaScript string limit, not this process.
#[tokio::test]
async fn large_bodies_round_trip_intact() {
    let server = MockServer::start().await;
    // ~2 MB of verifiable content per package: enough that a truncation,
    // re-serialization, or size cap on this side would corrupt the payload,
    // while staying cheap enough for CI.
    let padding = "x".repeat(2 * 1024 * 1024);
    let body = serde_json::json!({ "name": "pkg", "padding": padding });
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let requests: Vec<_> = (0..3)
        .map(|i| request(&format!("big:{i}"), &format!("{}/pkg-{i}", server.uri())))
        .collect();
    let run = run_fetch(&batch(requests), &[]).expect_success();

    assert_eq!(run.stats()["ok"], 3);
    for i in 0..3 {
        let result = run.result(&format!("big:{i}"));
        assert_eq!(result["ok"], true);
        // The body must arrive verbatim — the JS side derives every field
        // from it, so any normalisation here would be a divergence.
        assert_eq!(result["body"], body);
    }
}

/// `--output <file>` is the protocol's escape hatch for envelopes that must
/// not travel through a pipe (docs/CDXRS_PROTOCOL.md): the envelope has to
/// land in the file, byte-complete, with stdout staying empty.
#[tokio::test]
async fn output_flag_writes_the_envelope_to_a_file() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "left-pad",
            "dist-tags": {"latest": "1.3.0"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let out = TempDir::new().unwrap();
    let path = out.path().join("envelope.json");
    let input = batch(vec![request(
        "npm:left-pad",
        &format!("{}/left-pad", server.uri()),
    )]);
    let run = run_fetch(&input, &["--output", &path.to_string_lossy()]).expect_success();

    assert!(
        run.stdout.trim().is_empty(),
        "stdout must stay empty when --output is a file, got {:?}",
        run.stdout
    );
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let envelope: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("--output file is not valid JSON ({e}): {text}"));
    assert_eq!(envelope["results"][0]["id"], "npm:left-pad");
    assert_eq!(envelope["results"][0]["body"]["name"], "left-pad");
}

// ------------------------------------------------------ gzip and size budgets

/// Deterministic pseudo-random bytes: hex-of-xorshift, so every platform and
/// every run compresses the same. Random hex is near the worst case for
/// gzip (~2:1), which is exactly the shape of real registry metadata and
/// stays comfortably under the decode ratio.
fn hex_noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let hex = format!("{state:016x}");
        out.extend_from_slice(hex.as_bytes());
    }
    out.truncate(len);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A registry that answers with `Content-Encoding: gzip` must still come
/// back decoded.
#[tokio::test]
async fn gzip_responses_are_decoded() {
    let server = MockServer::start().await;
    let body = serde_json::json!({"name": "left-pad", "versions": String::from_utf8(hex_noise(120 * 1024)).unwrap()});
    let raw = serde_json::to_vec(&body).unwrap();
    let gz = gzip(&raw);
    Mock::given(method("GET"))
        .and(path("/gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_raw(gz, JSON),
        )
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/gz", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], true, "{}", run.result("x"));
    assert_eq!(run.result("x")["body"], body);
}

/// The client advertises the one encoding it decodes.
#[tokio::test]
async fn accept_encoding_gzip_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/negotiate"))
        .and(header("accept-encoding", "gzip"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/negotiate", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], true);
}

/// A body that expands beyond [`MAX_DECODE_RATIO`] once past the floor is
/// refused mid-decode: a few KB on the wire must not become tens of MB in
/// memory whatever the scanned lockfile asked for.
#[tokio::test]
async fn a_gzip_body_expanding_over_the_ratio_is_refused() {
    let server = MockServer::start().await;
    // 4 MiB of one character compresses to ~4 KB; the decoded size crosses
    // the 1 MiB floor and 100x the wire size in the same breath.
    let raw = vec![b'a'; 4 * 1024 * 1024];
    let gz = gzip(&raw);
    assert!(
        gz.len() * 100 < raw.len(),
        "fixture must expand past the ratio"
    );
    Mock::given(method("GET"))
        .and(path("/bomb"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_raw(gz, JSON),
        )
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/bomb", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    let result = run.result("x");
    let error = result["error"].as_str().unwrap();
    assert!(
        error.contains("100x the bytes received"),
        "unexpected error: {error}"
    );
    assert_eq!(
        result["refused"], true,
        "a size refusal tells the caller not to retry"
    );
}

/// The batch-wide ceiling on decoded bytes. Requests that would cross it
/// fail individually; the batch still exits 0 and reports every result.
#[tokio::test]
async fn the_total_decoded_budget_bounds_the_batch() {
    let server = MockServer::start().await;
    // 1 MiB of near-incompressible text per answer: the ratio never trips,
    // so only the budget can stop the batch.
    let raw = format!(
        "\"{}\"",
        String::from_utf8(hex_noise(1024 * 1024 - 2)).unwrap()
    );
    Mock::given(method("GET"))
        .and(path_regex("/doc.*"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(raw.clone(), JSON))
        .mount(&server)
        .await;

    // Distinct URLs: identical URLs are coalesced into one fetch, which
    // would charge the budget once and prove nothing about the batch.
    let input = batch(vec![
        request("a", &format!("{}/doc?a", server.uri())),
        request("b", &format!("{}/doc?b", server.uri())),
        request("c", &format!("{}/doc?c", server.uri())),
        request("d", &format!("{}/doc?d", server.uri())),
    ]);
    let run = run_fetch(&input, &["--max-total-bytes", "2500000"]).expect_success();
    let ok: Vec<_> = ["a", "b", "c", "d"]
        .iter()
        .filter(|id| run.result(id)["ok"] == true)
        .cloned()
        .collect();
    let budget_failures: Vec<_> = ["a", "b", "c", "d"]
        .iter()
        .filter(|id| {
            run.result(id)["error"]
                .as_str()
                .is_some_and(|e| e.contains("budget exhausted"))
        })
        .cloned()
        .collect();
    assert!(
        !ok.is_empty() && !budget_failures.is_empty(),
        "the budget must both admit and refuse: ok={ok:?} failures={budget_failures:?}"
    );
    assert_eq!(
        ok.len() + budget_failures.len(),
        4,
        "every result is either served or budget-refused: {}",
        run.json()["results"]
    );
    assert_eq!(run.stats()["failures"], budget_failures.len());
}

/// `--max-total-bytes 0` documents "no ceiling": the whole batch is served.
#[tokio::test]
async fn max_total_bytes_zero_disables_the_ceiling() {
    let server = MockServer::start().await;
    let raw = format!("\"{}\"", String::from_utf8(hex_noise(512 * 1024)).unwrap());
    Mock::given(method("GET"))
        .and(path_regex("/doc.*"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(raw, JSON))
        .mount(&server)
        .await;

    let input = batch(vec![
        request("a", &format!("{}/doc?a", server.uri())),
        request("b", &format!("{}/doc?b", server.uri())),
        request("c", &format!("{}/doc?c", server.uri())),
        request("d", &format!("{}/doc?d", server.uri())),
        request("e", &format!("{}/doc?e", server.uri())),
        request("f", &format!("{}/doc?f", server.uri())),
    ]);
    let run = run_fetch(&input, &["--max-total-bytes", "0"]).expect_success();
    for id in ["a", "b", "c", "d", "e", "f"] {
        assert_eq!(run.result(id)["ok"], true, "{}", run.result(id));
    }
}

/// A response that claims gzip but is not a gzip container is a malformed
/// body, not a transport failure and not a body of compressed bytes handed
/// to the caller as though it were the document.
#[tokio::test]
async fn a_corrupt_gzip_container_is_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/broken"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_raw(b"not really gzip", JSON),
        )
        .mount(&server)
        .await;

    let input = batch(vec![request("x", &format!("{}/broken", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["ok"], false);
    assert_eq!(
        run.result("x")["error"].as_str().unwrap(),
        "malformed response body"
    );
}

// ------------------------------------------------------ host-directory safety

/// The lockfile-chosen URL `http://../x` must leave the cache root alone:
/// before host validation, the once-per-process sweep treated the cache
/// root as the host directory for host `..` and deleted expired files
/// there, `--offline` or not.
#[tokio::test]
async fn dot_and_dotdot_hosts_do_not_touch_the_cache_root() {
    let cache = TempDir::new().unwrap();
    let root = cache.path().to_path_buf();
    let fetch_dir = root.join("cdxrs-fetch");
    std::fs::create_dir_all(fetch_dir.join("registry.example")).unwrap();
    // Planted files a sweep of the cache root would delete: an expired json
    // entry and a stale temp file, plus one file no sweep may ever touch.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 60 * 60);
    for (name, contents) in [
        ("other.json", "{}"),
        ("download.tmp.1", "x"),
        ("notes.txt", "keep"),
    ] {
        let p = root.join(name);
        std::fs::write(&p, contents).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
    }
    // And a stale temp directly under cdxrs-fetch, which a `.`-host sweep
    // would have reclaimed.
    let tmp_planted = fetch_dir.join("stale.tmp.999.0");
    std::fs::write(&tmp_planted, "x").unwrap();
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&tmp_planted)
        .unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();

    let input = batch(vec![
        request("dotdot", "http://../x"),
        request("dot", "http://./x"),
        request("encoded", "http://%2e%2e/x"),
    ]);
    let run = run_fetch_cached(&input, &["--offline"], &root);
    assert_eq!(run.status, 0, "stderr={}", run.stderr);
    // Offline + no cacheable host: every request is a recorded miss.
    for id in ["dotdot", "dot", "encoded"] {
        let result = run.result(id);
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"].as_str().unwrap(), "offline-miss");
    }
    // The cache root is exactly as it was.
    for name in ["other.json", "download.tmp.1", "notes.txt"] {
        assert!(
            root.join(name).exists(),
            "{name} was swept from the cache root"
        );
    }
    assert!(tmp_planted.exists(), "a . host swept cdxrs-fetch itself");
    // Nothing new appeared outside cdxrs-fetch either.
    for file in walk(&root) {
        assert!(
            file.starts_with(&fetch_dir)
                || file == root.join("other.json")
                || file == root.join("download.tmp.1")
                || file == root.join("notes.txt"),
            "unexpected file written: {}",
            file.display()
        );
    }
}

/// Bodies are held as their JSON text, never as a parsed tree, so a body the
/// budget admits costs memory equal to its bytes. The body still arrives
/// unchanged, whitespace included, because nothing re-serializes it.
#[tokio::test]
async fn bodies_pass_through_as_the_text_received() {
    let server = MockServer::start().await;
    let raw = "{ \"name\" :  \"left-pad\", \"n\": [0,0,0] }";
    Mock::given(method("GET"))
        .and(path("/raw"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(raw, JSON))
        .mount(&server)
        .await;
    let input = batch(vec![request("x", &format!("{}/raw", server.uri()))]);
    let run = run_fetch(&input, &[]).expect_success();
    assert_eq!(run.result("x")["body"]["name"], "left-pad");
    assert!(
        run.stdout.contains(raw),
        "body was rewritten: {}",
        run.stdout
    );
}

/// Malformed JSON is refused without spending the budget, so it cannot
/// starve the well-formed answers behind it.
#[tokio::test]
async fn a_malformed_body_gives_its_budget_back() {
    let server = MockServer::start().await;
    let bad = format!(
        "[\"{}\"",
        String::from_utf8(hex_noise(1024 * 1024)).unwrap()
    );
    let good = format!("\"{}\"", String::from_utf8(hex_noise(100 * 1024)).unwrap());
    Mock::given(method("GET"))
        .and(path_regex("/bad.*"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(bad, JSON))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/good.*"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(good, JSON))
        .mount(&server)
        .await;
    // One request at a time, in whatever order the tasks get their permits.
    // The sizes make every order pass when refunds work: the good answers
    // (200 KB) plus one malformed MiB fit the 1.6 MB budget, so no request
    // ever finds it spent. Without refunds, three malformed MiB spend it,
    // and a good answer that runs after the second of them fails.
    let input = batch(vec![
        request("bad1", &format!("{}/bad?1", server.uri())),
        request("bad2", &format!("{}/bad?2", server.uri())),
        request("bad3", &format!("{}/bad?3", server.uri())),
        request("good1", &format!("{}/good?1", server.uri())),
        request("good2", &format!("{}/good?2", server.uri())),
    ]);
    let run = run_fetch(
        &input,
        &["--concurrency", "1", "--max-total-bytes", "1600000"],
    )
    .expect_success();
    for id in ["bad1", "bad2", "bad3"] {
        assert_eq!(run.result(id)["ok"], false);
        assert!(
            run.result(id).get("refused").is_none(),
            "malformed is not a size refusal"
        );
    }
    for id in ["good1", "good2"] {
        assert_eq!(run.result(id)["ok"], true, "{}", run.result(id)["error"]);
    }
}

/// A body served from the cache is held and written like a fetched one, so
/// it is charged to the budget too. Otherwise each scan of the same project
/// could add another budget's worth of cached bodies to the next.
#[tokio::test]
async fn cached_bodies_are_charged_to_the_budget() {
    let server = MockServer::start().await;
    let raw = format!("\"{}\"", String::from_utf8(hex_noise(1024 * 1024)).unwrap());
    Mock::given(method("GET"))
        .and(path_regex("/doc.*"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(raw, JSON))
        .mount(&server)
        .await;
    let cache = TempDir::new().unwrap();
    let input = batch(vec![
        request("a", &format!("{}/doc?a", server.uri())),
        request("b", &format!("{}/doc?b", server.uri())),
    ]);
    let first = run_fetch_cached(&input, &[], cache.path()).expect_success();
    assert_eq!(first.stats()["ok"], 2);

    let second =
        run_fetch_cached(&input, &["--max-total-bytes", "1500000"], cache.path()).expect_success();
    assert_eq!(
        second.stats()["cacheHits"],
        1,
        "{}",
        second.json()["results"]
    );
    assert_eq!(second.stats()["budgetExhausted"], 1);
}
