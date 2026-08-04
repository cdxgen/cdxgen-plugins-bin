//! Shared test helpers for integration tests.
//!
//! Environment is passed to the child process rather than set on the test
//! process. `std::env::set_var` is unsound with a threaded test harness, and
//! cargo runs integration tests in parallel — a cache directory set by one test
//! was visible to another, which is exactly the kind of cross-talk that makes a
//! cache test pass for the wrong reason.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct FetchRun {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

impl FetchRun {
    /// Parse stdout as the batch envelope.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not valid JSON ({e}); stdout={:?} stderr={:?}",
                self.stdout, self.stderr
            )
        })
    }

    /// The single result for `id`.
    pub fn result(&self, id: &str) -> serde_json::Value {
        let json = self.json();
        json["results"]
            .as_array()
            .expect("results is not an array")
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no result with id {id} in {json}"))
            .clone()
    }

    pub fn stats(&self) -> serde_json::Value {
        self.json()["stats"].clone()
    }

    pub fn expect_success(self) -> Self {
        assert_eq!(
            self.status, 0,
            "cdxrs fetch exited {}: stderr={}",
            self.status, self.stderr
        );
        self
    }
}

/// A batch request entry.
pub fn request(id: &str, url: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "url": url })
}

pub fn batch(requests: Vec<serde_json::Value>) -> String {
    serde_json::json!({ "requests": requests }).to_string()
}

/// Run `cdxrs fetch` with the given envelope on stdin.
///
/// `env` entries are applied on top of a cleared registry-related environment,
/// so an ambient `GITHUB_TOKEN` or `CDXGEN_CACHE_DIR` on the developer's
/// machine cannot change what a test observes.
pub fn run_fetch_env(input_json: &str, extra_args: &[&str], env: &[(&str, &str)]) -> FetchRun {
    let bin = env!("CARGO_BIN_EXE_cdxrs");
    let mut cmd = Command::new(bin);
    let overrides: HashMap<&str, &str> = env.iter().copied().collect();
    for key in [
        "CDXGEN_CACHE_DIR",
        "CDXGEN_CACHE_LOOPBACK",
        "GITHUB_TOKEN",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        if !overrides.contains_key(key) {
            cmd.env_remove(key);
        }
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.arg("fetch")
        .arg("--input")
        .arg("-")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn cdxrs");
    {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(input_json.as_bytes())
            .expect("failed to write stdin");
    }
    let output = child.wait_with_output().expect("failed to wait");
    FetchRun {
        stdout: String::from_utf8(output.stdout).expect("stdout is not UTF-8"),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status.code().unwrap_or(-1),
    }
}

/// Run with a dedicated, empty cache directory. Sets `CDXGEN_CACHE_LOOPBACK=1`
/// because every cache test uses a wiremock server on `127.0.0.1`.
pub fn run_fetch_cached(
    input_json: &str,
    extra_args: &[&str],
    cache_dir: &std::path::Path,
) -> FetchRun {
    run_fetch_env(
        input_json,
        extra_args,
        &[
            ("CDXGEN_CACHE_DIR", &cache_dir.to_string_lossy()),
            ("CDXGEN_CACHE_LOOPBACK", "1"),
        ],
    )
}

/// Run with the cache switched off.
pub fn run_fetch(input_json: &str, extra_args: &[&str]) -> FetchRun {
    let mut args = vec!["--no-cache"];
    args.extend_from_slice(extra_args);
    run_fetch_env(input_json, &args, &[])
}

/// Recursively list files under a directory.
pub fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
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
