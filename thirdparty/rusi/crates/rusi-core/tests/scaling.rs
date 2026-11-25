//! Scaling assertions over the analysis work counters.
//!
//! The counters `--stats-json` reports are deterministic, so a test can
//! assert how the work grows with input size and never flake on timing: the
//! whole-variable reads scan the environment, and the loop settling clones
//! and joins whole states, so both must stay near linear in the size of a
//! function. The scenarios run one after another in this one test because
//! the counters are process-wide; two parallel tests would read each
//! other's increments.

use std::collections::BTreeMap;
use std::fs;

use rusi_core::stats;
use rusi_core::{AnalysisScope, AnalyzeOptionsInput, analyze};

/// Analyzes `source` as a dependency-free crate and returns the counter
/// deltas the analysis added to the process-wide set.
fn analyze_source(name: &str, source: &str) -> BTreeMap<String, u64> {
    let dir = std::env::temp_dir().join(format!("rusi-scaling-{}-{name}", std::process::id()));
    let src = dir.join("src");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&src).expect("temp src directory is created");
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("Cargo.toml is written");
    fs::write(src.join("lib.rs"), source).expect("lib.rs is written");

    let before = counters();
    let report = analyze(AnalyzeOptionsInput {
        dir: dir.clone(),
        backend: "stable".to_string(),
        analysis_scope: AnalysisScope::Default,
        call_graph_mode: "static".to_string(),
        data_flow_mode: "security".to_string(),
        custom_data_flow_patterns: None,
        include_tests: false,
        debug: false,
        max_call_candidates: 8,
        include_dependencies: false,
    })
    .expect("analysis succeeds");
    let after = counters();
    assert!(
        report.diagnostics.iter().all(|d| d.kind != "parse"),
        "generated source parses: {:?}",
        report
            .diagnostics
            .iter()
            .filter(|d| d.kind == "parse")
            .collect::<Vec<_>>()
    );
    let _ = fs::remove_dir_all(&dir);

    after
        .iter()
        .map(|(key, value)| (key.clone(), value.saturating_sub(before[key])))
        .collect()
}

fn counters() -> BTreeMap<String, u64> {
    let value = stats::snapshot_value();
    let mut out = BTreeMap::new();
    for (key, value) in value["counts"].as_object().expect("counts object") {
        out.insert(key.clone(), value.as_u64().unwrap_or(0));
    }
    out
}

/// A struct with a few fields, instantiated `N` times with field writes and
/// then read whole: `N` plain reads over an environment that holds about
/// `4N` entries.
fn locals_source(n: usize) -> String {
    let mut source = String::from(
        "pub struct Part {\n    f0: String,\n    f1: String,\n    f2: String,\n}\n\npub fn big(seed: String) -> String {\n",
    );
    for index in 0..n {
        source.push_str(&format!(
            "    let mut x{index} = Part {{ f0: seed.clone(), f1: String::new(), f2: String::new() }};\n"
        ));
    }
    for index in 0..n {
        source.push_str(&format!("    x{index}.f0 = seed.clone();\n"));
        source.push_str(&format!("    x{index}.f1 = seed.clone();\n"));
    }
    for index in 0..n {
        source.push_str(&format!("    let r{index} = x{index};\n"));
    }
    source.push_str("    r0.f0\n}\n");
    source
}

/// A loop nest `depth` levels deep whose innermost body reassigns `env_size`
/// locals, so every trip clones and joins a state of that size.
fn loop_nest_source(depth: usize, env_size: usize) -> String {
    let mut source = String::from("pub fn nested(seed: String) -> String {\n");
    for index in 0..env_size {
        source.push_str(&format!("    let mut v{index} = seed.clone();\n"));
    }
    for level in 0..depth {
        source.push_str(&format!("    for _l{level} in 0..2usize {{\n"));
    }
    for index in 0..env_size {
        let next = (index + 1) % env_size;
        source.push_str(&format!("        v{index} = v{next}.clone();\n"));
    }
    for _ in 0..depth {
        source.push_str("    }\n");
    }
    source.push_str("    v0\n}\n");
    source
}

#[test]
fn work_counters_stay_near_linear() {
    // Whole-variable reads: the work at 1000 locals must be at most about
    // 4.5 times the work at 250, which is what a per-variable index costs,
    // where the whole-environment scan costs 16 times.
    let small = analyze_source("locals-250", &locals_source(250));
    let big = analyze_source("locals-1000", &locals_source(1000));
    let small_scans = small["env_scan_entries_summary"];
    let big_scans = big["env_scan_entries_summary"];
    println!(
        "locals: env_scan_entries_summary 250={} 1000={} ratio={:.2}",
        small_scans,
        big_scans,
        big_scans as f64 / small_scans.max(1) as f64
    );
    assert!(
        big_scans <= small_scans * 9 / 2,
        "whole-variable reads scale quadratically: {small_scans} at 250 locals, {big_scans} at 1000"
    );

    // Loop nests: the states the settling clones and the entries the joins
    // visit must grow far slower than the product of the trips, which is
    // what restarting every inner loop on every outer trip would cost.
    let mut clone_costs = Vec::new();
    let mut join_costs = Vec::new();
    for depth in [1, 2, 3, 4] {
        let counts = analyze_source("loop-nest", &loop_nest_source(depth, 40));
        let cloned = counts["state_entries_cloned_summary"];
        let joined = counts["join_entries_visited_summary"];
        println!(
            "loop nest depth={depth}: state_entries_cloned_summary={cloned} join_entries_visited_summary={joined}"
        );
        clone_costs.push(cloned);
        join_costs.push(joined);
    }
    for window in clone_costs.windows(2) {
        assert!(
            window[1] <= window[0] * 6,
            "cloned state entries explode with nesting depth: {clone_costs:?}"
        );
    }
    for window in join_costs.windows(2) {
        assert!(
            window[1] <= window[0] * 6,
            "join visits explode with nesting depth: {join_costs:?}"
        );
    }
}
