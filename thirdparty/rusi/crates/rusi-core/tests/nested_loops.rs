//! Taint written inside a nested loop must survive both loop heads.
//!
//! The loop settling folds a trip's body into the loop head through the keys
//! the trip changed. A variable declared before two nested loops and written
//! only inside the inner one changes the outer trip's existing entry through
//! the inner loop's join, not through a write of the outer trip itself, so it
//! is the case that shows whether the outer join still sees every change.

use std::fs;

use rusi_core::{AnalysisScope, AnalyzeOptionsInput, analyze};

const SOURCE: &str = r#"use std::process::Command;

pub fn pass_through(input: String) -> String {
    let mut out = String::new();
    for _ in 0..2 {
        for _ in 0..2 {
            out = input.clone();
        }
    }
    out
}

fn main() {
    let mut cmd = String::new();
    for _ in 0..2 {
        for _ in 0..2 {
            cmd = std::env::var("CMD").unwrap();
        }
    }
    Command::new(cmd).spawn().unwrap();
}
"#;

#[test]
fn a_write_in_an_inner_loop_reaches_the_code_after_the_outer_loop() {
    let dir = std::env::temp_dir().join(format!("rusi-nested-loops-{}", std::process::id()));
    let src = dir.join("src");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&src).expect("temp src directory is created");
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"nested_loops\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("Cargo.toml is written");
    fs::write(src.join("main.rs"), SOURCE).expect("main.rs is written");

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
    let _ = fs::remove_dir_all(&dir);

    let data_flow = report.data_flow.expect("data flow is collected");
    let pass_through = data_flow
        .summaries
        .iter()
        .find(|summary| summary.function.ends_with("::pass_through"))
        .expect("pass_through is summarized");
    assert_eq!(
        pass_through.param_to_return,
        vec![0],
        "the parameter reaches the return through both loops"
    );
    assert!(
        data_flow.slices.iter().any(|slice| {
            slice.source_name == "std::env::var" && slice.sink_name == "std::process::Command::new"
        }),
        "the environment value assigned in the inner loop reaches the command"
    );
}
