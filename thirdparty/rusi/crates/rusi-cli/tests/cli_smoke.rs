use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusi_schema::Report;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is valid")
        .as_nanos();
    std::env::temp_dir().join(format!("rusi-{name}-{timestamp}.{extension}"))
}

#[test]
fn cli_emits_json_report_for_fixture() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("basic-app").to_string_lossy().as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.tool.name, "rusi");
    assert!(report.call_graph.is_some());
    assert!(report.data_flow.is_some());
    Ok(())
}

#[test]
fn cli_emits_expanded_pack_flows() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("expanded-packs-app")
                .to_string_lossy()
                .as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let data_flow = report.data_flow.expect("dataflow present");
    assert!(
        data_flow
            .slices
            .iter()
            .any(|slice| slice.sink_category == "filesystem-write")
    );
    assert!(
        data_flow
            .slices
            .iter()
            .any(|slice| slice.sink_category == "network-connect")
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn cli_supports_compiler_backend_capabilities_and_source_evidence() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("basic-app").to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.options.backend, "compiler");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "backend-capability")
    );
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == "compiler-source-evidence"
            || (diagnostic.kind == "backend"
                && diagnostic
                    .message
                    .contains("embedded rustc support is unavailable"))
    }));
    assert!(report.call_graph.is_some());
    assert!(report.data_flow.is_some());
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_emits_native_model_flow_for_ffi_fixture() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("ffi-app").to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    assert!(data_flow.slices.iter().any(|slice| {
        slice.source_category == "env"
            && slice.sink_category == "native-output"
            && slice
                .properties
                .get("nativeBoundary")
                .is_some_and(|value| value == "true")
            && slice
                .properties
                .get("dataflowModels")
                .is_some_and(|value| value.contains("puts"))
    }));
    assert!(data_flow.nodes.iter().any(|node| {
        node.sink
            && node.category == "native-output"
            && node
                .properties
                .get("modelTags")
                .is_some_and(|value| value.contains("native-boundary"))
    }));
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_expands_trait_and_generic_impl_summaries() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    for fixture in ["dyn-dispatch-app", "generic-specialization-app"] {
        let output = Command::new(&binary)
            .args([
                "analyze",
                "--dir",
                fixture_path(fixture).to_string_lossy().as_ref(),
                "--backend",
                "compiler",
                "--callgraph",
                "static",
                "--dataflow",
                "security",
            ])
            .output()?;

        assert!(
            output.status.success(),
            "{fixture} cli stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Report = serde_json::from_slice(&output.stdout)?;
        let embedded_available = report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
        if !embedded_available {
            continue;
        }
        let data_flow = report.data_flow.expect("compiler dataflow present");
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "env"
                    && slice.sink_category == "filesystem-write"),
            "{fixture} should include env -> filesystem-write through trait/generic dispatch"
        );
        assert!(
            data_flow
                .slices
                .iter()
                .any(|slice| slice.source_category == "env"
                    && slice.sink_category == "network-connect"),
            "{fixture} should include env -> network-connect through trait/generic dispatch"
        );
    }
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_lifts_async_task_closure_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("async-semantic-app")
                .to_string_lossy()
                .as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    assert!(data_flow.slices.iter().any(|slice| {
        slice.source_category == "env"
            && slice.sink_category == "process-exec"
            && slice.source_name.contains("load_secret")
            && slice.sink_name.contains("dispatch")
    }));
    assert!(data_flow.summaries.iter().any(|summary| {
        summary.function == "dispatch"
            && summary
                .param_to_sink
                .get("process-exec")
                .is_some_and(|indexes| indexes.contains(&0))
    }));
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_models_protocol_request_response_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("protocol-flow-app").to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    assert!(
        data_flow.slices.iter().any(|slice| {
            slice.source_category == "network-request"
                && slice.sink_category == "network-response"
                && slice.source_name.contains("read_frame")
                && (slice.sink_name.contains("write_frame")
                    || slice.sink_name.contains("Command::apply"))
        }),
        "expected network-request -> network-response protocol wrapper slice, got {:?}",
        data_flow
            .slices
            .iter()
            .map(|slice| (
                &slice.source_category,
                &slice.sink_category,
                &slice.source_name,
                &slice.sink_name
            ))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_models_rusi_cli_export_path_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("rusi-self-flow-app")
                .to_string_lossy()
                .as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    assert!(
        data_flow.slices.iter().any(|slice| {
            slice.source_category == "cli"
                && slice.sink_category == "filesystem-write"
                && slice.source_name.contains("Parser")
                && slice.source_name.contains("parse")
                && (slice.sink_name.contains("std::fs::write")
                    || slice.sink_name.contains("write_export")
                    || slice.sink_name.contains("export_command"))
        }),
        "expected cli -> filesystem-write flow for Rusi-style export path, got {:?}",
        data_flow
            .slices
            .iter()
            .map(|slice| (
                &slice.source_category,
                &slice.sink_category,
                &slice.source_name,
                &slice.sink_name
            ))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_models_rusi_driver_command_builder_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("rusi-driver-flow-app")
                .to_string_lossy()
                .as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    let fs_slice = data_flow
        .slices
        .iter()
        .find(|slice| slice.source_category == "env" && slice.sink_category == "filesystem-write")
        .expect("expected env -> filesystem-write slice");
    assert!(
        fs_slice.node_ids.len() >= 3,
        "expected multi-node flow path, got {:?}",
        fs_slice.node_ids
    );
    assert!(
        fs_slice.path_length >= 2,
        "expected path_length >= 2, got {}",
        fs_slice.path_length
    );

    let exec_slice = data_flow
        .slices
        .iter()
        .find(|slice| slice.source_category == "env" && slice.sink_category == "process-exec")
        .expect("expected env -> process-exec slice");
    assert!(
        exec_slice.node_ids.len() >= 3,
        "expected multi-node flow path, got {:?}",
        exec_slice.node_ids
    );
    assert!(
        exec_slice.path_length >= 2,
        "expected path_length >= 2, got {}",
        exec_slice.path_length
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_does_not_treat_local_open_as_native_sink() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("native-name-collision-app")
                .to_string_lossy()
                .as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    assert!(
        data_flow
            .slices
            .iter()
            .all(|slice| slice.sink_category != "native-filesystem-open"),
        "local open function should not be classified as native open; got {:?}",
        data_flow
            .slices
            .iter()
            .map(|slice| (
                &slice.source_category,
                &slice.sink_category,
                &slice.source_name,
                &slice.sink_name
            ))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_models_expanded_stdlib_flows() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("stdlib-flow-app").to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let embedded_available = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        return Ok(());
    }

    let data_flow = report.data_flow.expect("compiler dataflow present");
    let categories = data_flow
        .slices
        .iter()
        .map(|slice| (slice.source_category.as_str(), slice.sink_category.as_str()))
        .collect::<Vec<_>>();
    for expected in [
        ("env", "filesystem-read"),
        ("file", "filesystem-write"),
        ("env", "filesystem-write"),
        ("env", "network-connect"),
        ("env", "network-listen"),
        ("env", "process-working-directory"),
        ("env", "output"),
    ] {
        assert!(
            categories.contains(&expected),
            "expected stdlib flow {:?}, got {:?}",
            expected,
            data_flow
                .slices
                .iter()
                .map(|slice| (
                    &slice.source_category,
                    &slice.sink_category,
                    &slice.source_name,
                    &slice.sink_name
                ))
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_dependency_bodies_require_security_deps_mode() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let root = temp_path("external-dependency-mode", "dir");
    let app_dir = root.join("app");
    let dep_dir = root.join("external-dep");
    fs::create_dir_all(app_dir.join("src"))?;
    fs::create_dir_all(dep_dir.join("src"))?;
    fs::write(
        dep_dir.join("Cargo.toml"),
        r#"[package]
name = "external-dep"
version = "0.1.0"
edition = "2021"

[lib]
name = "external_dep"
path = "src/lib.rs"
"#,
    )?;
    fs::write(
        dep_dir.join("src/lib.rs"),
        r#"pub fn dependency_passthrough(value: String) -> String {
    value
}
"#,
    )?;
    fs::write(
        app_dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "dependency-mode-app"
version = "0.1.0"
edition = "2021"

[dependencies]
external-dep = {{ path = "{}" }}
"#,
            dep_dir.display()
        ),
    )?;
    fs::write(
        app_dir.join("src/main.rs"),
        r#"fn main() {
    let value = std::env::var("RUSI_INPUT").unwrap_or_default();
    let _ = external_dep::dependency_passthrough(value);
}
"#,
    )?;

    let default_output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            app_dir.to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
            "--debug",
        ])
        .output()?;
    assert!(
        default_output.status.success(),
        "default dependency-mode stderr: {}",
        String::from_utf8_lossy(&default_output.stderr)
    );
    let default_report: Report = serde_json::from_slice(&default_output.stdout)?;
    let embedded_available = default_report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !embedded_available {
        let _ = fs::remove_dir_all(root);
        return Ok(());
    }
    assert!(
        String::from_utf8_lossy(&default_output.stderr)
            .contains("pass=rustc-wrapper-skip-dependency"),
        "default mode should debug-log skipped dependency crates"
    );
    assert!(
        !default_report
            .declarations
            .iter()
            .any(|decl| decl.package_path == "external_dep"),
        "default security mode should not collect dependency body declarations"
    );

    let deps_output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            app_dir.to_string_lossy().as_ref(),
            "--backend",
            "compiler",
            "--callgraph",
            "static",
            "--dataflow",
            "security-deps",
        ])
        .output()?;
    assert!(
        deps_output.status.success(),
        "security-deps stderr: {}",
        String::from_utf8_lossy(&deps_output.stderr)
    );
    let deps_report: Report = serde_json::from_slice(&deps_output.stdout)?;
    assert!(
        deps_report
            .declarations
            .iter()
            .any(|decl| decl.package_path == "external_dep"),
        "security-deps mode should collect dependency body declarations"
    );

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn cli_emits_vulnerable_web_flows() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("vulnerable-web-app")
                .to_string_lossy()
                .as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let data_flow = report.data_flow.expect("dataflow present");
    assert!(
        data_flow
            .slices
            .iter()
            .any(|slice| slice.source_category == "file" && slice.sink_category == "sql-query")
    );
    assert!(
        data_flow
            .slices
            .iter()
            .any(|slice| slice.source_category == "http-request"
                && slice.sink_category == "network-request")
    );
    assert!(
        data_flow
            .slices
            .iter()
            .any(|slice| slice.source_category == "http-request"
                && slice.sink_category == "html-response")
    );
    Ok(())
}

#[test]
fn cli_exports_callgraph_and_dataflow_formats() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let callgraph_path = temp_path("callgraph", "graphml");
    let dataflow_path = temp_path("dataflow", "gexf");
    let report_path = temp_path("report", "json");
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("basic-app").to_string_lossy().as_ref(),
            "--out",
            report_path.to_string_lossy().as_ref(),
            "--callgraph-out",
            callgraph_path.to_string_lossy().as_ref(),
            "--callgraph-export-format",
            "graphml",
            "--dataflow-out",
            dataflow_path.to_string_lossy().as_ref(),
            "--dataflow-export-format",
            "gexf",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let callgraph_export = std::fs::read_to_string(&callgraph_path)?;
    let dataflow_export = std::fs::read_to_string(&dataflow_path)?;
    assert!(callgraph_export.contains("<graphml"));
    assert!(callgraph_export.contains("sourcePurl"));
    assert!(dataflow_export.contains("<gexf"));
    assert!(dataflow_export.contains("targetPurl"));

    let _ = std::fs::remove_file(callgraph_path);
    let _ = std::fs::remove_file(dataflow_path);
    let _ = std::fs::remove_file(report_path);
    Ok(())
}

#[test]
fn cli_merges_custom_json_patterns() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let patterns_path = temp_path("custom-patterns", "json");
    fs::write(
        &patterns_path,
        r#"{
  "sources": [
    {
      "pattern": "helper::read_secret",
      "category": "custom-source"
    }
  ],
  "sinks": [
    {
      "pattern": "helper::run_command",
      "category": "custom-command",
      "relevant_arguments": [0]
    }
  ]
}"#,
    )?;

    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("basic-app").to_string_lossy().as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
            "--patterns",
            patterns_path.to_string_lossy().as_ref(),
        ])
        .output()?;

    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    let data_flow = report.data_flow.expect("dataflow present");
    assert!(
        data_flow
            .patterns
            .sources
            .iter()
            .any(|pattern| pattern.category == "custom-source")
    );
    assert!(
        data_flow
            .patterns
            .sinks
            .iter()
            .any(|pattern| pattern.category == "custom-command")
    );
    assert!(data_flow.slices.iter().any(|slice| {
        slice.source_category == "custom-source" && slice.sink_category == "custom-command"
    }));

    let _ = fs::remove_file(patterns_path);
    Ok(())
}

#[test]
fn cli_cryptos_command_filters_to_crypto_flows_and_paths() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let full_output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("async-crypto-app").to_string_lossy().as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;
    assert!(
        full_output.status.success(),
        "full analyze stderr: {}",
        String::from_utf8_lossy(&full_output.stderr)
    );
    let full_report: Report = serde_json::from_slice(&full_output.stdout)?;

    let crypto_output = Command::new(binary)
        .args([
            "cryptos",
            "--dir",
            fixture_path("async-crypto-app").to_string_lossy().as_ref(),
            "--callgraph",
            "static",
            "--dataflow",
            "security",
        ])
        .output()?;
    assert!(
        crypto_output.status.success(),
        "cryptos stderr: {}",
        String::from_utf8_lossy(&crypto_output.stderr)
    );
    let crypto_report: Report = serde_json::from_slice(&crypto_output.stdout)?;
    assert_eq!(crypto_report.options.analysis_scope, "cryptos");

    let data_flow = crypto_report.data_flow.expect("crypto dataflow present");
    assert!(
        !data_flow.slices.is_empty(),
        "expected crypto-focused slices"
    );
    assert!(data_flow.slices.iter().all(|slice| {
        slice.sink_category.starts_with("crypto")
            || matches!(slice.sink_category.as_str(), "jwt" | "certificate" | "tls")
    }));
    assert!(data_flow.slices.iter().any(|slice| {
        slice.sink_category == "crypto-key" || slice.sink_category == "crypto-digest"
    }));

    let full_graph = full_report.call_graph.expect("full callgraph present");
    let crypto_graph = crypto_report.call_graph.expect("crypto callgraph present");
    assert!(crypto_graph.stats.edge_count <= full_graph.stats.edge_count);
    assert!(crypto_graph.stats.node_count <= full_graph.stats.node_count);
    assert!(crypto_graph.nodes.iter().any(|node| {
        node.qualified_name.contains("encryptor") || node.qualified_name.contains("main")
    }));
    Ok(())
}

/// Run one fixture through one backend and return its call graph.
fn analyze_with_backend(fixture: &str, backend: &str) -> Result<Report> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let mut args = vec![
        "analyze".to_string(),
        "--dir".to_string(),
        fixture_path(fixture).to_string_lossy().to_string(),
        "--backend".to_string(),
        backend.to_string(),
        "--callgraph".to_string(),
        "static".to_string(),
        "--dataflow".to_string(),
        "none".to_string(),
    ];
    // `--toolchain auto` prefers a nightly, and a nightly outside the narrow
    // `rustc_private` window cannot build the embedded wrapper, so on such a
    // machine every compiler-backend assertion below skips itself. Setting
    // `RUSI_TEST_TOOLCHAIN=stable` (with the `rustc-dev` and `rust-src`
    // components installed, as `rust-toolchain.toml` specifies) pins the
    // toolchain so the assertions actually run. Without this there is no way
    // to make them execute on a machine whose nightly has drifted, and a
    // suite that cannot be made to run is a suite nobody trusts.
    if let Ok(toolchain) = std::env::var("RUSI_TEST_TOOLCHAIN") {
        args.push("--toolchain".to_string());
        args.push(toolchain);
    }
    let output = Command::new(&binary).args(&args).output()?;
    assert!(
        output.status.success(),
        "{fixture}/{backend} cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// True when the embedded rustc collector actually ran.
///
/// The `rustc_private` API window is narrow, so on a machine whose resolved
/// toolchain is outside it the driver reports `backend-error` and falls back to
/// stable evidence. A compiler-backend assertion made against that fallback
/// would be testing the stable backend under another name, so callers skip.
/// The skip is announced rather than silent: a test that quietly asserts
/// nothing is worse than one that fails.
fn embedded_compiler_ran(report: &Report, context: &str) -> bool {
    let ran = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "compiler-source-evidence");
    if !ran {
        eprintln!(
            "SKIP {context}: embedded rustc collector unavailable, \
             compiler-backend assertions not exercised"
        );
    }
    ran
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn both_backends_name_the_same_dispatching_trait() -> Result<()> {
    // A trait object carries one vtable, so both backends should name the same
    // trait for the same dispatched call. They reach it by different routes:
    // the stable backend reduces the written receiver type, the compiler
    // backend takes the trait owning the called method from `TyCtxt`. If they
    // disagree, `dispatch_trait` cannot be joined across backends and is not
    // worth publishing.
    //
    // `dyn-bounds-app` is the fixture for the compiler half. It is the one
    // whose receiver is a bare `&(dyn Store + Send + Sync)`, which is what
    // `resolve_method_call` recognises as `ty::Dynamic`. See the two tests
    // below for why the other dyn fixtures cannot serve here.
    //
    // The trait name is asserted literally. "Some trait is named" passes
    // against the wrong trait, which is the failure this test exists to catch.
    let stable = analyze_with_backend("dyn-bounds-app", "stable")?;
    let stable_traits: Vec<&str> = stable
        .call_graph
        .as_ref()
        .expect("stable call graph")
        .edges
        .iter()
        .filter(|edge| edge.method.as_deref() == Some("persist"))
        .filter_map(|edge| edge.dispatch_trait.as_deref())
        .collect();
    assert!(
        !stable_traits.is_empty(),
        "stable backend must dispatch `persist` through a trait"
    );
    for named in &stable_traits {
        assert_eq!(*named, "Store", "stable backend named the wrong trait");
    }

    let compiler = analyze_with_backend("dyn-bounds-app", "compiler")?;
    if !embedded_compiler_ran(&compiler, "both_backends_name_the_same_dispatching_trait") {
        return Ok(());
    }
    let compiler_graph = compiler.call_graph.as_ref().expect("compiler call graph");
    let dyn_edges: Vec<_> = compiler_graph
        .edges
        .iter()
        .filter(|edge| edge.call_type.starts_with("dyn-dispatch"))
        .collect();
    assert!(
        !dyn_edges.is_empty(),
        "compiler backend must see `&(dyn Store + Send + Sync)` as vtable dispatch"
    );
    for edge in dyn_edges {
        assert_eq!(
            edge.dispatch_trait.as_deref(),
            Some("Store"),
            "backends disagree on the trait dispatching `persist`; \
             compiler-side receiver text was {:?}",
            edge.receiver
        );
    }
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_names_no_trait_outside_vtable_dispatch() -> Result<()> {
    // The negative half. `dispatch_trait` means "the receiver is a trait
    // object and the target resolved through that trait's impls". A change
    // that sets it on every call reaching a trait method, or on every call at
    // all, passes the agreement test above and fails here.
    let report = analyze_with_backend("dyn-bounds-app", "compiler")?;
    if !embedded_compiler_ran(
        &report,
        "compiler_backend_names_no_trait_outside_vtable_dispatch",
    ) {
        return Ok(());
    }
    let graph = report.call_graph.as_ref().expect("compiler call graph");
    for edge in &graph.edges {
        if edge.call_type.starts_with("dyn-dispatch") {
            continue;
        }
        assert_eq!(
            edge.dispatch_trait, None,
            "`{}` is not vtable dispatch, so it must name no trait",
            edge.call_type
        );
    }
    // `trait-static` edges are the ones that make this assertion mean
    // something: they reach a trait's method without a vtable.
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.call_type.starts_with("trait-static")),
        "fixture must contain static trait calls for this test to bite"
    );
    Ok(())
}
