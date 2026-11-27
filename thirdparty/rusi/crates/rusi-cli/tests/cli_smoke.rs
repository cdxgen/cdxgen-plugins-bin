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
        summary.function == "async_semantic_app::dispatch"
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
            // TOML basic strings treat `\U` as a unicode escape, and a
            // Windows temp path is full of them; forward slashes are valid
            // path separators for cargo on every host.
            dep_dir.display().to_string().replace('\\', "/")
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
    analyze_with_backend_at(&fixture_path(fixture), backend)
}

fn analyze_with_backend_at(dir: &std::path::Path, backend: &str) -> Result<Report> {
    let output = run_analyze_at(dir, backend)?;
    assert!(
        output.status.success(),
        "{}/{backend} cli stderr: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Runs `rusi analyze` on `dir` with the toolchain the test environment pins,
/// returning the process output whether or not the run succeeded.
fn run_analyze_at(dir: &std::path::Path, backend: &str) -> Result<std::process::Output> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let mut args = vec![
        "analyze".to_string(),
        "--dir".to_string(),
        dir.to_string_lossy().to_string(),
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
    if let Some(toolchain) = std::env::var("RUSI_TEST_TOOLCHAIN")
        .ok()
        .filter(|toolchain| !toolchain.is_empty())
    {
        args.push("--toolchain".to_string());
        args.push(toolchain);
    }
    Ok(Command::new(&binary).args(&args).output()?)
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

/// Like [`analyze_with_backend`], but with data flow enabled, for assertions
/// on data-flow nodes.
fn analyze_with_backend_and_dataflow(fixture: &str, backend: &str) -> Result<Report> {
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
        "security".to_string(),
    ];
    if let Some(toolchain) = std::env::var("RUSI_TEST_TOOLCHAIN")
        .ok()
        .filter(|toolchain| !toolchain.is_empty())
    {
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

/// The macro invocation sites one report records: the macro's path with its
/// trailing `!`, and the line it was invoked on.
fn macro_call_sites(report: &Report) -> Vec<(String, usize)> {
    let mut sites: Vec<(String, usize)> = report
        .usages
        .iter()
        .filter(|usage| usage.kind == "macro-call")
        .map(|usage| (usage.name.clone(), usage.position.line))
        .collect();
    sites.sort();
    sites
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_reports_no_signal_from_dependency_expansions() -> Result<()> {
    // Every compiler-generated unsafe block in this fixture comes out of a
    // dependency macro (`format!`, `println!`, `dbg!`), so none of them may
    // be reported against the user's lines. The `unsafe` block the
    // workspace's own `checked_slot!` transcriber writes is kept and names
    // the macro, and the block written by hand beside an `info!` call is
    // kept with no macro origin at all.
    let report = analyze_with_backend("macro-zoo-app", "compiler")?;
    if !embedded_compiler_ran(
        &report,
        "compiler_mode_reports_no_signal_from_dependency_expansions",
    ) {
        return Ok(());
    }
    assert!(
        !report
            .security_signals
            .iter()
            .any(|signal| signal.description.contains("compiler-generated")),
        "signals raised inside dependency expansions must not be reported"
    );
    let hand_written = report
        .security_signals
        .iter()
        .filter(|signal| {
            signal.category == "unsafe-code"
                && signal.description == "unsafe block detected"
                && signal.expanded_from.is_none()
        })
        .count();
    assert_eq!(
        hand_written, 1,
        "the hand-written unsafe block beside the macro call is the one signal with no origin"
    );
    assert!(
        report.security_signals.iter().any(|signal| {
            signal.category == "unsafe-code"
                && signal
                    .expanded_from
                    .as_ref()
                    .is_some_and(|origin| origin.macro_path == "macro_zoo_app::checked_slot")
        }),
        "the unsafe block written in checked_slot!'s transcriber is reported and names the macro"
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_fills_expanded_from_for_workspace_generated_code() -> Result<()> {
    // `Seconds::danger` is a method the `make_units!` macro generated: its
    // declaration and the data-flow nodes of its slice name the macro, while
    // the position stays at the invocation site. A hand-written function has
    // no origin, and neither does code a dependency macro produced.
    let report = analyze_with_backend_and_dataflow("macro-zoo-app", "compiler")?;
    if !embedded_compiler_ran(
        &report,
        "compiler_mode_fills_expanded_from_for_workspace_generated_code",
    ) {
        return Ok(());
    }
    let danger = report
        .declarations
        .iter()
        .find(|declaration| declaration.qualified_name == "macro_zoo_app::Seconds::danger")
        .expect("generated method declared");
    let origin = danger
        .expanded_from
        .as_ref()
        .expect("generated method carries its macro origin");
    assert_eq!(
        origin.macro_path,
        "macro_zoo_app::macros::make_units::make_units"
    );
    assert_eq!(origin.file_path, "src/macros/make_units.rs");
    assert_eq!(danger.file_path, "src/lib.rs");

    let data_flow = report.data_flow.expect("dataflow present");
    let danger_nodes = data_flow
        .nodes
        .iter()
        .filter(|node| node.function == "macro_zoo_app::Seconds::danger")
        .collect::<Vec<_>>();
    assert!(
        !danger_nodes.is_empty(),
        "the generated method contributes data-flow nodes"
    );
    for node in danger_nodes {
        assert_eq!(
            node.expanded_from
                .as_ref()
                .map(|origin| origin.macro_path.as_str()),
            Some("macro_zoo_app::macros::make_units::make_units"),
            "every node of the slice inside the generated method names the macro"
        );
    }

    let run = report
        .declarations
        .iter()
        .find(|declaration| declaration.qualified_name == "macro_zoo_app::run")
        .expect("hand-written function declared");
    assert!(
        run.expanded_from.is_none(),
        "a hand-written function carries no macro origin"
    );
    // A dependency macro's helper is not workspace code either: it names no
    // workspace macro as its origin.
    assert!(
        report
            .usages
            .iter()
            .filter(|usage| usage.name.ends_with("log::__private_api::log"))
            .all(|usage| usage.expanded_from.is_none()),
        "calls made by a dependency macro's expansion carry no workspace origin"
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_names_dependency_macro_helpers_and_matches_stable_macro_calls() -> Result<()> {
    // The helper call a dependency macro's expansion makes carries the macro
    // the user invoked, so `log::__private_api::log` reads as `log::info!`.
    // The macro-level calls the two backends report must agree: the same
    // `macro-call` usages and the same `macro` edges, or one backend is
    // hiding or inventing invocations.
    let compiler = analyze_with_backend("macro-zoo-app", "compiler")?;
    if !embedded_compiler_ran(&compiler, "compiler_mode_names_dependency_macro_helpers") {
        return Ok(());
    }
    let stable = analyze_with_backend("macro-zoo-app", "stable")?;

    for (helper, macro_name) in [
        ("log::__private_api::log", "log::info!"),
        ("anyhow::__private::format_err", "anyhow::bail!"),
    ] {
        // One helper serves several macros (`trace!`, `info!` and `warn!` all
        // call `log::__private_api::log`), and report order is not part of
        // the contract, so every helper call must name some macro and one of
        // them must name this one.
        let named: Vec<Option<&str>> = compiler
            .usages
            .iter()
            .filter(|usage| usage.name.ends_with(helper))
            .map(|usage| usage.properties.get("viaMacro").map(String::as_str))
            .collect();
        assert!(
            !named.is_empty(),
            "compiler report names the {helper} helper"
        );
        assert!(
            named.iter().all(Option::is_some),
            "every {helper} call names the macro that made it: {named:?}"
        );
        assert!(
            named.contains(&Some(macro_name)),
            "a {helper} call names {macro_name}: {named:?}"
        );
    }
    // The negative case: a call written by hand, or one a workspace macro
    // wrote, names no dependency macro.
    let command_calls = compiler
        .usages
        .iter()
        .filter(|usage| usage.name.starts_with("std::process::Command::new"))
        .count();
    assert!(
        command_calls > 0,
        "fixture has hand-written and macro-written Command::new calls"
    );
    assert!(
        compiler
            .usages
            .iter()
            .filter(|usage| usage.name.starts_with("std::process::Command::new"))
            .all(|usage| !usage.properties.contains_key("viaMacro")),
        "calls not made through a dependency macro carry no viaMacro"
    );

    let compiler_sites = macro_call_sites(&compiler);
    assert!(
        compiler_sites.iter().any(|(name, _)| name == "log::info!"),
        "compiler records the info! call"
    );
    assert_eq!(
        compiler_sites,
        macro_call_sites(&stable),
        "both backends record the same macro-call sites (name and line) on macro-zoo-app; \
         a difference must be explained in the docs"
    );

    let macro_edges = |report: &Report| -> Vec<(String, usize)> {
        let mut edges: Vec<(String, usize)> = report
            .call_graph
            .as_ref()
            .expect("call graph")
            .edges
            .iter()
            .filter(|edge| edge.call_type == "macro")
            .map(|edge| (edge.callee_text.clone().unwrap_or_default(), edge.line))
            .collect();
        edges.sort();
        edges
    };
    assert_eq!(
        macro_edges(&compiler),
        macro_edges(&stable),
        "both backends record the same macro edges"
    );
    let edge_purls: Vec<&str> = compiler
        .call_graph
        .as_ref()
        .expect("call graph")
        .edges
        .iter()
        .filter(|edge| {
            edge.call_type == "macro" && edge.callee_text.as_deref() == Some("log::info")
        })
        .map(|edge| edge.target_purl.as_str())
        .collect();
    assert!(
        edge_purls
            .iter()
            .all(|purl| purl.starts_with("pkg:cargo/log")),
        "the macro edge names the dependency's purl: {edge_purls:?}"
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_drops_stale_macro_note_for_analysed_files() -> Result<()> {
    // The stable backend cannot recover `maplit::hashmap!`'s body and says
    // so. The compiler backend expands it, so in compiler mode the report
    // holds the calls of that body and the stable note would deny exactly
    // what the report shows.
    let compiler = analyze_with_backend("macro-zoo-app", "compiler")?;
    if !embedded_compiler_ran(&compiler, "compiler_mode_drops_stale_macro_note") {
        return Ok(());
    }
    assert!(
        !compiler
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("bodies were not analyzed")),
        "compiler mode reports no stable note about bodies it analysed"
    );

    let stable = analyze_with_backend("macro-zoo-app", "stable")?;
    assert!(
        stable.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("maplit::hashmap! bodies were not analyzed")),
        "stable mode still reports the body it could not recover"
    );
    Ok(())
}

/// A copy of `macro-zoo-app` in a temporary directory, with `extra` appended
/// to `src/lib.rs`, for tests that need the fixture plus one more function.
fn copy_macro_zoo(label: &str, extra: &str) -> Result<PathBuf> {
    let fixture = fixture_path("macro-zoo-app");
    let copy = std::env::temp_dir().join(format!(
        "rusi-macro-zoo-{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is valid")
            .as_nanos()
    ));
    fs::create_dir_all(copy.join("src"))?;
    for file in ["Cargo.toml", "Cargo.lock"] {
        fs::copy(fixture.join(file), copy.join(file))?;
    }
    for entry in fs::read_dir(fixture.join("src"))? {
        let entry = entry?;
        let target = copy.join("src").join(entry.file_name());
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&target)?;
            for nested in fs::read_dir(entry.path())? {
                let nested = nested?;
                fs::copy(nested.path(), target.join(nested.file_name()))?;
            }
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    let mut lib = fs::read_to_string(fixture.join("src/lib.rs"))?;
    lib.push_str(extra);
    fs::write(copy.join("src/lib.rs"), lib)?;
    Ok(copy)
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_keeps_unsafe_blocks_written_as_dependency_macro_arguments() -> Result<()> {
    // Tokens passed to a dependency macro keep the invoking file's spans, so
    // an `unsafe` block the user writes as an argument is the user's code
    // even though the macro's expansion holds it, and its signal stays.
    let copy = copy_macro_zoo(
        "arguments",
        "\npub fn unsafe_in_macro_arguments(p: *const u32) -> Vec<u32> {\n    info!(\"value {}\", unsafe { *p });\n    vec![unsafe { *p }]\n}\n",
    )?;
    let lib_lines = fs::read_to_string(copy.join("src/lib.rs"))?.lines().count();
    let report = analyze_with_backend_at(&copy, "compiler");
    let _ = fs::remove_dir_all(&copy);
    let report = report?;
    if !embedded_compiler_ran(
        &report,
        "compiler_mode_keeps_unsafe_blocks_written_as_dependency_macro_arguments",
    ) {
        return Ok(());
    }
    // The appended function ends the file: `}` is its last line, and the
    // `info!` and `vec!` lines are the two before the closing tail.
    let argument_lines = [lib_lines - 2, lib_lines - 1];
    for line in argument_lines {
        assert!(
            report.security_signals.iter().any(|signal| {
                signal.description == "unsafe block detected"
                    && signal.file_path == "src/lib.rs"
                    && signal.position.line == line
                    && signal.expanded_from.is_none()
            }),
            "the unsafe block written as a macro argument on line {line} is reported"
        );
    }
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_mode_keeps_macro_note_when_the_compiler_run_fails() -> Result<()> {
    // A crate the compiler run fails on contributes no compiler evidence, so
    // the stable note about its macro bodies stays: the report's macro-level
    // blind spot is real there.
    let broken = copy_macro_zoo(
        "broken",
        "\nfn broken() {\n    let x: u32 = \"not a number\";\n}\n",
    )?;

    // The pinned toolchain matters here as everywhere: without it `auto`
    // picks a toolchain the CI leg did not install, and the run fails for that
    // reason instead of the type error.
    let output = run_analyze_at(&broken, "compiler");
    let _ = fs::remove_dir_all(&broken);
    let output = output?;
    assert!(
        output.status.success(),
        "a failed compiler run is reported, not fatal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "backend-error"),
        "the failed compiler run is reported as a backend error"
    );
    assert!(
        report.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("maplit::hashmap! bodies were not analyzed")),
        "the note about bodies the report does not hold is kept"
    );
    Ok(())
}

fn run_report(args: &[&str]) -> Result<serde_json::Value> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary).arg("analyze").args(args).output()?;
    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Every `id` of one list, collected from `value[section]`.
fn ids_of(list: &serde_json::Value) -> Vec<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .map(|item| item["id"].as_str().expect("item has an id").to_string())
        .collect()
}

fn assert_unique(label: &str, ids: &[String]) {
    let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len(), "duplicate ids in {label}");
}

/// Every string under a `file_path` or `filename` key, anywhere in the report.
fn collect_file_strings(value: &serde_json::Value, into: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if (key == "file_path" || key == "filename")
                    && let Some(text) = child.as_str()
                {
                    into.push(text.to_string());
                }
                collect_file_strings(child, into);
            }
        }
        serde_json::Value::Array(items) => {
            items
                .iter()
                .for_each(|item| collect_file_strings(item, into));
        }
        _ => {}
    }
}

#[test]
fn discover_merges_sibling_crates_into_one_root_relative_report() -> Result<()> {
    let root = fixture_path("multi-crate-root");
    let root_text = root.to_string_lossy().into_owned();
    let report = run_report(&[
        "--dir",
        &root_text,
        "--discover",
        "--exclude",
        "skipped/**",
        "--dataflow",
        "security",
    ])?;

    let canonical_root = fs::canonicalize(&root)?;
    assert_eq!(
        report["options"]["directory"].as_str(),
        Some(canonical_root.display().to_string().as_str())
    );
    assert_eq!(
        report["runtime"]["working_directory"].as_str(),
        Some(canonical_root.display().to_string().as_str())
    );

    // Files: both crates, each under its own directory; the excluded one is out.
    let files: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["alpha/src/main.rs", "beta/src/main.rs"]);
    assert_eq!(report["packages"].as_array().unwrap().len(), 2);

    // Every file reference in every section is the root-relative path of a file
    // that exists, or is empty (an external call-graph node has no file).
    let mut strings = Vec::new();
    collect_file_strings(&report, &mut strings);
    assert!(strings.iter().any(|path| path == "alpha/src/main.rs"));
    assert!(strings.iter().any(|path| path == "beta/src/main.rs"));
    for path in strings.iter().filter(|path| !path.is_empty()) {
        assert!(
            canonical_root.join(path).is_file(),
            "{path} is not a file relative to the root"
        );
    }
    // No crate-relative path was left behind in any string of the report.
    assert!(!report.to_string().contains("\"src/main.rs\""));

    // Package manifests keep their absolute paths and exist.
    for package in report["packages"].as_array().unwrap() {
        let manifest = PathBuf::from(package["manifest_path"].as_str().unwrap());
        assert!(manifest.is_absolute() && manifest.is_file());
        for file in package["files"].as_array().unwrap() {
            assert!(canonical_root.join(file.as_str().unwrap()).is_file());
        }
    }

    // Both crates share a package name, a file name and a function name, so
    // their ids collide until the merge tells them apart.
    for section in ["packages", "declarations", "usages", "security_signals"] {
        assert_unique(section, &ids_of(&report[section]));
    }
    let call_graph = &report["call_graph"];
    let node_ids = ids_of(&call_graph["nodes"]);
    assert_unique("call graph nodes", &node_ids);
    assert_unique("call graph edges", &ids_of(&call_graph["edges"]));
    for edge in call_graph["edges"].as_array().unwrap() {
        for end in ["source_id", "target_id"] {
            let id = edge[end].as_str().unwrap();
            assert!(
                node_ids.iter().any(|node| node == id),
                "dangling {end} {id}"
            );
        }
    }
    assert_eq!(
        call_graph["stats"]["node_count"].as_u64().unwrap() as usize,
        node_ids.len()
    );
    assert_eq!(
        report["stats"]["call_graph_node_count"].as_u64().unwrap() as usize,
        node_ids.len()
    );

    let data_flow = &report["data_flow"];
    let flow_nodes = ids_of(&data_flow["nodes"]);
    let flow_edges = ids_of(&data_flow["edges"]);
    assert_unique("data-flow nodes", &flow_nodes);
    assert_unique("data-flow edges", &flow_edges);
    let slices = ids_of(&data_flow["slices"]);
    assert_unique("data-flow slices", &slices);
    assert!(
        !slices.is_empty(),
        "the fixture must produce data-flow slices"
    );
    for slice in data_flow["slices"].as_array().unwrap() {
        for end in ["source_id", "sink_id"] {
            assert!(flow_nodes.iter().any(|n| n == slice[end].as_str().unwrap()));
        }
        for id in slice["node_ids"].as_array().unwrap() {
            assert!(flow_nodes.iter().any(|n| n == id.as_str().unwrap()));
        }
        for id in slice["edge_ids"].as_array().unwrap() {
            assert!(flow_edges.iter().any(|n| n == id.as_str().unwrap()));
        }
    }
    for summary in data_flow["summaries"].as_array().unwrap() {
        let function_id = summary["function_id"].as_str().unwrap();
        assert!(
            report["declarations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|declaration| declaration["id"] == function_id),
            "summary names {function_id}, which no declaration carries"
        );
    }
    Ok(())
}

#[test]
fn discover_without_exclude_takes_every_crate_and_skips_target() -> Result<()> {
    let scratch = temp_path("multi-copy", "d");
    let source = fixture_path("multi-crate-root");
    for crate_dir in ["alpha", "beta", "skipped"] {
        fs::create_dir_all(scratch.join(crate_dir).join("src"))?;
        for file in ["Cargo.toml", "src/main.rs"] {
            fs::copy(
                source.join(crate_dir).join(file),
                scratch.join(crate_dir).join(file),
            )?;
        }
    }
    fs::create_dir_all(scratch.join("target/stray/src"))?;
    fs::copy(
        source.join("alpha/Cargo.toml"),
        scratch.join("target/stray/Cargo.toml"),
    )?;
    fs::copy(
        source.join("alpha/src/main.rs"),
        scratch.join("target/stray/src/main.rs"),
    )?;

    let report = run_report(&["--dir", scratch.to_str().unwrap(), "--discover"])?;
    let _ = fs::remove_dir_all(&scratch);
    let files: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        files,
        [
            "alpha/src/main.rs",
            "beta/src/main.rs",
            "skipped/src/main.rs"
        ]
    );
    Ok(())
}

#[test]
fn repeated_dir_uses_the_common_parent_as_root_unless_told_otherwise() -> Result<()> {
    let root = fixture_path("multi-crate-root");
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    let report = run_report(&[
        "--dir",
        alpha.to_str().unwrap(),
        "--dir",
        beta.to_str().unwrap(),
    ])?;
    let files: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["alpha/src/main.rs", "beta/src/main.rs"]);

    let fixtures = fixture_path("");
    let report = run_report(&[
        "--dir",
        alpha.to_str().unwrap(),
        "--dir",
        beta.to_str().unwrap(),
        "--root",
        fixtures.to_str().unwrap(),
    ])?;
    let files: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        files,
        [
            "multi-crate-root/alpha/src/main.rs",
            "multi-crate-root/beta/src/main.rs"
        ]
    );
    Ok(())
}

#[test]
fn single_directory_report_is_the_same_with_and_without_discovery() -> Result<()> {
    let dir = fixture_path("basic-app");
    let plain = run_report(&["--dir", dir.to_str().unwrap()])?;
    let discovered = run_report(&["--dir", dir.to_str().unwrap(), "--discover"])?;
    assert_eq!(plain, discovered);
    assert!(
        plain["files"][0]["path"]
            .as_str()
            .is_some_and(|path| path.starts_with("src/"))
    );
    Ok(())
}

// The context-impl-app fixture: a trait with a defaulted context parameter,
// implemented for a foreign type under local marker types. The qualified
// names below follow rustc's impl spelling (`crate::<impl Trait<Args> for
// Type>::method`), which both backends name impl methods with, so the two
// backends join on their canonical names.

const API_CTX_IMPL_TO_JSON: &str = "::<impl ToJson<ApiCtx> for fakeuuid::Uuid>::to_json";
const RPC_CTX_IMPL_TO_JSON: &str = "::<impl ToJson<RpcCtx> for fakeuuid::Uuid>::to_json";
const PRODUCT_IMPL_TO_JSON: &str = "::<impl ToJson<Ctx> for context_impl_app::Product>::to_json";
const MYUUID_IMPL_TO_JSON: &str = "::<impl ToJson for context_impl_app::MyUuid>::to_json";
const PAIR_IMPL_FOR_UUID: &str = "::<impl Pair<ApiCtx,T> for fakeuuid::Uuid>::pair";

// The compiler backend spells the same impls the way rustc prints them: a
// foreign self type in the `<impl Trait for Type>` form with the trait's
// crate path, a local one as `<Type as Trait<Args>>`.
const COMPILER_API_CTX_IMPL_TO_JSON: &str =
    "::<impl context_impl_tojson::ToJson<context_impl_app::ApiCtx> for fakeuuid::Uuid>::to_json";
const COMPILER_RPC_CTX_IMPL_TO_JSON: &str =
    "::<impl context_impl_tojson::ToJson<context_impl_app::RpcCtx> for fakeuuid::Uuid>::to_json";
const COMPILER_PRODUCT_IMPL_TO_JSON: &str =
    "<context_impl_app::Product as context_impl_tojson::ToJson<Ctx>>::to_json";
const COMPILER_MYUUID_IMPL_TO_JSON: &str =
    "<context_impl_app::MyUuid as context_impl_tojson::ToJson>::to_json";
const COMPILER_PAIR_IMPL_FOR_UUID: &str =
    "::<impl context_impl_tojson::Pair<context_impl_app::ApiCtx, T> for fakeuuid::Uuid>::pair";

/// Qualified names of every edge target out of `source_suffix`, filtered to
/// targets containing `target_part` (empty means all targets).
fn context_impl_edge_targets(
    report: &serde_json::Value,
    source_suffix: &str,
    target_part: &str,
) -> Vec<String> {
    let call_graph = &report["call_graph"];
    let names: std::collections::HashMap<&str, &str> = call_graph["nodes"]
        .as_array()
        .expect("call graph nodes")
        .iter()
        .map(|node| {
            (
                node["id"].as_str().expect("node id"),
                node["qualified_name"].as_str().expect("qualified name"),
            )
        })
        .collect();
    call_graph["edges"]
        .as_array()
        .expect("call graph edges")
        .iter()
        .filter_map(|edge| {
            let source = names.get(edge["source_id"].as_str()?)?;
            let target = names.get(edge["target_id"].as_str()?)?;
            if !source.ends_with(source_suffix) {
                return None;
            }
            if !target_part.is_empty() && !target.contains(target_part) {
                return None;
            }
            Some(target.to_string())
        })
        .collect()
}

/// A call from `source_suffix` reaches a target ending with `target_suffix`.
fn assert_context_impl_edge(report: &serde_json::Value, source: &str, target: &str) {
    let targets = context_impl_edge_targets(report, source, "");
    assert!(
        targets.iter().any(|name| name.ends_with(target)),
        "{source} should reach {target}, got {targets:?}"
    );
}

/// Every call from `source_suffix` whose target shares `target_suffix`'s
/// method name ends at `target_suffix`: the dispatch reaches the one impl and
/// nothing else of that method.
fn assert_context_impl_dispatch(report: &serde_json::Value, source: &str, target: &str) {
    let method = format!("::{}", target.rsplit("::").next().unwrap_or(target));
    let targets = context_impl_edge_targets(report, source, "");
    let dispatches: Vec<&String> = targets
        .iter()
        .filter(|name| name.ends_with(method.as_str()))
        .collect();
    assert!(
        !dispatches.is_empty(),
        "{source} should dispatch to {target}, got {targets:?}"
    );
    assert!(
        dispatches.iter().all(|name| name.ends_with(target)),
        "{source} should dispatch only to {target}, got {dispatches:?}"
    );
}

fn context_impl_slice_from(report: &serde_json::Value, function_suffix: &str) {
    let slices = report["data_flow"]["slices"]
        .as_array()
        .expect("data flow slices");
    assert!(
        slices.iter().any(|slice| {
            slice["source_category"] == "env"
                && slice["sink_category"] == "process-exec"
                && slice["source_function"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(function_suffix))
        }),
        "no environment -> process-exec slice from {function_suffix}: {}",
        serde_json::to_string(slices).unwrap_or_default()
    );
}

#[test]
fn stable_backend_resolves_context_impl_dispatch() -> Result<()> {
    let report = run_report(&[
        "--dir",
        fixture_path("context-impl-app").to_str().unwrap(),
        "--callgraph",
        "static",
        "--dataflow",
        "security",
    ])?;

    // Expectation 1: handler -> api -> Product's generic impl -> the ApiCtx
    // impl on the foreign Uuid type.
    assert_context_impl_edge(&report, "::handler", "::api");
    assert_context_impl_dispatch(&report, "::api", PRODUCT_IMPL_TO_JSON);
    let product_targets = context_impl_edge_targets(&report, PRODUCT_IMPL_TO_JSON, "to_json");
    assert!(
        product_targets
            .iter()
            .any(|name| name.ends_with(API_CTX_IMPL_TO_JSON)),
        "Product's impl should reach the ApiCtx impl on Uuid, got {product_targets:?}"
    );

    // The two context impls on Uuid are distinct declarations.
    let uuid_impls: Vec<&str> = report["declarations"]
        .as_array()
        .expect("declarations")
        .iter()
        .filter_map(|declaration| {
            let name = declaration["qualified_name"].as_str()?;
            (name.ends_with(API_CTX_IMPL_TO_JSON) || name.ends_with(RPC_CTX_IMPL_TO_JSON))
                .then_some(declaration["id"].as_str()?)
        })
        .collect();
    assert_eq!(uuid_impls.len(), 2, "both Uuid impl methods are declared");
    assert_ne!(
        uuid_impls[0], uuid_impls[1],
        "the ApiCtx and RpcCtx impls of Uuid must not share a declaration id"
    );

    // Expectations 3 and 4: each `dyn ToJson<Ctx>` receiver dispatches only to
    // the impl of that context.
    assert_context_impl_dispatch(&report, "::method_api", API_CTX_IMPL_TO_JSON);
    assert_context_impl_dispatch(&report, "::plain_method", RPC_CTX_IMPL_TO_JSON);

    // Expectation 5: the fully qualified `ToJson::<RpcCtx>::to_json` call
    // reaches the RpcCtx impl, not the trait's crate.
    assert_context_impl_dispatch(&report, "::rpc", RPC_CTX_IMPL_TO_JSON);
    assert!(
        context_impl_edge_targets(&report, "::rpc", "context_impl_tojson::ToJson::to_json")
            .is_empty(),
        "rpc's call must not end at the abstract trait item"
    );

    // The newtype receiver is the tuple-struct constructor of a local type, so
    // only MyUuid's impl is a candidate.
    assert_context_impl_dispatch(&report, "::newtype", MYUUID_IMPL_TO_JSON);
    assert_context_impl_dispatch(&report, "::pair", PAIR_IMPL_FOR_UUID);

    // The `Client` chain's calls carry the codec crate's name and purl.
    let enc_nodes: Vec<&serde_json::Value> = report["call_graph"]["nodes"]
        .as_array()
        .expect("call graph nodes")
        .iter()
        .filter(|node| node["qualified_name"] == "context_impl_tojson::Client::enc")
        .collect();
    assert_eq!(enc_nodes.len(), 1, "Client::enc is named by its crate");
    assert_eq!(
        enc_nodes[0]["purl"], "pkg:cargo/context-impl-tojson",
        "Client::enc carries the codec crate's purl"
    );
    let codec_nodes: Vec<&serde_json::Value> = report["call_graph"]["nodes"]
        .as_array()
        .expect("call graph nodes")
        .iter()
        .filter(|node| node["qualified_name"] == "context_impl_tojson::Client::codec")
        .collect();
    assert_eq!(codec_nodes.len(), 1, "Client::codec is named by its crate");
    Ok(())
}

#[test]
fn stable_backend_context_impl_flows_through_the_dependency() -> Result<()> {
    let report = run_report(&[
        "--dir",
        fixture_path("context-impl-app").to_str().unwrap(),
        "--deps",
        "--callgraph",
        "static",
        "--dataflow",
        "security-deps",
    ])?;

    // With the dependency bodies in, both handlers carry the environment
    // source to the process-exec sink inside the ApiCtx impl.
    context_impl_slice_from(&report, "::handler");
    context_impl_slice_from(&report, "::handler2");

    // The dependency's generic `enc` over-approximates its `to_json` call to
    // the local impls, including the ApiCtx one the user code dispatches to.
    let enc_targets = context_impl_edge_targets(&report, "Client<X>::enc", "to_json");
    assert!(
        enc_targets
            .iter()
            .any(|name| name.ends_with(API_CTX_IMPL_TO_JSON)),
        "enc's bound callback should reach the ApiCtx impl, got {enc_targets:?}"
    );
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_resolves_context_impl_dispatch() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("context-impl-app").to_str().unwrap(),
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if !report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|diagnostic| diagnostic["kind"] == "compiler-source-evidence")
    {
        return Ok(());
    }

    // Expectation 1: handler -> api -> Product's generic impl -> the ApiCtx
    // impl on the foreign Uuid type -> the process sink.
    assert_context_impl_edge(&report, "::handler", "::api");
    assert_context_impl_dispatch(&report, "::api", COMPILER_PRODUCT_IMPL_TO_JSON);
    let product_targets =
        context_impl_edge_targets(&report, COMPILER_PRODUCT_IMPL_TO_JSON, "to_json");
    assert!(
        product_targets
            .iter()
            .any(|name| name.ends_with(COMPILER_API_CTX_IMPL_TO_JSON)),
        "Product's impl should reach the ApiCtx impl on Uuid, got {product_targets:?}"
    );
    let sink_targets =
        context_impl_edge_targets(&report, COMPILER_API_CTX_IMPL_TO_JSON, "Command::arg");
    assert!(
        !sink_targets.is_empty(),
        "the ApiCtx impl should call Command::arg"
    );

    // Expectations 3 and 4: the dyn receivers dispatch only to the impl of
    // their context argument, in the `<impl Trait<Args> for Type>` spelling
    // rustc prints for a foreign self type. The generic Product impl stays
    // in the bounded set: a `dyn ToJson<ApiCtx>` may hold a `Product`.
    assert_context_impl_reaches(&report, "::method_api", COMPILER_API_CTX_IMPL_TO_JSON);
    assert_context_impl_reaches(&report, "::plain_method", COMPILER_RPC_CTX_IMPL_TO_JSON);
    assert!(
        context_impl_edge_targets(&report, "::method_api", COMPILER_RPC_CTX_IMPL_TO_JSON)
            .is_empty(),
        "method_api must not dispatch to the RpcCtx impl"
    );
    assert!(
        context_impl_edge_targets(&report, "::plain_method", COMPILER_API_CTX_IMPL_TO_JSON)
            .is_empty(),
        "plain_method must not dispatch to the ApiCtx impl"
    );
    assert!(
        context_impl_edge_targets(&report, "::method_api", COMPILER_MYUUID_IMPL_TO_JSON).is_empty(),
        "method_api must not dispatch to the ToJson<()> impl"
    );

    // Expectation 5: fully qualified calls reach the impl of the written
    // context, and the abstract trait item edge is superseded.
    assert_context_impl_dispatch(&report, "::rpc", COMPILER_RPC_CTX_IMPL_TO_JSON);
    assert!(
        context_impl_edge_targets(&report, "::rpc", "context_impl_tojson::ToJson::to_json")
            .is_empty(),
        "rpc's abstract trait item edge should be superseded by the impl edge"
    );
    assert_context_impl_dispatch(&report, "::newtype", COMPILER_MYUUID_IMPL_TO_JSON);
    assert_context_impl_dispatch(&report, "::pair", COMPILER_PAIR_IMPL_FOR_UUID);

    // The dependency's generic `enc` is called with its generic arguments
    // known at the call site, so the bound's method reaches the ApiCtx impl
    // alone, marked as a trait callback.
    assert_context_impl_edge(&report, "::handler2", "::via_client");
    let client_targets = context_impl_edge_targets(&report, "::via_client", "Client::<X>::enc");
    assert!(
        !client_targets.is_empty(),
        "via_client should call the dependency's Client::enc"
    );
    let callback_targets =
        context_impl_edge_targets(&report, "::via_client", COMPILER_API_CTX_IMPL_TO_JSON);
    assert!(
        !callback_targets.is_empty(),
        "via_client's trait bound should call back into the ApiCtx impl"
    );
    assert!(
        context_impl_edge_targets(&report, "::via_client", COMPILER_RPC_CTX_IMPL_TO_JSON)
            .is_empty(),
        "the ApiCtx callback must not reach the RpcCtx impl"
    );
    Ok(())
}

/// A call from `source_suffix` reaches a target ending with `target_suffix`
/// among the targets that share its method name (other calls of the same
/// function, to other methods, are not part of the dispatch).
fn assert_context_impl_reaches(report: &serde_json::Value, source: &str, target: &str) {
    let method = format!("::{}", target.rsplit("::").next().unwrap_or(target));
    let targets = context_impl_edge_targets(report, source, "");
    let dispatches: Vec<&String> = targets
        .iter()
        .filter(|name| name.ends_with(method.as_str()))
        .collect();
    assert!(
        dispatches.iter().any(|name| name.ends_with(target)),
        "{source} should reach {target}, got {targets:?}"
    );
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_context_impl_flows_through_the_dependency() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("context-impl-app").to_str().unwrap(),
            "--backend",
            "compiler",
            "--deps",
            "--callgraph",
            "static",
            "--dataflow",
            "security-deps",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "cli stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if !report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|diagnostic| diagnostic["kind"] == "compiler-source-evidence")
    {
        return Ok(());
    }
    context_impl_slice_from(&report, "::handler");
    context_impl_slice_from(&report, "::handler2");
    Ok(())
}

/// Declarations whose qualified name ends with `suffix`, as (id, canonical
/// name) pairs.
fn context_impl_declarations(report: &serde_json::Value, suffix: &str) -> Vec<(String, String)> {
    report["declarations"]
        .as_array()
        .expect("declarations")
        .iter()
        .filter(|declaration| {
            declaration["qualified_name"]
                .as_str()
                .is_some_and(|name| name.ends_with(suffix))
        })
        .map(|declaration| {
            (
                declaration["id"].as_str().unwrap_or_default().to_string(),
                declaration["canonical_name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

/// Slices from `function_suffix` carrying the environment source to `sink`.
fn context_impl_has_slice(report: &serde_json::Value, function_suffix: &str, sink: &str) -> bool {
    context_impl_has_slice_from(report, function_suffix, Some("env"), sink)
}

/// Slices from `function_suffix` to `sink`, from `source` or from any source
/// (parameters included) when `source` is `None`.
fn context_impl_has_slice_from(
    report: &serde_json::Value,
    function_suffix: &str,
    source: Option<&str>,
    sink: &str,
) -> bool {
    report["data_flow"]["slices"]
        .as_array()
        .expect("data flow slices")
        .iter()
        .any(|slice| {
            source.is_none_or(|source| slice["source_category"] == source)
                && slice["sink_category"] == sink
                && slice["source_function"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(function_suffix))
        })
}

#[test]
fn stable_backend_keeps_context_impl_probes_apart() -> Result<()> {
    let report = run_report(&[
        "--dir",
        fixture_path("context-impl-app").to_str().unwrap(),
        "--callgraph",
        "static",
        "--dataflow",
        "security",
    ])?;

    // Same-named types in two modules: the impl methods carry the module
    // path, get distinct ids, and reduce to the canonical name rustc's
    // spelling reduces to.
    let a_fmt = context_impl_declarations(
        &report,
        "::probes::a::<impl core::fmt::Display for context_impl_app::probes::a::Err>::fmt",
    );
    let b_fmt = context_impl_declarations(
        &report,
        "::probes::b::<impl core::fmt::Display for context_impl_app::probes::b::Err>::fmt",
    );
    assert_eq!(a_fmt.len(), 1, "a::Err's Display impl is declared once");
    assert_eq!(b_fmt.len(), 1, "b::Err's Display impl is declared once");
    assert_ne!(a_fmt[0].0, b_fmt[0].0, "the two impls must not share an id");
    assert_eq!(a_fmt[0].1, "context_impl_app::probes::a::Err::fmt");
    assert_eq!(b_fmt[0].1, "context_impl_app::probes::b::Err::fmt");

    // An impl that relies on the trait's default argument stays a candidate
    // for a call that writes the argument out; the impls of other contexts
    // do not.
    let plain = "::<impl ToJson for context_impl_app::probes::Plain>::to_json";
    assert_context_impl_reaches(&report, "::default_dyn", plain);
    assert_context_impl_reaches(&report, "::default_dyn", MYUUID_IMPL_TO_JSON);
    assert!(
        context_impl_edge_targets(&report, "::default_dyn", API_CTX_IMPL_TO_JSON).is_empty(),
        "default_dyn must not dispatch to the ApiCtx impl"
    );
    assert_context_impl_dispatch(&report, "::default_qualified", plain);

    // A method's own generic parameter on a trait object leaves every impl
    // of the trait possible.
    assert_context_impl_reaches(&report, "::method_generic", API_CTX_IMPL_TO_JSON);
    assert_context_impl_reaches(&report, "::method_generic", RPC_CTX_IMPL_TO_JSON);

    // A trait written with a path, and arguments spelled differently on the
    // impl and the call, still resolve.
    assert_context_impl_dispatch(
        &report,
        "::pathed",
        "::<impl tj::Pair<crate::ApiCtx,u8> for context_impl_app::probes::Pathed>::pair",
    );
    // A lifetime argument never rules an impl out.
    assert_context_impl_reaches(
        &report,
        "::named_dyn",
        "::<impl tj::Pair<&'a str,u8> for context_impl_app::probes::Named>::pair",
    );

    // `unwrap` on a dependency constructor's result is the standard
    // library's method, not the dependency type's.
    assert!(
        !report["call_graph"]["nodes"]
            .as_array()
            .expect("call graph nodes")
            .iter()
            .any(|node| node["qualified_name"] == "fakeuuid::Uuid::unwrap"),
        "Result::unwrap must not be attributed to fakeuuid::Uuid"
    );
    Ok(())
}

#[test]
fn stable_backend_keeps_context_impl_flows_apart() -> Result<()> {
    let report = run_report(&[
        "--dir",
        fixture_path("context-impl-app").to_str().unwrap(),
        "--deps",
        "--callgraph",
        "static",
        "--dataflow",
        "security-deps",
    ])?;
    // Two qualified calls with the same text shape but different context
    // arguments reach only their own impl's sink.
    assert!(context_impl_has_slice(
        &report,
        "::api_direct",
        "process-exec"
    ));
    assert!(
        !context_impl_has_slice(&report, "::api_direct", "filesystem-write"),
        "the ApiCtx call must not reach the RpcCtx impl's sink"
    );
    assert!(context_impl_has_slice(
        &report,
        "::rpc_direct",
        "filesystem-write"
    ));
    assert!(
        !context_impl_has_slice(&report, "::rpc_direct", "process-exec"),
        "the RpcCtx call must not reach the ApiCtx impl's sink"
    );
    // The trait-object receivers reach only the sink of their context's
    // impl, and a call that resolves to an impl without a sink has none.
    assert!(context_impl_has_slice_from(
        &report,
        "::method_api",
        None,
        "process-exec"
    ));
    assert!(
        !context_impl_has_slice_from(&report, "::method_api", None, "filesystem-write"),
        "method_api must not reach the RpcCtx impl's sink"
    );
    assert!(context_impl_has_slice_from(
        &report,
        "::plain_method",
        None,
        "filesystem-write"
    ));
    assert!(
        !context_impl_has_slice_from(&report, "::plain_method", None, "process-exec"),
        "plain_method must not reach the ApiCtx impl's sink"
    );
    for sink in ["process-exec", "filesystem-write"] {
        assert!(
            !context_impl_has_slice_from(&report, "::default_qualified", None, sink),
            "default_qualified reaches only Plain's impl, which has no {sink} sink"
        );
    }
    Ok(())
}

#[test]
#[ignore = "compiler backend: needs the rustc-dev and rust-src components and runs nested cargo. Run: RUSTC_BOOTSTRAP=1 cargo test -- --ignored --test-threads=1"]
fn compiler_backend_keeps_context_impl_probes_apart() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(&binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("context-impl-app").to_str().unwrap(),
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if !report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|diagnostic| diagnostic["kind"] == "compiler-source-evidence")
    {
        return Ok(());
    }
    // The stable and compiler declarations of the two Display impls join on
    // one canonical name each.
    let canonical: std::collections::BTreeSet<String> = report["declarations"]
        .as_array()
        .expect("declarations")
        .iter()
        .filter_map(|declaration| declaration["canonical_name"].as_str())
        .filter(|name| name.ends_with("::Err::fmt"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        canonical.into_iter().collect::<Vec<_>>(),
        vec![
            "context_impl_app::probes::a::Err::fmt".to_string(),
            "context_impl_app::probes::b::Err::fmt".to_string(),
        ]
    );
    // A lifetime argument never rules an impl out of a dyn dispatch.
    assert_context_impl_reaches(&report, "::named_dyn", "Named");
    // A method's own generic parameter leaves every impl possible.
    assert_context_impl_reaches(&report, "::method_generic", COMPILER_API_CTX_IMPL_TO_JSON);
    assert_context_impl_reaches(&report, "::method_generic", COMPILER_RPC_CTX_IMPL_TO_JSON);
    // The bound callback finds an impl whose self type is generic.
    let wrapped = context_impl_edge_targets(&report, "::via_client_wrapped", "Wrapper");
    assert!(
        !wrapped.is_empty(),
        "via_client_wrapped's bound should call back into Wrapper's impl"
    );
    Ok(())
}
