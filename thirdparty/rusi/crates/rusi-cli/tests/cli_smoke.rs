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
            .map(|slice| (&slice.source_category, &slice.sink_category, &slice.source_name, &slice.sink_name))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn compiler_backend_models_rusi_cli_export_path_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("rusi-self-flow-app").to_string_lossy().as_ref(),
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
            .map(|slice| (&slice.source_category, &slice.sink_category, &slice.source_name, &slice.sink_name))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn compiler_backend_models_rusi_driver_command_builder_flow() -> Result<()> {
    let binary = std::env::var("CARGO_BIN_EXE_rusi")?;
    let output = Command::new(binary)
        .args([
            "analyze",
            "--dir",
            fixture_path("rusi-driver-flow-app").to_string_lossy().as_ref(),
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
            .map(|slice| (&slice.source_category, &slice.sink_category, &slice.source_name, &slice.sink_name))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
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
                .map(|slice| (&slice.source_category, &slice.sink_category, &slice.source_name, &slice.sink_name))
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
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
    assert!(!data_flow.slices.is_empty(), "expected crypto-focused slices");
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
