use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusi_schema::Report;
use clap::{Args, Parser, Subcommand};
use rusi_core::{
    AnalysisScope, AnalyzeOptionsInput, BACKEND_COMPILER, BACKEND_STABLE, analyze,
    analyze_with_optional_compiler,
};
use rusi_driver::{DriverOptions, run_driver};

mod export;
mod modeling;

use export::{EXPORT_FORMATS, write_call_graph_export, write_data_flow_export};
use modeling::{ModelingArgs, apply_modeling};

#[derive(Debug, Parser)]
#[command(name = "rusi", version, about = "Rust source analysis inspector")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Analyze(AnalysisArgs),
    Cryptos(AnalysisArgs),
}

#[derive(Debug, Clone, Args)]
struct AnalysisArgs {
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[arg(long, default_value = BACKEND_STABLE, value_parser = [BACKEND_STABLE, BACKEND_COMPILER])]
    backend: String,
    #[arg(long, default_value = "auto")]
    toolchain: String,
    #[arg(long, default_value = "json")]
    format: String,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    callgraph_out: Option<PathBuf>,
    #[arg(long, default_value = "json", requires = "callgraph_out", value_parser = EXPORT_FORMATS)]
    callgraph_export_format: String,
    #[arg(long)]
    dataflow_out: Option<PathBuf>,
    #[arg(long, default_value = "json", requires = "dataflow_out", value_parser = EXPORT_FORMATS)]
    dataflow_export_format: String,
    #[arg(long, default_value = "static")]
    callgraph: String,
    #[arg(
        long,
        default_value = "security",
        help = "Data-flow mode: security, security-deps, or none. security-deps opts compiler mode into full dependency/external crate body analysis"
    )]
    dataflow: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Include test sources/targets. In compiler mode this runs cargo check --all-targets; by default test targets are skipped"
    )]
    tests: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Print analysis progress to stderr"
    )]
    debug: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Pretty-print JSON output (report and exports). Off by default: output is minified to reduce file size"
    )]
    pretty: bool,
    #[command(flatten)]
    modeling: ModelingArgs,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze(args) => run_analysis_command(args, AnalysisScope::Default),
        Command::Cryptos(args) => run_analysis_command(args, AnalysisScope::Cryptos),
    }
}

fn run_analysis_command(args: AnalysisArgs, scope: AnalysisScope) -> Result<()> {
    if args.format != "json" {
        anyhow::bail!(
            "unsupported report format {}; only json is currently implemented for the full report (use --callgraph-out/--dataflow-out for graph exports)",
            args.format
        );
    }

    let mut options = AnalyzeOptionsInput {
        dir: args.dir,
        backend: args.backend.clone(),
        analysis_scope: AnalysisScope::Default,
        call_graph_mode: args.callgraph,
        data_flow_mode: args.dataflow,
        custom_data_flow_patterns: None,
        include_tests: args.tests,
        debug: args.debug,
    };
    apply_modeling(&mut options, scope, &args.modeling)?;
    let report = if options.backend == BACKEND_COMPILER {
        let mut driver_options = DriverOptions::from_analyze_options(&options);
        driver_options.rustc_toolchain = args.toolchain;
        let envelope = run_driver(&driver_options)?;
        analyze_with_optional_compiler(options, Some(envelope.into_compiler_payload()))?
    } else {
        analyze(options)?
    };

    if let Some(path) = args.callgraph_out.as_ref() {
        let call_graph = report
            .call_graph
            .as_ref()
            .context("callgraph export requested but no call graph was produced")?;
        write_call_graph_export(call_graph, &args.callgraph_export_format, path, args.pretty)?;
    }
    if let Some(path) = args.dataflow_out.as_ref() {
        let data_flow = report
            .data_flow
            .as_ref()
            .context("dataflow export requested but no data flow was produced")?;
        write_data_flow_export(data_flow, &args.dataflow_export_format, path, args.pretty)?;
    }

    write_report_json(&report, args.out.as_deref(), args.pretty)
}

/// Serialize the report straight into the destination writer instead of
/// building the entire JSON document as an in-memory `String` first. For large
/// targets (whole-program graphs with millions of nodes) the intermediate
/// `String` was a full second copy of the output and a major contributor to
/// peak memory; streaming through a `BufWriter` removes it.
///
/// Output is minified by default; `pretty` selects indented output.
fn write_report_json(report: &Report, out: Option<&Path>, pretty: bool) -> Result<()> {
    match out {
        Some(path) => {
            let file = fs::File::create(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            let mut writer = BufWriter::new(file);
            write_json(&mut writer, report, pretty)
                .with_context(|| format!("failed to write report to {}", path.display()))?;
            writer
                .flush()
                .with_context(|| format!("failed to flush report to {}", path.display()))?;
        }
        None => {
            let stdout = std::io::stdout();
            let mut writer = BufWriter::new(stdout.lock());
            write_json(&mut writer, report, pretty)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

fn write_json<W: Write, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
    pretty: bool,
) -> serde_json::Result<()> {
    if pretty {
        serde_json::to_writer_pretty(writer, value)
    } else {
        serde_json::to_writer(writer, value)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusi_schema::Report;

    use super::{
        AnalysisArgs, AnalysisScope, ModelingArgs, run_analysis_command, write_report_json,
    };

    #[test]
    fn write_report_json_defaults_to_minified_and_round_trips() {
        let mut report = Report::default();
        report.schema_version = "rusi.report/test".to_string();
        report.options.backend = "stable".to_string();

        let path = temp_report_path("stream-writer");
        write_report_json(&report, Some(path.as_path()), false).expect("streamed write succeeds");

        let written = std::fs::read_to_string(&path).expect("read streamed report");
        let _ = std::fs::remove_file(&path);

        // Default output is minified (compact), byte-identical to `to_string`.
        let expected = serde_json::to_string(&report).expect("reference serialization");
        assert_eq!(written, expected);
        // Minified output has no pretty-print indentation.
        assert!(!written.contains("\n  "));

        let parsed: Report = serde_json::from_str(&written).expect("round-trips back to Report");
        assert_eq!(parsed, report);
    }

    #[test]
    fn write_report_json_pretty_flag_indents() {
        let mut report = Report::default();
        report.schema_version = "rusi.report/test".to_string();

        let path = temp_report_path("stream-writer-pretty");
        write_report_json(&report, Some(path.as_path()), true).expect("streamed write succeeds");

        let written = std::fs::read_to_string(&path).expect("read streamed report");
        let _ = std::fs::remove_file(&path);

        let expected = serde_json::to_string_pretty(&report).expect("reference serialization");
        assert_eq!(written, expected);
        assert!(written.contains("\n  "));
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    fn temp_report_path(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is valid")
            .as_nanos();
        std::env::temp_dir().join(format!("rusi-{name}-{timestamp}.json"))
    }

    #[test]
    fn compiler_backend_cli_smoke_emits_backend_diagnostics() {
        let output_path = temp_report_path("compiler-backend-smoke");
        run_analysis_command(AnalysisArgs {
            dir: fixture_path("basic-app"),
            backend: "compiler".to_string(),
            toolchain: "auto".to_string(),
            format: "json".to_string(),
            out: Some(output_path.clone()),
            callgraph_out: None,
            callgraph_export_format: "json".to_string(),
            dataflow_out: None,
            dataflow_export_format: "json".to_string(),
            callgraph: "static".to_string(),
            dataflow: "security".to_string(),
            tests: false,
            debug: false,
            pretty: false,
            modeling: ModelingArgs::default(),
        }, AnalysisScope::Default)
        .expect("compiler backend analyze succeeds");

        let report: Report = serde_json::from_str(
            &std::fs::read_to_string(&output_path).expect("read report output"),
        )
        .expect("parse report output");
        let _ = std::fs::remove_file(&output_path);

        assert_eq!(report.options.backend, "compiler");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "backend-capability")
        );
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == "compiler-source-evidence" || diagnostic.kind == "backend"
        }));
        assert!(report.call_graph.is_some());
        assert!(report.data_flow.is_some());
    }

    #[test]
    fn analyze_command_writes_callgraph_and_dataflow_exports() {
        let report_path = temp_report_path("export-report");
        let callgraph_path = temp_report_path("callgraph-export").with_extension("graphml");
        let dataflow_path = temp_report_path("dataflow-export").with_extension("gexf");

        run_analysis_command(AnalysisArgs {
            dir: fixture_path("basic-app"),
            backend: "stable".to_string(),
            toolchain: "auto".to_string(),
            format: "json".to_string(),
            out: Some(report_path.clone()),
            callgraph_out: Some(callgraph_path.clone()),
            callgraph_export_format: "graphml".to_string(),
            dataflow_out: Some(dataflow_path.clone()),
            dataflow_export_format: "gexf".to_string(),
            callgraph: "static".to_string(),
            dataflow: "security".to_string(),
            tests: false,
            debug: false,
            pretty: false,
            modeling: ModelingArgs::default(),
        }, AnalysisScope::Default)
        .expect("analysis with exports succeeds");

        let callgraph_export =
            std::fs::read_to_string(&callgraph_path).expect("read callgraph export");
        let dataflow_export =
            std::fs::read_to_string(&dataflow_path).expect("read dataflow export");

        assert!(callgraph_export.contains("<graphml"));
        assert!(callgraph_export.contains("sourcePurl"));
        assert!(dataflow_export.contains("<gexf"));
        assert!(dataflow_export.contains("targetPurl"));

        let _ = std::fs::remove_file(report_path);
        let _ = std::fs::remove_file(callgraph_path);
        let _ = std::fs::remove_file(dataflow_path);
    }
}
