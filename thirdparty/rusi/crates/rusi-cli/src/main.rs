use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
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
        write_call_graph_export(call_graph, &args.callgraph_export_format, path)?;
    }
    if let Some(path) = args.dataflow_out.as_ref() {
        let data_flow = report
            .data_flow
            .as_ref()
            .context("dataflow export requested but no data flow was produced")?;
        write_data_flow_export(data_flow, &args.dataflow_export_format, path)?;
    }

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = args.out {
        fs::write(path, json)?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusi_schema::Report;

    use super::{AnalysisArgs, AnalysisScope, ModelingArgs, run_analysis_command};

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
