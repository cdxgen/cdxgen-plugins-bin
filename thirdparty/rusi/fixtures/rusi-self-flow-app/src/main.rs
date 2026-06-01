use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Export(ExportArgs),
}

#[derive(Debug, Parser)]
struct ExportArgs {
    #[arg(long)]
    out: PathBuf,
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Export(args) => export_command(args),
    }
}

fn export_command(args: ExportArgs) -> std::io::Result<()> {
    let report = render_report();
    write_export(&args.out, &report)
}

fn render_report() -> String {
    "report".to_string()
}

fn write_export(path: &Path, content: &str) -> std::io::Result<()> {
    fs::write(path, content)
}
