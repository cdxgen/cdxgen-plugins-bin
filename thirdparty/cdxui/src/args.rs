use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cdxui", version, about = "Interactive terminal UI for CycloneDX BOM exploration")]
pub struct Args {
    #[arg(help = "Path to a CycloneDX BOM file (.json) or directory.")]
    pub path: Option<PathBuf>,

    #[arg(
        long,
        default_value = "false",
        help = "Generate BOM by spawning cdxgen. All args after -- are passed to cdxgen."
    )]
    pub generate: bool,

    #[arg(
        long,
        default_value = "false",
        help = "Skip alternate screen (useful for debugging)"
    )]
    pub no_alternate_screen: bool,

    #[arg(
        long = "theme",
        default_value = "dark",
        help = "Color theme: dark, light"
    )]
    pub theme: String,

    #[arg(
        long = "output",
        default_value = "/tmp/bom.json",
        help = "Output BOM file path (for --generate mode)"
    )]
    pub output: PathBuf,
}

pub fn parse_cdxgen_args() -> Vec<String> {
    let cdgenv = std::env::var("CDXGEN_ARGS").unwrap_or_default();
    if !cdgenv.is_empty() {
        return cdgenv.split_whitespace().map(|s| s.to_string()).collect();
    }
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--") {
        args[pos + 1..].to_vec()
    } else {
        Vec::new()
    }
}

